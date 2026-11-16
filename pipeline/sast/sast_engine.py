import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union


class SASTEngine:
    """UML Phase 1 (Steps 1, 2, 3, and 5): Hybrid Static Application Security Testing Engine.

    Provides both the standardized AVR UML schema (for AST Context Pruner & Qwen Patch Synthesizer)
    and full backward compatibility with the team pipeline interface (target_path & scan_with_bandit).
    Combines Bandit (AST-based static analyzer) and Semgrep (semantic rule & pattern engine).
    """

    # Map Semgrep severity levels to standard HIGH/MEDIUM/LOW schema
    SEMGREP_SEVERITY_MAP: Dict[str, str] = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW",
    }

    # Bandit rules that only flag top-level import statements (B401-B415) or assert statements (B101).
    # Filtering these prevents AST Context Pruner from failing on top-level non-function lines.
    NOISY_BANDIT_RULES: Set[str] = {
        "B101",  # assert_used
        "B401",  # import_telnetlib
        "B402",  # import_ftplib
        "B403",  # import_pickle
        "B404",  # import_subprocess
        "B405",  # import_xml_etree
        "B406",  # import_xml_sax
        "B407",  # import_xml_expat
        "B408",  # import_xml_minidom
        "B409",  # import_xml_pulldom
        "B410",  # import_lxml
        "B411",  # import_xmlrpclib
        "B412",  # import_httpoxy
        "B413",  # import_pycrypto
        "B414",  # import_cryptography_deprecated
        "B415",  # import_pyghmi
    }

    def __init__(
        self,
        target_path: Optional[Union[str, Path]] = None,
        timeout: int = 45,
        ignore_noisy_rules: bool = True,
        rules_file: Optional[Union[str, Path]] = None,
    ) -> None:
        self.target_path = Path(target_path) if target_path else None
        self.timeout = timeout
        self.ignore_noisy_rules = ignore_noisy_rules
        default_rules = Path(__file__).parent / "rules.yaml"
        self.rules_file = Path(rules_file) if rules_file else (default_rules if default_rules.exists() else None)

    def _normalize_cwe(self, raw_cwe: Any) -> str:
        """Extracts a clean 'CWE-XXX' identifier from varied tool metadata formats."""
        if isinstance(raw_cwe, list) and raw_cwe:
            raw_cwe = raw_cwe[0]
        if isinstance(raw_cwe, dict):
            cwe_id = raw_cwe.get("id")
            return f"CWE-{cwe_id}" if cwe_id else "CWE-Unknown"
        if isinstance(raw_cwe, str):
            match = re.search(r"CWE-\d+", raw_cwe, re.IGNORECASE)
            if match:
                return match.group(0).upper()
        return "CWE-Unknown"

    def _extract_code_snippet(
        self, file_path: str, start_line: int, end_line: int
    ) -> str:
        """Reads exact source code lines directly from the file as a fallback for Semgrep."""
        try:
            lines = Path(file_path).read_text(encoding="utf-8").splitlines()
            start_idx = max(0, start_line - 1)
            end_idx = min(len(lines), end_line)
            snippet_lines = [
                f"{idx + 1} {lines[idx]}" for idx in range(start_idx, end_idx)
            ]
            return "\n".join(snippet_lines).strip()
        except Exception:
            return ""

    def _build_finding_record(
        self,
        tool: str,
        rule_id: str,
        cwe_id: str,
        file_path: str,
        line_number: int,
        end_line_number: int,
        severity: str,
        confidence: str,
        code_snippet: str,
        message: str,
    ) -> Dict[str, Any]:
        """Creates a unified finding dictionary supporting both UML schema keys and team pipeline keys."""
        return {
            # Standard UML Phase 1 schema keys (for AST Context Pruner & Qwen Patch Synthesizer)
            "tool": tool,
            "rule_id": rule_id,
            "cwe_id": cwe_id,
            "file_path": file_path,
            "line_number": line_number,
            "end_line_number": end_line_number,
            "severity": severity,
            "confidence": confidence,
            "code_snippet": code_snippet,
            "message": message,
            # Backward-compatible alias keys for team pipeline
            "engine": tool.capitalize(),
            "filename": file_path,
            "test_id": rule_id,
            "cwe": cwe_id,
            "issue_text": message,
            "code": code_snippet,
        }

    def run_bandit(
        self, target_path: Optional[str] = None, display_path: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """UML Step 2: Runs Bandit static analyzer on a file or directory and normalizes findings."""
        resolved_target = str(target_path if target_path else self.target_path)
        bandit_bin = shutil.which("bandit")
        cmd = [bandit_bin] if bandit_bin else [sys.executable, "-m", "bandit"]

        if Path(resolved_target).is_dir():
            cmd.append("-r")

        cmd.extend(["-f", "json", "-q", resolved_target])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=self.timeout,
                check=False,
            )

            if not result.stdout.strip():
                return []

            data = json.loads(result.stdout)
            findings: List[Dict[str, Any]] = []

            for item in data.get("results", []):
                rule_id = item.get("test_id", "UNKNOWN_RULE")

                if self.ignore_noisy_rules and rule_id in self.NOISY_BANDIT_RULES:
                    continue

                cwe_str = self._normalize_cwe(item.get("issue_cwe", {}))
                line_num = int(item.get("line_number", 1))
                line_range = item.get("line_range", [])
                end_line_num = int(line_range[-1]) if line_range else line_num
                reported_file = (
                    str(display_path)
                    if display_path
                    else str(item.get("filename", resolved_target))
                )

                findings.append(
                    self._build_finding_record(
                        tool="bandit",
                        rule_id=rule_id,
                        cwe_id=cwe_str,
                        file_path=reported_file,
                        line_number=line_num,
                        end_line_number=end_line_num,
                        severity=item.get("issue_severity", "MEDIUM").upper(),
                        confidence=item.get("issue_confidence", "MEDIUM").upper(),
                        code_snippet=item.get("code", "").strip(),
                        message=item.get("issue_text", "").strip(),
                    )
                )

            return findings

        except subprocess.TimeoutExpired:
            print(f"[!] ERROR: Bandit analysis timed out ({self.timeout}s).")
        except json.JSONDecodeError as err:
            print(f"[!] ERROR: Failed to parse Bandit JSON output: {err}")
        except Exception as err:
            print(f"[!] ERROR: Unexpected error while running Bandit: {err}")

        return []

    def run_semgrep(
        self, target_path: Optional[str] = None, display_path: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """UML Step 2: Runs Semgrep static analyzer with lightweight memory constraints."""
        resolved_target = str(target_path if target_path else self.target_path)
        semgrep_bin = shutil.which("semgrep") or "semgrep"
        cmd = [
            semgrep_bin,
            "scan",
            "--json",
            "--quiet",
            "--metrics=off",
            "--jobs",
            "1",
            "--max-memory",
            "1024",
            "--config",
            "p/python",
        ]

        if self.rules_file and self.rules_file.exists():
            cmd.extend(["--config", str(self.rules_file)])

        cmd.append(resolved_target)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=self.timeout,
                check=False,
            )

            if not result.stdout.strip():
                return []

            data = json.loads(result.stdout)
            findings: List[Dict[str, Any]] = []

            for item in data.get("results", []):
                start_info = item.get("start", {})
                end_info = item.get("end", {})
                extra_info = item.get("extra", {})
                metadata = extra_info.get("metadata", {})

                line_num = int(start_info.get("line", 1))
                end_line_num = int(end_info.get("line", line_num))

                raw_severity = extra_info.get("severity", "WARNING").upper()
                severity = self.SEMGREP_SEVERITY_MAP.get(raw_severity, "MEDIUM")
                confidence = str(metadata.get("confidence", "MEDIUM")).upper()

                item_path = str(item.get("path", resolved_target))
                reported_file = str(display_path) if display_path else item_path

                raw_lines = extra_info.get("lines", "").strip()
                if not raw_lines or "requires login" in raw_lines.lower():
                    code_snippet = self._extract_code_snippet(
                        item_path, line_num, end_line_num
                    )
                else:
                    code_snippet = raw_lines

                findings.append(
                    self._build_finding_record(
                        tool="semgrep",
                        rule_id=item.get("check_id", "UNKNOWN_RULE"),
                        cwe_id=self._normalize_cwe(metadata.get("cwe")),
                        file_path=reported_file,
                        line_number=line_num,
                        end_line_number=end_line_num,
                        severity=severity,
                        confidence=confidence,
                        code_snippet=code_snippet,
                        message=extra_info.get("message", "").strip(),
                    )
                )

            return findings

        except subprocess.TimeoutExpired:
            print(f"[!] ERROR: Semgrep analysis timed out ({self.timeout}s).")
        except json.JSONDecodeError as err:
            print(f"[!] ERROR: Failed to parse Semgrep JSON output: {err}")
        except Exception as err:
            print(f"[!] ERROR: Unexpected error while running Semgrep: {err}")

        return []

    def scan(self, target: Optional[Union[str, Path]] = None) -> List[Dict[str, Any]]:
        """Team pipeline primary method: executes both Bandit and Semgrep on target or self.target_path."""
        target_to_scan = target or self.target_path
        if not target_to_scan:
            raise ValueError("target_path must be set when calling scan().")
        report = self.analyze_file(file_path=str(target_to_scan))
        return report["findings"]

    def scan_with_bandit(self, target: Optional[Union[str, Path]] = None) -> List[Dict[str, Any]]:
        """Team pipeline compatibility method: executes Bandit on target or self.target_path."""
        target_to_scan = target or self.target_path
        if not target_to_scan:
            raise ValueError("target_path must be set when calling scan_with_bandit().")
        return self.run_bandit(target_path=str(target_to_scan))

    def scan_with_semgrep(self, target: Optional[Union[str, Path]] = None) -> List[Dict[str, Any]]:
        """Team pipeline compatibility method: executes Semgrep on target or self.target_path."""
        target_to_scan = target or self.target_path
        if not target_to_scan:
            raise ValueError("target_path must be set when calling scan_with_semgrep().")
        return self.run_semgrep(target_path=str(target_to_scan))

    def scan_all(self, target: Optional[Union[str, Path]] = None) -> List[Dict[str, Any]]:
        """Team pipeline helper method: executes both Bandit and Semgrep."""
        return self.scan(target)

    def analyze_file(
        self, file_path: Optional[str] = None, virtual_file_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """UML Steps 1, 2, 3, and 5: Runs hybrid SAST analysis on a physical .py file or directory."""
        resolved_path = str(file_path if file_path else self.target_path)
        display_name = virtual_file_name if virtual_file_name else resolved_path

        bandit_findings = self.run_bandit(
            target_path=resolved_path, display_path=virtual_file_name
        )
        semgrep_findings = self.run_semgrep(
            target_path=resolved_path, display_path=virtual_file_name
        )

        all_findings = sorted(
            bandit_findings + semgrep_findings,
            key=lambda x: (x["line_number"], x["end_line_number"], x["tool"]),
        )

        is_vulnerable = len(all_findings) > 0
        status = "VULNERABLE" if is_vulnerable else "CLEAN"
        diagnostic_report = self._build_diagnostic_report(all_findings)

        return {
            "is_vulnerable": is_vulnerable,
            "status": status,
            "findings": all_findings,
            "diagnostic_report": diagnostic_report,
        }

    def analyze_code(
        self, source_code: str, file_name: str = "inline_code.py"
    ) -> Dict[str, Any]:
        """Writes raw Python source code to a temporary file and invokes hybrid SAST analysis."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", encoding="utf-8", delete=False
        ) as tmp_file:
            tmp_file.write(source_code)
            tmp_path = tmp_file.name

        try:
            return self.analyze_file(
                file_path=tmp_path, virtual_file_name=file_name
            )
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def _build_diagnostic_report(self, findings: List[Dict[str, Any]]) -> str:
        """UML Step 5: Formats all SAST findings into a concise prompt block for the LLM."""
        if not findings:
            return "SAST Diagnostic Report: No static security vulnerabilities detected (STATUS: CLEAN)."

        lines = [
            "=== SAST SECURITY DIAGNOSTIC REPORT ===",
            f"Status: VULNERABLE | Total Findings: {len(findings)}",
            "-" * 50,
        ]

        for idx, finding in enumerate(findings, start=1):
            lines.append(
                f"[{idx}] Tool: {finding['tool'].upper()} | "
                f"Rule: {finding['rule_id']} | "
                f"CWE: {finding['cwe_id']}"
            )
            lines.append(
                f"    File: {finding['file_path']} "
                f"(Lines {finding['line_number']}-{finding['end_line_number']})"
            )
            lines.append(
                f"    Severity: {finding['severity']} | "
                f"Confidence: {finding['confidence']}"
            )
            lines.append(f"    Issue: {finding['message']}")
            lines.append(f"    Vulnerable Code:\n    {finding['code_snippet']}")
            lines.append("-" * 50)

        return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        engine = SASTEngine(target_path=target)
        report = engine.analyze_file()
        print(report["diagnostic_report"])
    else:
        sample_code = '''import subprocess

def run_ping(host: str) -> None:
    subprocess.Popen(f"ping -c 1 {host}", shell=True)
'''
        engine = SASTEngine()
        report = engine.analyze_code(sample_code, file_name="sample_task/app.py")
        print(report["diagnostic_report"])
