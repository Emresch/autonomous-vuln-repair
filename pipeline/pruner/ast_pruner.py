import ast
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple


class ASTContextPruner:
    def __init__(self, file_path: str, source_code: Optional[str] = None):
        self.file_path = Path(file_path)
        if source_code is not None:
            self.source_code = source_code
        else:
            with open(self.file_path, "r", encoding="utf-8") as f:
                self.source_code = f.read()
        self.lines = self.source_code.splitlines()
        self.tree = ast.parse(self.source_code)

    @staticmethod
    def validate_syntax(source_code: str, filename: str = "<candidate>") -> Tuple[bool, Optional[str]]:
        """Diske yazmadan önce Python kaynak kodunun sözdizimini ast.parse() ile doğrular."""
        try:
            ast.parse(source_code, filename=filename)
            return True, None
        except (SyntaxError, IndentationError) as err:
            line_info = f"line {err.lineno}" if err.lineno else "unknown line"
            detail = f"{type(err).__name__} ({line_info}): {err.msg}"
            if err.text:
                detail += f"\n  Offending line: {err.text.rstrip()}"
            return False, detail

    def get_imports(self) -> List[str]:
        """Dosyanın en başındaki import ifadelerini ayıklar."""
        import_lines = []
        for node in self.tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                # Import satırlarını orijinal metinden çek
                start = node.lineno - 1
                end = getattr(node, "end_lineno", node.lineno)
                import_lines.extend(self.lines[start:end])
        return import_lines

    def _iter_functions(
        self,
        body: List[ast.stmt],
        class_stack: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """AST ağacındaki tüm fonksiyon/metot düğümlerini sınıf bağlamıyla birlikte toplar."""
        class_stack = class_stack or []
        collected: List[Dict[str, Any]] = []

        for node in body:
            if isinstance(node, ast.ClassDef):
                collected.extend(self._iter_functions(node.body, class_stack + [node.name]))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                decorator_lines = [d.lineno for d in getattr(node, "decorator_list", [])]
                start = min([node.lineno] + decorator_lines)
                end = getattr(node, "end_lineno", node.lineno)
                class_name = ".".join(class_stack) if class_stack else None
                qualified_name = f"{class_name}.{node.name}" if class_name else node.name

                collected.append({
                    "name": node.name,
                    "class_name": class_name,
                    "qualified_name": qualified_name,
                    "start_line": start,
                    "end_line": end,
                    "code": "\n".join(self.lines[start - 1 : end]),
                    "args": [arg.arg for arg in node.args.args],
                })

                # İç içe (nested) fonksiyonları da tara
                nested = self._iter_functions(node.body, class_stack)
                collected.extend(nested)

        return collected

    def _format_chunk(self, func_info: Dict[str, Any]) -> Dict[str, Any]:
        imports = self.get_imports()
        return {
            "file": self.file_path.as_posix(),
            "function_name": func_info["name"],
            "class_name": func_info["class_name"],
            "qualified_name": func_info["qualified_name"],
            "start_line": func_info["start_line"],
            "end_line": func_info["end_line"],
            "arguments": func_info["args"],
            "function_code": func_info["code"],
            "imports": "\n".join(imports),
        }

    def prune_enclosing_function(self, target_line: int) -> Optional[Dict[str, Any]]:
        """
        Verilen hedef satır numarasını (SAST'ın işaret ettiği satırı) kapsayan
        en dar fonksiyonu AST yardımıyla bulur ve kırpar.
        """
        matching_func = None

        for func_info in self._iter_functions(self.tree.body):
            start = func_info["start_line"]
            end = func_info["end_line"]
            if start <= target_line <= end:
                # İç içe fonksiyonlar varsa en dar olanını seç
                if matching_func is None or (
                    end - start < matching_func["end_line"] - matching_func["start_line"]
                ):
                    matching_func = func_info

        if not matching_func:
            return None

        return self._format_chunk(matching_func)

    def prune_function_by_name(
        self,
        function_name: str,
        class_name: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Satır kaymalarından etkilenmeden fonksiyonu (ve varsa sınıf bağlamını)
        doğrudan adına göre AST üzerinde konumlandırır ve kırpar.
        """
        candidates = self._iter_functions(self.tree.body)
        for func_info in candidates:
            if func_info["name"] == function_name and func_info["class_name"] == class_name:
                return self._format_chunk(func_info)

        # Sınıf adı belirtilmediyse veya eşleşmediyse yalnızca fonksiyon adına düş
        if class_name is None:
            for func_info in candidates:
                if func_info["name"] == function_name:
                    return self._format_chunk(func_info)

        return None


if __name__ == "__main__":
    import sys

    file_arg = sys.argv[1] if len(sys.argv) > 1 else "pipeline/sample_task/app.py"
    line_arg = int(sys.argv[2]) if len(sys.argv) > 2 else 24

    pruner = ASTContextPruner(file_arg)
    result = pruner.prune_enclosing_function(line_arg)

    if result:
        print(f"\n[AST Pruner] Satır {line_arg} için fonksiyon başarıyla kırpıldı!")
        print(
            f"[-] Fonksiyon: {result['qualified_name']} "
            f"(Satır {result['start_line']} - {result['end_line']})"
        )
        print("[-] Importlar:")
        print(result["imports"])
        print("[-] Kırpılan Fonksiyon Kodu:\n")
        print(result["function_code"])
    else:
        print(f"[!] Satır {line_arg} bir fonksiyon bloğu içinde bulunamadı.")
