import ast
from pathlib import Path
from typing import Optional, Dict, Any, List

class ASTContextPruner:
    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        with open(self.file_path, "r", encoding="utf-8") as f:
            self.source_code = f.read()
        self.lines = self.source_code.splitlines()
        self.tree = ast.parse(self.source_code)

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

    def prune_enclosing_function(self, target_line: int) -> Optional[Dict[str, Any]]:
        """
        Verilen hedef satır numarasını (SAST'ın işaret ettiği satırı) kapsayan
        en dar fonksiyonu AST yardımıyla bulur ve kırpar.
        """
        matching_func = None

        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = node.lineno
                end = getattr(node, "end_lineno", node.lineno)

                if start <= target_line <= end:
                    # İç içe fonksiyonlar varsa en dar olanını seçebilmek için:
                    if matching_func is None or (end - start < matching_func["end_line"] - matching_func["start_line"]):
                        func_code = "\n".join(self.lines[start - 1 : end])
                        matching_func = {
                            "name": node.name,
                            "start_line": start,
                            "end_line": end,
                            "code": func_code,
                            "args": [arg.arg for arg in node.args.args]
                        }

        if not matching_func:
            return None

        imports = self.get_imports()
        return {
            "file": str(self.file_path),
            "function_name": matching_func["name"],
            "start_line": matching_func["start_line"],
            "end_line": matching_func["end_line"],
            "arguments": matching_func["args"],
            "function_code": matching_func["code"],
            "imports": "\n".join(imports)
        }

if __name__ == "__main__":
    import sys
    file_arg = sys.argv[1] if len(sys.argv) > 1 else "sample_task/app.py"
    line_arg = int(sys.argv[2]) if len(sys.argv) > 2 else 32

    pruner = ASTContextPruner(file_arg)
    result = pruner.prune_enclosing_function(line_arg)

    if result:
        print(f"\n[AST Pruner] Satır {line_arg} için fonksiyon başarıyla kırpıldı!")
        print(f"[-] Fonksiyon: {result['function_name']} (Satır {result['start_line']} - {result['end_line']})")
        print("[-] Importlar:")
        print(result["imports"])
        print("[-] Kırpılan Fonksiyon Kodu:\n")
        print(result["function_code"])
    else:
        print(f"[!] Satır {line_arg} bir fonksiyon bloğu içinde bulunamadı.")
