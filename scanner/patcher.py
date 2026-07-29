import difflib
import re
from pathlib import Path

class PatchGenerator:
    def __init__(self):
        self.expr_pattern = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")

    def sanitize_var_name(self, expr: str) -> str:
        """Convierte una expresión como github.head_ref en un nombre válido de variable de entorno."""
        clean = expr.replace("github.", "").replace("event.", "").replace("pull_request.", "").replace(".", "_")
        clean = re.sub(r"[^a-zA-Z0-9_]", "", clean).upper()
        return clean or "UNTRUSTED_VAR"

    def patch_file(self, file_path: Path, vulns: list[dict], output_patch_path: Path) -> dict | None:
        if not file_path.exists():
            return None

        with open(file_path, "r", encoding="utf-8") as f:
            original_lines = f.readlines()

        modified_lines = list(original_lines)
        added_envs = {}

        # Generar cambios en el contenido del archivo YAML
        for vuln in vulns:
            to_parts = vuln["to"].split(":")
            if len(to_parts) < 2:
                continue
            line_idx = int(to_parts[1]) - 1

            if line_idx >= len(modified_lines):
                continue

            target_line = modified_lines[line_idx]
            matches = self.expr_pattern.findall(target_line)

            for expr in matches:
                var_name = self.sanitize_var_name(expr)
                env_expr = f"${{{{ {expr} }}}}"
                
                # Sustituir la expresión directa por la variable entre comillas "$VAR"
                modified_lines[line_idx] = modified_lines[line_idx].replace(env_expr, f'"${var_name}"')
                added_envs[var_name] = env_expr

        # Crear el parche en formato diff unificado
        diff = difflib.unified_diff(
            original_lines,
            modified_lines,
            fromfile=str(file_path),
            tofile=str(file_path),
            lineterm=""
        )
        patch_content = "\n".join(diff)

        if patch_content:
            output_patch_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_patch_path, "w", encoding="utf-8") as f:
                f.write(patch_content)

            return {
                "file": str(file_path),
                "patch_file": str(output_patch_path),
                "explanation": "La expresión no confiable se movió a una variable de entorno `env:` y se accedió como variable de shell entre comillas."
            }
        return None
