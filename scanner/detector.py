import re
from pathlib import Path
from .untrusted import UntrustedDataLoader
from .loader import YAMLLoader

class VulnerabilityDetector:
    def __init__(self, loader: YAMLLoader, untrusted_loader: UntrustedDataLoader):
        self.loader = loader
        self.untrusted_loader = untrusted_loader
        self.expr_pattern = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")

    def find_run_step_line(self, lines: list[str], start_search: int = 0) -> int:
        """Encuentra la línea exacta (1-indexed) de un comando run:"""
        for idx in range(start_search, len(lines)):
            line = lines[idx].strip()
            if line.startswith("run:"):
                return idx + 1
        return -1

    def analyze_file(self, file_path: Path, rel_path_str: str) -> list[dict]:
        vulnerabilities = []
        raw_lines = self.loader.read_raw_lines(file_path)
        if not raw_lines:
            return vulnerabilities

        current_run_line = -1
        in_run_block = False

        for i, line in enumerate(raw_lines):
            line_num = i + 1
            stripped = line.strip()

            if stripped.startswith("run:"):
                current_run_line = line_num
                in_run_block = True
            elif stripped.startswith("- name:") or stripped.startswith("uses:") or (stripped.startswith("step") and ":" in stripped):
                if not line.startswith(" ") and not line.startswith("\t"):
                    in_run_block = False

            # Buscar expresiones de GitHub Actions dentro de las líneas de código o comandos run:
            matches = self.expr_pattern.findall(line)
            for expr in matches:
                if self.untrusted_loader.is_untrusted_expression(expr):
                    # Si estamos en un bloque run: o en la misma línea
                    sink_line = current_run_line if current_run_line != -1 else line_num
                    vulnerabilities.append({
                        "from": f"{rel_path_str}:{line_num}",
                        "to": f"{rel_path_str}:{sink_line}",
                        "explanation": f"Entrada no confiable `${{{{ {expr} }}}}` utilizada directamente en una sentencia ejecutable `run:`."
                    })
                    break  # Evitar registrar múltiples vulnerabilidades duplicate por la misma línea

        return vulnerabilities
