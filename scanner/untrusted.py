import csv
import re
from pathlib import Path

class UntrustedDataLoader:
    def __init__(self, csv_path: str | Path):
        self.csv_path = Path(csv_path)
        self.sources = set()
        self.patterns = []
        self._load_sources()

    def _load_sources(self):
        if not self.csv_path.exists():
            raise FileNotFoundError(f"No se encontró el archivo de datos no confiables: {self.csv_path}")

        with open(self.csv_path, mode="r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            for row in reader:
                if not row:
                    continue
                expr = row[0].strip()
                if expr:
                    self.sources.add(expr)
                    # Convertir comodines como [*] a expresiones regulares
                    regex_str = re.escape(expr).replace(r"\[\*\]", r"\[\d+\]")
                    regex_str = f"^{regex_str}$"
                    self.patterns.append(re.compile(regex_str))

    def is_untrusted_expression(self, expression: str) -> bool:
        """Verifica si una expresión o parte de ella coincide con una fuente no confiable."""
        clean_expr = expression.strip()
        
        # Eliminar envoltorios ${{ }} si existen
        if clean_expr.startswith("${{") and clean_expr.endswith("}}"):
            clean_expr = clean_expr[3:-2].strip()

        # Verificar coincidencia directa
        if clean_expr in self.sources:
            return True

        # Verificar coincidencia con regex (por ejemplo con comodines)
        for pattern in self.patterns:
            if pattern.search(clean_expr):
                return True

        # Rastrear si alguna subexpresión no confiable está presente
        for source in self.sources:
            base_source = source.replace("[*]", "")
            if base_source in clean_expr:
                return True

        return False
