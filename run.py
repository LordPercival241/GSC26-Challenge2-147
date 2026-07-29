import argparse
import csv
import json
from pathlib import Path

from scanner.untrusted import UntrustedDataLoader
from scanner.loader import YAMLLoader
from scanner.detector import VulnerabilityDetector
from scanner.patcher import PatchGenerator

def main():
    parser = argparse.ArgumentParser(description="GSC26 Challenge 2 - Automated Vulnerability Detector & Patcher")
    parser.add_argument("--data-dir", type=str, default="../", help="Directorio base donde se encuentran train/ o validation/")
    parser.add_argument("--untrusted-csv", type=str, default="../untrusted_data.csv", help="Ruta al archivo untrusted_data.csv")
    parser.add_argument("--input-csv", type=str, default="../train.csv", help="Ruta al archivo train.csv o test.csv")
    parser.add_argument("--output-csv", type=str, default="test.csv", help="Ruta para guardar los resultados finales CSV")
    parser.add_argument("--patches-dir", type=str, default="patches", help="Directorio donde guardar los parches .patch")

    args = parser.parse_args()

    base_dir = Path(args.data_dir)
    untrusted_loader = UntrustedDataLoader(args.untrusted_csv)
    yaml_loader = YAMLLoader(base_dir)
    detector = VulnerabilityDetector(yaml_loader, untrusted_loader)
    patcher = PatchGenerator()

    output_rows = []
    patches_dir = Path(args.patches_dir)
    patches_dir.mkdir(parents=True, exist_ok=True)

    if not Path(args.input_csv).exists():
        print(f"Error: no se encontró el archivo de entrada {args.input_csv}")
        return

    with open(args.input_csv, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            sample_id = row["sample_id"]
            
            # Buscar archivo de workflow correspondiente en workflows/
            workflow_path = base_dir / "train" / "workflows" / f"{sample_id}.yml"
            if not workflow_path.exists():
                workflow_path = base_dir / "workflows" / f"{sample_id}.yml"

            rel_path = f"train/workflows/{sample_id}.yml"
            
            detected_vulns = []
            generated_patches = []

            if workflow_path.exists():
                vulns = detector.analyze_file(workflow_path, rel_path)
                if vulns:
                    detected_vulns.extend(vulns)
                    patch_file_path = patches_dir / f"{sample_id}.patch"
                    patch_info = patcher.patch_file(workflow_path, vulns, patch_file_path)
                    if patch_info:
                        generated_patches.append(patch_info)

            output_rows.append({
                "sample_id": sample_id,
                "vulnerabilities": json.dumps(detected_vulns, ensure_ascii=False),
                "patches": json.dumps(generated_patches, ensure_ascii=False)
            })

    # Guardar resultados en CSV
    with open(args.output_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["sample_id", "vulnerabilities", "patches"])
        writer.writeheader()
        writer.writerows(output_rows)

    print(f"Procesamiento completado. Archivo generado: {args.output_csv} con {len(output_rows)} muestras.")

if __name__ == "__main__":
    main()
