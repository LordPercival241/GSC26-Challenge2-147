import argparse
import csv
import json
import os
from pathlib import Path

from scanner.untrusted import UntrustedDataLoader
from scanner.loader import YAMLLoader
from scanner.detector import VulnerabilityDetector
from scanner.patcher import PatchGenerator
from scanner.llm_client import OpenRouterClient, DEFAULT_API_KEY, DEFAULT_MODEL

def main():
    parser = argparse.ArgumentParser(description="GSC26 Challenge 2 - Automated Vulnerability Detector & Patcher")
    parser.add_argument("--data-dir", type=str, default="../", help="Base directory containing train/, validation/, or test/")
    parser.add_argument("--split", type=str, default="train", help="Dataset split: train, validation, or test")
    parser.add_argument("--untrusted-csv", type=str, default=None, help="Path to untrusted_data.csv")
    parser.add_argument("--input-csv", type=str, default=None, help="Input CSV path (defaults to {data_dir}/{split}.csv)")
    parser.add_argument("--output-csv", type=str, default=None, help="Output CSV path (defaults to test.csv if split is test, or {split}_pred.csv)")
    parser.add_argument("--patches-dir", type=str, default=None, help="Directory to save .patch files")
    parser.add_argument("--api-key", type=str, default=DEFAULT_API_KEY, help="OpenRouter API Key for LLM patch explanation")
    parser.add_argument("--model", type=str, default=DEFAULT_MODEL, help="OpenRouter LLM model identifier")

    args = parser.parse_args()

    base_dir = Path(args.data_dir).resolve()
    split = args.split.strip()

    # Determine default paths if not explicitly provided
    untrusted_csv_path = Path(args.untrusted_csv) if args.untrusted_csv else base_dir / "untrusted_data.csv"
    if not untrusted_csv_path.exists():
        untrusted_csv_path = Path("../untrusted_data.csv")

    input_csv_path = Path(args.input_csv) if args.input_csv else base_dir / f"{split}.csv"
    if not input_csv_path.exists() and split == "train":
        input_csv_path = Path("../train.csv")

    output_csv_path = Path(args.output_csv) if args.output_csv else Path("test.csv" if split in ["test", "validation"] else f"{split}_pred.csv")
    patches_dir = Path(args.patches_dir) if args.patches_dir else Path("patches")
    patches_dir.mkdir(parents=True, exist_ok=True)

    # Initialize OpenRouter LLM client with Team API Key
    llm_key = args.api_key or os.getenv("OPENROUTER_API_KEY", DEFAULT_API_KEY)
    llm_client = OpenRouterClient(api_key=llm_key, model=args.model)

    print(f"[*] Initializing Q-Suyo-Guard Scanner...")
    print(f"    - Split: {split}")
    print(f"    - Base Data Dir: {base_dir}")
    print(f"    - Untrusted Data CSV: {untrusted_csv_path}")
    print(f"    - Input CSV: {input_csv_path}")
    print(f"    - Output CSV: {output_csv_path}")
    print(f"    - Patches Dir: {patches_dir}")
    print(f"    - OpenRouter Model: {args.model}")
    print(f"    - OpenRouter API Key: {'Configured' if llm_key else 'None'}")

    untrusted_loader = UntrustedDataLoader(untrusted_csv_path)
    yaml_loader = YAMLLoader(base_dir)
    detector = VulnerabilityDetector(yaml_loader, untrusted_loader)
    patcher = PatchGenerator(llm_client=llm_client)

    output_rows = []

    if not input_csv_path.exists():
        print(f"[!] Warning: Input CSV file {input_csv_path} not found. Scanning workflows directory directly...")
        workflows_dir = base_dir / split / "workflows"
        if not workflows_dir.exists():
            workflows_dir = base_dir / "workflows"
        
        sample_files = list(workflows_dir.glob("*.yml")) + list(workflows_dir.glob("*.yaml"))
        sample_ids = [f.stem for f in sample_files]
    else:
        with open(input_csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            sample_ids = [row["sample_id"] for row in reader]

    for sample_id in sample_ids:
        # Locate workflow file across split directory structures
        workflow_path = base_dir / split / "workflows" / f"{sample_id}.yml"
        if not workflow_path.exists():
            workflow_path = base_dir / split / "workflows" / f"{sample_id}.yaml"
        if not workflow_path.exists():
            workflow_path = base_dir / "workflows" / f"{sample_id}.yml"
        if not workflow_path.exists():
            workflow_path = base_dir / "train" / "workflows" / f"{sample_id}.yml"

        rel_path = f"{split}/workflows/{sample_id}.yml"
        
        detected_vulns = []
        generated_patches = []

        if workflow_path.exists():
            vulns = detector.analyze_file(workflow_path, rel_path)
            if vulns:
                detected_vulns.extend(vulns)
                patch_file_path = patches_dir / f"{sample_id}.patch"
                patch_info = patcher.patch_file(workflow_path, vulns, patch_file_path)
                if patch_info:
                    patch_info["patch_file"] = f"{split}/patches/{sample_id}.patch" if split != "train" else f"train/patches/{sample_id}.patch"
                    generated_patches.append(patch_info)

        output_rows.append({
            "sample_id": sample_id,
            "vulnerabilities": json.dumps(detected_vulns, ensure_ascii=False),
            "patches": json.dumps(generated_patches, ensure_ascii=False)
        })

    # Write output CSV
    with open(output_csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["sample_id", "vulnerabilities", "patches"])
        writer.writeheader()
        writer.writerows(output_rows)

    print(f"[+] Complete. Processed {len(output_rows)} samples -> Output: {output_csv_path}")

if __name__ == "__main__":
    main()
