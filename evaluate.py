import argparse
import csv
import json

def evaluate(pred_csv: str, ground_truth_csv: str):
    with open(ground_truth_csv, "r", encoding="utf-8") as f:
        gt_rows = {r["sample_id"]: r for r in csv.DictReader(f)}

    with open(pred_csv, "r", encoding="utf-8") as f:
        pred_rows = {r["sample_id"]: r for r in csv.DictReader(f)}

    tp, fp, fn, tn = 0, 0, 0, 0

    for sample_id, gt in gt_rows.items():
        gt_vulns = json.loads(gt["vulnerabilities"]) if gt["vulnerabilities"] else []
        pred = pred_rows.get(sample_id, {})
        pred_vulns = json.loads(pred.get("vulnerabilities", "[]")) if pred.get("vulnerabilities") else []

        is_gt_vuln = len(gt_vulns) > 0
        is_pred_vuln = len(pred_vulns) > 0

        if is_gt_vuln and is_pred_vuln:
            tp += 1
        elif not is_gt_vuln and is_pred_vuln:
            fp += 1
        elif is_gt_vuln and not is_pred_vuln:
            fn += 1
        else:
            tn += 1

    total = tp + fp + fn + tn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    print("=== RESULTADOS DE EVALUACIÓN ===")
    print(f"Total muestras: {total}")
    print(f"TP: {tp} | FP: {fp} | FN: {fn} | TN: {tn}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-Score:  {f1:.4f}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--predictions", type=str, required=True)
    parser.add_argument("--ground-truth", type=str, required=True)
    args = parser.parse_args()

    evaluate(args.predictions, args.ground_truth)
