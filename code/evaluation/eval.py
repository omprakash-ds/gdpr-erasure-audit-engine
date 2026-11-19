import csv
from difflib import SequenceMatcher
import json
import sys


def normalize_step(step: dict) -> tuple:
    return (
        step.get("phase", ""),
        step.get("system_id", ""),
        step.get("resource_id", ""),
        step.get("operation", ""),
        step.get("state", ""),
        step.get("evidence_id", ""),
    )


def evaluate(pred_csv: str, truth_csv: str = "dataset/sample_output.csv"):
    with open(truth_csv, encoding="utf-8") as f:
        truth = {r["case_id"]: r for r in csv.DictReader(f)}
    with open(pred_csv, encoding="utf-8") as f:
        preds = {r["case_id"]: r for r in csv.DictReader(f)}

    total = len(truth)
    status_ok = 0
    exact_steps_ok = 0
    step_precision_sum = 0.0
    step_recall_sum = 0.0
    field_acc_sum = 0.0
    seq_acc_sum = 0.0
    mismatches = []

    for cid, gt in sorted(truth.items()):
        pr = preds.get(cid)
        if not pr:
            mismatches.append((cid, "MISSING", gt["deletion_status"], []))
            continue

        if pr["deletion_status"] == gt["deletion_status"]:
            status_ok += 1

        gt_steps = [normalize_step(s) for s in json.loads(gt["steps_json"])]
        pr_steps = [normalize_step(s) for s in json.loads(pr["steps_json"])]

        if gt_steps == pr_steps:
            exact_steps_ok += 1
        else:
            mismatches.append((cid, pr["deletion_status"], gt["deletion_status"], (pr_steps, gt_steps)))

        gt_set, pr_set = set(gt_steps), set(pr_steps)
        if not gt_set and not pr_set:
            p, r, f_acc, seq = 1.0, 1.0, 1.0, 1.0
        else:
            inter = len(gt_set & pr_set)
            p = inter / len(pr_set) if pr_set else 0.0
            r = inter / len(gt_set) if gt_set else 0.0
            field_ok = sum(g[i] == p_step[i] for g, p_step in zip(gt_steps, pr_steps) for i in range(6))
            f_acc = field_ok / (6 * max(len(gt_steps), len(pr_steps), 1))
            seq = SequenceMatcher(None, gt_steps, pr_steps).ratio()

        step_precision_sum += p
        step_recall_sum += r
        field_acc_sum += f_acc
        seq_acc_sum += seq

    print(f"=== Evaluation on {total} Sample Cases ===")
    print(f"Status Accuracy   : {status_ok}/{total} ({100*status_ok/total:.1f}%)")
    print(f"Exact Step Match  : {exact_steps_ok}/{total} ({100*exact_steps_ok/total:.1f}%)")
    print(f"Avg Step Precision: {100*step_precision_sum/total:.1f}%")
    print(f"Avg Step Recall   : {100*step_recall_sum/total:.1f}%")
    print(f"Avg Field Accuracy: {100*field_acc_sum/total:.1f}%")
    print(f"Avg Sequence Acc  : {100*seq_acc_sum/total:.1f}%")

    if mismatches:
        print(f"\nFirst 5 Mismatches ({len(mismatches)} total):")
        for cid, p_st, g_st, detail in mismatches[:5]:
            print(f"  - {cid}: pred={p_st} vs truth={g_st}")
            if isinstance(detail, tuple):
                print(f"      pred_steps : {detail[0]}")
                print(f"      truth_steps: {detail[1]}")


if __name__ == "__main__":
    pred_path = sys.argv[1] if len(sys.argv) > 1 else "sample_pred.csv"
    evaluate(pred_path)