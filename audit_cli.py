# audit_cli.py
import argparse
import pickle
from utils import summarize_password
import csv
from tqdm import tqdm

def load_bloom(path):
    with open(path, "rb") as f:
        return pickle.load(f)

def audit_file(input_file, out_csv="reports/audit_report.csv", bloom_path=None):
    bfilter = None
    if bloom_path:
        bfilter = load_bloom(bloom_path)
    results = []
    with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in tqdm(f, desc="Auditing"):
            pw = line.strip()
            if not pw:
                continue
            summary = summarize_password(pw)
            # if bloom available, override pwned_count/probability heuristically:
            if bfilter is not None:
                summary['bloom_probable_pwned'] = pw in bfilter
            results.append(summary)
    # save CSV summary
    import os
    os.makedirs("reports", exist_ok=True)
    keys = ["password", "strength_score", "entropy_bits", "pwned_count", "pwned_probability"]
    with open(out_csv, "w", newline='', encoding="utf-8") as cf:
        writer = csv.DictWriter(cf, fieldnames=keys)
        writer.writeheader()
        for r in results:
            writer.writerow({k: r.get(k) for k in keys})
    print("Wrote", out_csv)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", "-i", required=True)
    ap.add_argument("--bloom", help="Optional bloomfilter.bf to use for fast local checks")
    ap.add_argument("--out", default="reports/audit_report.csv")
    args = ap.parse_args()
    audit_file(args.input, out_csv=args.out, bloom_path=args.bloom)
