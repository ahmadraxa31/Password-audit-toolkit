# audit.py
import argparse
import json
import csv
import os
import pickle
import sqlite3
from utils import summarize, sha256_hash
from tqdm import tqdm
from rich import print

def load_pickle(path):
    with open(path, "rb") as f:
        return pickle.load(f)

def connect_sqlite(path):
    conn = sqlite3.connect(path)
    return conn

def check_in_db_sha256(hash_val, db_conn):
    cur = db_conn.cursor()
    cur.execute("SELECT 1 FROM leaked_hashes WHERE hash = ? LIMIT 1", (hash_val,))
    return cur.fetchone() is not None

def audit_password(pwd, source):
    data = summarize(pwd)
    hashed = data["sha256"]
    leaked = False
    if source.get("pkl"):
        leaked = hashed in source["pkl"]
    elif source.get("db_conn"):
        leaked = check_in_db_sha256(hashed, source["db_conn"])
    data["leaked"] = leaked
    return data

def write_reports(results, out_prefix):
    os.makedirs("reports", exist_ok=True)
    json_path = os.path.join("reports", out_prefix + ".json")
    csv_path = os.path.join("reports", out_prefix + ".csv")
    # JSON
    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(results, jf, indent=2)
    # CSV (flatten some fields)
    keys = ["password", "length", "strength_label", "strength_score", "entropy_bits", "leaked"]
    with open(csv_path, "w", newline='', encoding="utf-8") as cf:
        writer = csv.DictWriter(cf, fieldnames=keys)
        writer.writeheader()
        for r in results:
            row = {k: r.get(k) for k in keys}
            writer.writerow(row)
    print(f"[green]Wrote reports:[/green] {json_path}, {csv_path}")

def main():
    ap = argparse.ArgumentParser(description="Password Audit Toolkit")
    ap.add_argument("--password", "-p", help="Single password to audit")
    ap.add_argument("--input-file", "-i", help="File with one password per line to audit")
    ap.add_argument("--pkl", help="Path to hashed_passwords.pkl (optional)")
    ap.add_argument("--db", help="Path to leaked_passwords.db (optional)")
    ap.add_argument("--out", default="audit_report", help="Output report prefix")
    args = ap.parse_args()

    if not args.password and not args.input_file:
        print("[red]Provide --password or --input-file[/red]")
        return

    source = {}
    if args.pkl:
        print("[blue]Loading pickle hash set...[/blue]")
        source["pkl"] = load_pickle(args.pkl)
        print(f"[blue]Loaded {len(source['pkl'])} hashes[/blue]")
    elif args.db:
        print("[blue]Opening sqlite DB...[/blue]")
        source["db_conn"] = connect_sqlite(args.db)
        print("[blue]DB connected.[/blue]")
    else:
        print("[yellow]No leaked DB provided. Only strength & pattern checks will run.[/yellow]")

    targets = []
    if args.password:
        targets.append(args.password.strip())
    if args.input_file:
        with open(args.input_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                pw = line.strip()
                if pw:
                    targets.append(pw)

    results = []
    for pwd in tqdm(targets, desc="Auditing passwords"):
        res = audit_password(pwd, source)
        results.append(res)

    write_reports(results, args.out)

    if source.get("db_conn"):
        source["db_conn"].close()

if __name__ == "__main__":
    main()
