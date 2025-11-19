import sqlite3
import hashlib
from tqdm import tqdm
import sys
import os

def create_db(db_path: str):
    if os.path.exists(db_path):
        os.remove(db_path)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("CREATE TABLE leaked_hashes (hash TEXT PRIMARY KEY)")
    conn.commit()
    return conn

def preprocess_to_sqlite(input_file: str, db_path: str, batch_size: int = 10000):
    conn = create_db(db_path)
    cur = conn.cursor()
    batch = []
    total = 0
    with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in tqdm(f, desc="Processing lines"):
            pwd = line.strip()
            if not pwd:
                continue
            h = hashlib.sha256(pwd.encode("utf-8")).hexdigest()
            batch.append((h,))
            if len(batch) >= batch_size:
                try:
                    cur.executemany("INSERT OR IGNORE INTO leaked_hashes(hash) VALUES(?)", batch)
                    conn.commit()
                except Exception as e:
                    print("Error inserting batch:", e)
                total += len(batch)
                batch = []
        # final batch
        if batch:
            cur.executemany("INSERT OR IGNORE INTO leaked_hashes(hash) VALUES(?)", batch)
            conn.commit()
            total += len(batch)
    cur.execute("CREATE INDEX idx_hash ON leaked_hashes(hash)")
    conn.commit()
    print("Done. Estimated rows processed:", total)
    conn.close()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python preprocess_sqlite.py raw_passwords.txt leaked_passwords.db")
        exit(1)
    preprocess_to_sqlite(sys.argv[1], sys.argv[2])
