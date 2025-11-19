# preprocess_bloom.py
"""
Create a Bloom filter from a large password file (one password per line).
Saves the Bloom filter to bloomfilter.bf (binary).
Requires pybloom_live.
"""
import argparse
from pybloom_live import BloomFilter
from tqdm import tqdm
import pickle

def build_bloom(input_file: str, out_file: str, expected_elements: int = 50_000_000, error_rate: float = 0.001):
    print("Creating Bloom filter (this may take time and memory)...")
    bf = BloomFilter(capacity=expected_elements, error_rate=error_rate)
    count = 0
    with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in tqdm(f, desc="Adding entries"):
            pw = line.strip()
            if not pw:
                continue
            bf.add(pw)
            count += 1
    with open(out_file, "wb") as out:
        pickle.dump(bf, out)
    print(f"Done. Added ~{count} items. Saved Bloom filter to {out_file}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("input_file")
    ap.add_argument("out_file", nargs="?", default="bloomfilter.bf")
    ap.add_argument("--expected", type=int, default=50000000)
    ap.add_argument("--err", type=float, default=0.001)
    args = ap.parse_args()
    build_bloom(args.input_file, args.out_file, expected_elements=args.expected, error_rate=args.err)
