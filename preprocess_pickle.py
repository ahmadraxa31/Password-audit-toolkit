# preprocess_pickle.py
import hashlib
import pickle
from tqdm import tqdm
import sys

def preprocess_to_pickle(input_file: str, output_file: str):
    hashed_set = set()
    with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in tqdm(f, desc="Hashing lines"):
            pwd = line.strip()
            if not pwd:
                continue
            h = hashlib.sha256(pwd.encode("utf-8")).hexdigest()
            hashed_set.add(h)
    print(f"Total unique hashes: {len(hashed_set)}")
    with open(output_file, "wb") as out:
        pickle.dump(hashed_set, out)
    print("Saved to", output_file)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python preprocess_pickle.py raw_passwords.txt hashed_passwords.pkl")
        sys.exit(1)
    preprocess_to_pickle(sys.argv[1], sys.argv[2])
