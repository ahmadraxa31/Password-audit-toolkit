# build_bloom.py  (run once to create leaked_bloom.pkl)
from pybloom_live import BloomFilter
import pickle

# tune capacity and error_rate for your dataset
capacity = 20_000_000     # number of passwords you expect
error_rate = 0.001        # false positive rate (0.1%)

bloom = BloomFilter(capacity=capacity, error_rate=error_rate)

with open("leaked_passwords.txt", "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        pw = line.strip()
        if pw:
            bloom.add(pw)   # or add pw_hash if you prefer hashed bloom

with open("leaked_bloom.pkl", "wb") as out:
    pickle.dump(bloom, out)
print("Built and saved leaked_bloom.pkl")
