# utils.py
import re
import hashlib
import math
from collections import Counter

COMMON_WORDS = [
    "password", "qwerty", "admin", "welcome", "letmein", "dragon", "baseball",
    "iloveyou", "monkey", "login", "abc123", "test"
]

def sha256_hash(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def contains_personal_info(password: str, personal_info: list) -> bool:
    pw_lower = password.lower()
    return any(info.lower() in pw_lower for info in personal_info if info.strip() != "")

def contains_common_word(password: str) -> bool:
    pw_lower = password.lower()
    return any(word in pw_lower for word in COMMON_WORDS)

def detect_patterns(password: str) -> bool:
    sequential = "abcdefghijklmnopqrstuvwxyz0123456789"
    if any(password.lower() in sequential[i:i+len(password)] for i in range(len(sequential))):
        return True
    if re.fullmatch(r"(.)\1{3,}", password):  # like "aaaaaa"
        return True
    if re.fullmatch(r"(..)\1{2,}", password):  # like "ababab"
        return True
    return False

def entropy(password: str) -> float:
    length = len(password)
    counts = Counter(password)
    ent = 0
    for c in counts:
        p = counts[c] / length
        ent -= p * math.log2(p)
    return round(ent * length, 2)

def summarize_password(password: str, personal_info: list = None) -> dict:
    personal_info = personal_info or []

    # Basic checks
    too_short = len(password) < 12
    weak_chars = not (re.search(r"[A-Z]", password)
                      and re.search(r"[a-z]", password)
                      and re.search(r"[0-9]", password)
                      and re.search(r"[^A-Za-z0-9]", password))

    # Hard-fail categories
    name_included = contains_personal_info(password, personal_info)
    common_word = contains_common_word(password)
    pattern = detect_patterns(password)

    hard_fail = name_included or common_word or pattern or too_short or weak_chars

    strength_score = 0
    if not too_short:
        strength_score += 1
    if re.search(r"[A-Z]", password):
        strength_score += 1
    if re.search(r"[a-z]", password):
        strength_score += 1
    if re.search(r"[0-9]", password):
        strength_score += 1
    if re.search(r"[^A-Za-z0-9]", password):
        strength_score += 1

    return {
        "password": password,
        "length": len(password),
        "entropy": entropy(password),
        "strength_score": strength_score,
        "contains_name": name_included,
        "contains_common_word": common_word,
        "pattern_detected": pattern,
        "too_short": too_short,
        "missing_complexity": weak_chars,
        "hard_fail": hard_fail,
        "sha256": sha256_hash(password)
    }
