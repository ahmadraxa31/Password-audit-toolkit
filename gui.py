# gui.py
import streamlit as st
from utils import summarize_password
import pickle
from collections import Counter
import random
import string
import math

# ---------------- Load Bloom Filter ---------------- #
try:
    with open("leaked_bloom.pkl", "rb") as f:
        bloom_filter = pickle.load(f)
except FileNotFoundError:
    bloom_filter = None

# ---------------- Helper Functions ---------------- #
def calculate_entropy(password: str) -> float:
    counts = Counter(password)
    length = len(password)
    ent = 0.0
    for c in counts:
        p = counts[c] / length
        ent -= p * math.log2(p)
    return ent * length

def suggest_password(length=14):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(random.choice(chars) for _ in range(length))

common_words = ["password", "admin", "qwerty", "sonic", "letmein", "123456", "abc123"]

# ---------------- Streamlit UI ---------------- #
st.set_page_config(page_title="🔐 Password Security Audit Tool", layout="centered")

st.markdown(
    """
    <h1 style='text-align:center; color:#4CAF50;'>🔐 Password Security Audit Tool</h1>
    <p style='text-align:center;'>Check if your password is strong or leaked in breaches</p>
    """,
    unsafe_allow_html=True
)

# ------------ Password Input Form ------------- #
with st.form("password_form", clear_on_submit=False):
    password = st.text_input(
        "Enter your password:",
        type="password",
        max_chars=64,
        help="Your password is never stored."
    )
    submitted = st.form_submit_button("Check Password", use_container_width=True)

# ------------ Process Password ------------- #
if submitted:

    if not password:
        st.error("⚠ Please enter a password.")
    else:
        summary = summarize_password(password)
        ent = calculate_entropy(password)

        # Check weak/common words
        weak_pattern = any(word.lower() in password.lower() for word in common_words)

        # Check Bloom filter
        leaked = False
        if bloom_filter and summary["sha256"] in bloom_filter:
            leaked = True

        # ---------------- Layout Columns ---------------- #
        col1, col2 = st.columns([2, 1])

        with col1:
            st.subheader("🔎 Password Analysis")
            st.metric(label="Strength Score", value=f"{summary['strength_score']}/5")
            st.write(f"**Length:** {summary['length']} characters")
            st.write(f"**Entropy:** {round(ent,2)} bits")
            if weak_pattern:
                st.warning("⚠ Contains common words or predictable patterns!")

        with col2:
            st.subheader("💡 Suggestions")
            if summary['strength_score'] < 5 or ent < 50 or weak_pattern or leaked:
                st.info(f"Suggested stronger password: `{suggest_password()}`")
            else:
                st.success("✅ This password is strong!")

        # ---------------- Leak Check ---------------- #
        st.subheader("🛑 Leak Check")
        if leaked:
            st.error("❌ This password appears in leaked datasets! DO NOT USE IT.")
        else:
            st.success("✅ Password not found in leak list (or database unavailable).")

        # ---------------- Advanced Info ---------------- #
        with st.expander("Show Advanced Info"):
            st.write(f"**SHA-256 Hash:** `{summary['sha256']}`")
            st.write(f"**Entropy:** {round(ent,2)} bits")
            st.write(f"**Strength Score:** {summary['strength_score']} / 5")
            st.write(f"**Length:** {summary['length']} characters")

# ---------------- Footer ---------------- #
st.markdown("---")
st.markdown(
    "<p style='text-align:center; color:gray;'>Sponsored by Ahmad Raza</p>",
    unsafe_allow_html=True
)
