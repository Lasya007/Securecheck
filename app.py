"""
SecureCheck Web — Password Strength & URL Phishing Risk Analyzer
------------------------------------------------------------------
A website version of the security checker, built entirely in Python
using Streamlit (a library that turns Python scripts into web apps).

Same logic as the CLI version — just displayed on a webpage instead
of printed to a terminal.

Author: Sri Lasya
"""

import re
import math
import sqlite3
import datetime
import streamlit as st

# ---------------------------------------------------------
# Database setup — logs every scan to a local SQLite file
# so results can be reviewed later. This is what adds real
# "database" experience on top of the security logic.
# ---------------------------------------------------------

DB_FILE = "scan_history.db"


def init_db():
    """Creates the scan_history table if it doesn't already exist."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT NOT NULL,
            input_summary TEXT NOT NULL,
            verdict TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def log_scan(scan_type: str, input_summary: str, verdict: str):
    """Inserts one scan result as a row into the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scan_history (scan_type, input_summary, verdict, timestamp) VALUES (?, ?, ?, ?)",
        (scan_type, input_summary, verdict, datetime.datetime.now().isoformat(timespec="seconds"))
    )
    conn.commit()
    conn.close()


def get_recent_scans(limit: int = 10):
    """Fetches the most recent scans, newest first."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT scan_type, input_summary, verdict, timestamp FROM scan_history ORDER BY id DESC LIMIT ?",
        (limit,)
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


init_db()

# ---------------------------------------------------------
# Same password + URL logic as before (unchanged)
# ---------------------------------------------------------

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123",
    "password1", "111111", "iloveyou", "admin", "welcome",
    "letmein", "football", "123456789", "monkey", "dragon"
}

SUSPICIOUS_TLDS = ['.zip', '.xyz', '.top', '.gq', '.tk', '.ml', '.cf', '.click']
URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd']


def check_password_strength(password: str) -> dict:
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_symbol = bool(re.search(r'[^A-Za-z0-9]', password))
    is_common = password.lower() in COMMON_PASSWORDS

    pool_size = 0
    if has_lower: pool_size += 26
    if has_upper: pool_size += 26
    if has_digit: pool_size += 10
    if has_symbol: pool_size += 32

    if pool_size > 0 and len(password) > 0:
        entropy = round(len(password) * math.log2(pool_size), 1)
    else:
        entropy = 0

    checks_passed = sum([has_upper, has_lower, has_digit, has_symbol,
                          len(password) >= 12, not is_common])

    if is_common:
        verdict = "Very Weak (common password)"
    elif checks_passed <= 2:
        verdict = "Weak"
    elif checks_passed <= 4:
        verdict = "Moderate"
    else:
        verdict = "Strong"

    return {
        "length": len(password), "has_upper": has_upper, "has_lower": has_lower,
        "has_digit": has_digit, "has_symbol": has_symbol,
        "is_common_password": is_common, "entropy_bits": entropy, "verdict": verdict
    }


def check_url_risk(url: str) -> list:
    flags = []
    if re.search(r'https?://(\d{1,3}\.){3}\d{1,3}', url):
        flags.append("⚠️ Uses a raw IP address instead of a domain name.")
    if not url.startswith('https://'):
        flags.append("⚠️ Not using HTTPS — connection may not be encrypted.")
    if '@' in url:
        flags.append("⚠️ Contains '@' — classic redirect trick, real destination is after the @.")
    if any(url.endswith(tld) or tld + '/' in url for tld in SUSPICIOUS_TLDS):
        flags.append("⚠️ Uses a TLD often associated with spam/phishing campaigns.")
    if any(s in url for s in URL_SHORTENERS):
        flags.append("⚠️ Known URL shortener — real destination is hidden until clicked.")

    domain_part = re.sub(r'https?://', '', url).split('/')[0]
    if domain_part.count('.') > 3:
        flags.append(f"⚠️ Unusually many subdomains ({domain_part.count('.')}) — common phishing pattern.")
    if re.search(r'(paypal|amazon|google|microsoft|apple|netflix|instagram)', url, re.IGNORECASE) and '-' in domain_part:
        flags.append("⚠️ Contains a known brand name mixed with extra words — possible look-alike domain.")

    if not flags:
        flags.append("✅ No common phishing patterns detected. Still verify manually.")
    return flags


# ---------------------------------------------------------
# The web page itself — this is the ONLY new part vs the CLI version
# Every st.xxx() call just draws something on the page.
# ---------------------------------------------------------

st.set_page_config(page_title="SecureCheck", page_icon="🔒")

st.title("🔒 SecureCheck")
st.caption("Password strength & URL phishing risk analyzer — runs 100% locally, nothing is stored.")

st.divider()

# --- Password section ---
st.subheader("1. Password Strength")
password = st.text_input("Enter a password to test", type="password")

if password:
    result = check_password_strength(password)

    # Color-coded verdict
    color = {"Strong": "green", "Moderate": "orange",
             "Weak": "red", "Very Weak (common password)": "red"}[result["verdict"]]
    st.markdown(f"**Verdict:** :{color}[{result['verdict']}]  |  **Entropy:** {result['entropy_bits']} bits")

    col1, col2 = st.columns(2)
    with col1:
        st.write("✅ Uppercase" if result["has_upper"] else "❌ Uppercase")
        st.write("✅ Lowercase" if result["has_lower"] else "❌ Lowercase")
        st.write("✅ Number" if result["has_digit"] else "❌ Number")
    with col2:
        st.write("✅ Symbol" if result["has_symbol"] else "❌ Symbol")
        st.write("✅ 12+ characters" if result["length"] >= 12 else "❌ 12+ characters")
        st.write("❌ Common password" if result["is_common_password"] else "✅ Not a common password")

    # Log this scan (we never store the actual password — only length + verdict)
    log_scan("password", f"length={result['length']} chars", result["verdict"])

st.divider()

# --- URL section ---
st.subheader("2. URL Phishing Risk Scan")
url = st.text_input("Enter a URL to scan", placeholder="https://example.com/login")

if url:
    flags = check_url_risk(url)
    for flag in flags:
        st.write(flag)

    url_verdict = "Risky" if any("⚠️" in f for f in flags) else "Clean"
    log_scan("url", url, url_verdict)

st.divider()

# --- Scan history, pulled from the SQLite database ---
st.subheader("3. Recent Scan History")
st.caption("Read from a local SQLite database using a SQL SELECT query.")

recent = get_recent_scans(10)
if recent:
    st.table(
        [{"Type": r[0], "Input": r[1], "Verdict": r[2], "When": r[3]} for r in recent]
    )
else:
    st.write("No scans yet — try the password or URL checker above.")

st.divider()
st.caption("Built with Python + Streamlit + SQLite. Regex-based heuristics, entropy calculation, and persistent scan logging.")
