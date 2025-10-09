#!/usr/bin/env python3
"""
quarantine_users.py
- Scans users table for suspicious registrations using hybrid heuristics
- Moves suspicious rows into users_quarantine (keeps original schema + reason)
- Exports CSV for the quarantined rows of this run
- Emails CSV to ADMIN_EMAIL via Zoho SMTP only if new rows were quarantined
- Logs activity to /var/log/quarantine_activity.log
"""

import re
import os
import csv
import math
import ssl
import logging
import unicodedata
import mysql.connector
import smtplib
from email.message import EmailMessage
from datetime import datetime, timezone
from config import get_db_connection

# =========================
# CONFIG - EDIT BEFORE RUN
# =========================
""" DB_CONFIG = {
    "host": "localhost",            # or RDS endpoint
    "user": "your_mysql_user",
    "password": "your_mysql_password",
    "database": "your_database_name",
    "port": 3306
} """

SMTP_SERVER = os.getenv('EMAIL_HOST')
SMTP_PORT = 486      # STARTSSL
SMTP_USER = os.getenv('EMAIL_USER')
SMTP_PASS = os.getenv('EMAIL_PASSWORD')   # use app-specific password
ADMIN_EMAIL = os.getenv('EMAIL_USER')

# File paths - ensure these directories exist and are writable by the user that runs script
REPORT_DIR = "/var/www/stallionroutes/reports"
# LOG_FILE = "/var/log/quarantine_activity.log"
LOG_FILE = "/home/ubuntu/Stallion_Routes/quarantine_activity.log"

# Detection thresholds
ENTROPY_THRESHOLD = 4.0     # above this is likely gibberish
RISK_SCORE_THRESHOLD = 3    # quarantine when score >= threshold

# Patterns (kept broad & generic)
KEYWORD_PATTERNS = [
    r"http[s]?://", r"www\.", r"\.ru\b", r"\.org\b", r"\.xyz\b", r"\bbtc\b",
    r"\bbitcoin\b", r"urgent", r"alert", r"free money", r"accept funds",
    r"graph\.org", r"viagra|porn|sex", r"gift", r"winner", r"claim now"
]

SQL_INJECTION_PATTERN = re.compile(
    r"('|--|;|/\*|\*/|@@|char\(|nchar\(|varchar\(|alter\s|drop\s|insert\s|select\s|delete\s|update\s)",
    re.IGNORECASE
)

HTML_PATTERN = re.compile(r"<.*?>|&lt;.*?&gt;")

# =========================
# Logging setup
# =========================
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

console_logger = logging.getLogger("console")
console_logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
console_logger.addHandler(console_handler)

# =========================
# Utility functions
# =========================
def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    probs = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log(p, 2) for p in probs)

def has_mixed_scripts(s: str) -> bool:
    """Detect if string mixes different Unicode script names (basic heuristic)."""
    scripts = set()
    for ch in s:
        if ch.isalpha():
            try:
                name = unicodedata.name(ch)
            except ValueError:
                continue
            # Take first word of Unicode name (e.g., 'LATIN', 'CYRILLIC', 'GREEK')
            scripts.add(name.split()[0])
    return len(scripts) > 1

def score_text(text: str) -> tuple[int, list]:
    """Return risk score and reasons for a text (combines name, email, phone)."""
    text_l = (text or "").lower()
    reasons = []
    score = 0

    # 1) HTML / tags
    if HTML_PATTERN.search(text_l):
        reasons.append("HTML tags detected")
        score += 2

    # 2) SQL injection-like
    if SQL_INJECTION_PATTERN.search(text_l):
        reasons.append("SQL-like tokens detected")
        score += 2

    # 3) Keyword patterns
    for p in KEYWORD_PATTERNS:
        if re.search(p, text_l):
            reasons.append(f"Keyword match: {p}")
            score += 1
            break

    # 4) High entropy
    ent = shannon_entropy(text_l)
    if ent > ENTROPY_THRESHOLD:
        reasons.append(f"High entropy ({ent:.2f})")
        score += 2

    # 5) Mixed Unicode scripts
    if has_mixed_scripts(text):
        reasons.append("Mixed Unicode scripts")
        score += 1

    # 6) Excessive length
    if len(text_l) > 200:
        reasons.append("Excessive length")
        score += 1

    return score, reasons

# =========================
# Database / Quarantine helpers
# =========================
def ensure_quarantine_table(cursor):
    """Create a quarantine table with same structure as users and add reason/quarantined_at if missing."""
    # Create clone if not exists
    cursor.execute("CREATE TABLE IF NOT EXISTS users_quarantine LIKE users;")
    # Add reason column if not exists
    try:
        cursor.execute("ALTER TABLE users_quarantine ADD COLUMN IF NOT EXISTS reason VARCHAR(255);")
    except mysql.connector.errors.ProgrammingError:
        # Some MySQL versions may not support IF NOT EXISTS for ADD COLUMN - handle gracefully
        # Check if column exists:
        cursor.execute("SHOW COLUMNS FROM users_quarantine LIKE 'reason';")
        if not cursor.fetchall():
            cursor.execute("ALTER TABLE users_quarantine ADD COLUMN reason VARCHAR(255);")
    # Add quarantined_at column if not present
    try:
        cursor.execute("ALTER TABLE users_quarantine ADD COLUMN IF NOT EXISTS quarantined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;")
    except mysql.connector.errors.ProgrammingError:
        cursor.execute("SHOW COLUMNS FROM users_quarantine LIKE 'quarantined_at';")
        if not cursor.fetchall():
            cursor.execute("ALTER TABLE users_quarantine ADD COLUMN quarantined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;")

def export_rows_to_csv(rows, filepath):
    if not rows:
        return
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

def send_email_with_attachment(to_email, subject, body, attachment_path):
    msg = EmailMessage()
    msg["From"] = SMTP_USER
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    with open(attachment_path, "rb") as f:
        data = f.read()
    msg.add_attachment(data, maintype="text", subtype="csv", filename=attachment_path.split("/")[-1])

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls(context=context)
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        logging.info(f"Email sent to {to_email}")
    except Exception as e:
        logging.exception(f"Failed to send email: {e}")
        raise

# =========================
# Main workflow
# =========================
def main():
    start_ts = datetime.now(timezone.utc)   # <-- fixed
    console_logger.info(f"Starting quarantine job at {start_ts.isoformat()}...")
    logging.info("=== Quarantine job started ===")

    # Connect DB
    conn = mysql.connector.connect(**get_db_connection())
    cursor = conn.cursor(dictionary=True)

    try:
        ensure_quarantine_table(cursor)
        conn.commit()
        logging.info("Ensured users_quarantine table exists and has required columns.")

        # Fetch candidate columns (we'll use name,email,phone,id plus all other columns via SELECT)
        cursor.execute("SELECT id, name, email, phone FROM users;")
        users = cursor.fetchall()
        logging.info(f"Fetched {len(users)} users from users table.")

        suspicious_ids = []
        suspicious_rows_for_csv = []

        for u in users:
            combined = " ".join([str(u.get("name") or ""), str(u.get("email") or ""), str(u.get("phone") or "")])
            score, reasons = score_text(combined)
            if score >= RISK_SCORE_THRESHOLD:
                reason_text = "; ".join(reasons) if reasons else "scored"
                suspicious_ids.append(u["id"])
                # We will export some basic fields for CSV; full row added to quarantine table via SQL INSERT ... SELECT later
                suspicious_rows_for_csv.append({
                    "id": u["id"],
                    "name": u.get("name"),
                    "email": u.get("email"),
                    "phone": u.get("phone"),
                    "score": score,
                    "reason": reason_text
                })

        if not suspicious_ids:
            console_logger.info("[✓] No suspicious users detected. No email will be sent.")
            logging.info("No suspicious users detected.")
            return

        console_logger.info(f"[!] {len(suspicious_ids)} suspicious users detected — quarantining now.")
        logging.info(f"Suspicious IDs: {suspicious_ids}")

        # Insert full rows into users_quarantine using INSERT ... SELECT to preserve all columns
        # For each id, insert and delete inside a loop to avoid transaction/pk conflicts
        quarantined_ids = []
        for uid in suspicious_ids:
            # Insert full row + reason
            reason = next((r["reason"] for r in suspicious_rows_for_csv if r["id"] == uid), "suspicious")
            insert_sql = """
                INSERT INTO users_quarantine 
                SELECT u.*, %s AS reason FROM users u WHERE u.id = %s;
            """
            cursor.execute(insert_sql, (reason, uid))
            # Now delete from users
            cursor.execute("DELETE FROM users WHERE id = %s;", (uid,))
            quarantined_ids.append(uid)

        conn.commit()
        logging.info(f"Moved {len(quarantined_ids)} rows to users_quarantine and deleted them from users.")

        # Export CSV for the quarantined rows in this run
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_filename = f"quarantined_users_{timestamp}.csv"
        csv_filepath = f"{REPORT_DIR}/{csv_filename}"

        # Compose full rows for CSV by selecting from users_quarantine for the inserted IDs
        format_ids = ",".join("%s" for _ in quarantined_ids)
        select_sql = f"SELECT * FROM users_quarantine WHERE id IN ({format_ids}) ORDER BY quarantined_at DESC;"
        cursor.execute(select_sql, tuple(quarantined_ids))
        rows_for_csv = cursor.fetchall()
        if not rows_for_csv:
            logging.warning("No rows found in users_quarantine after insert (unexpected).")
        else:
            # ensure report dir exists
            import os
            os.makedirs(REPORT_DIR, exist_ok=True)
            export_rows_to_csv(rows_for_csv, csv_filepath)
            logging.info(f"CSV report written to {csv_filepath}")

        # Send email only if CSV exists and there were quarantined ids
        subject = f"[Security] {len(quarantined_ids)} suspicious user(s) quarantined"
        body = (
            f"Hello Stallion Routes Admin,\n\n"
            f"{len(quarantined_ids)} suspicious user record(s) were quarantined on {datetime.now().isoformat()}.\n"
            "See attached CSV for details.\n\n"
            "Regards,\nStallion Routes Security Bot"
        )

        try:
            send_email_with_attachment(ADMIN_EMAIL, subject, body, csv_filepath)
            logging.info("Email sent successfully with CSV attachment.")
            console_logger.info("[✓] Email sent with CSV attachment.")
        except Exception as e:
            console_logger.error(f"[✗] Failed to send email: {e}")

    except Exception as exc:
        logging.exception(f"Fatal error during quarantine job: {exc}")
        console_logger.error(f"Fatal error: {exc}")
    finally:
        try:
            cursor.close()
            conn.close()
        except Exception:
            pass
        logging.info("=== Quarantine job finished ===")
        console_logger.info("Quarantine job finished.")

if __name__ == "__main__":
    main()
