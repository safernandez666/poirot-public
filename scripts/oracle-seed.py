#!/usr/bin/env python3
"""
Oracle XE demo seed for Poirot DSPM.

Creates tables with synthetic sensitive data (credit cards, SSNs, AWS keys, etc.)
in the POIROT schema so the Oracle scanner can detect them.

Run via Docker:  docker compose --profile oracle up -d
"""

import os
import random
import sys
import time

# ─── Config ──────────────────────────────────────────────────────────────────

ORACLE_HOST     = os.environ.get("ORACLE_HOST", "oracle-xe")
ORACLE_PORT     = int(os.environ.get("ORACLE_PORT", 1521))
ORACLE_SERVICE  = os.environ.get("ORACLE_SERVICE", "XEPDB1")
ORACLE_USER     = os.environ.get("ORACLE_USER", "poirot")
ORACLE_PASSWORD = os.environ.get("ORACLE_PASSWORD", "PoirotScan1")

# ─── Synthetic data generators ───────────────────────────────────────────────

def _cc():
    return f"4{random.randint(100,999)}-{random.randint(1000,9999)}-{random.randint(1000,9999)}-{random.randint(1000,9999)}"

def _email():
    names   = ["alice", "bob", "carol", "dave", "eve", "frank", "grace", "henry"]
    domains = ["example.com", "test.org", "demo.net", "company.io"]
    return f"{random.choice(names)}{random.randint(1,99)}@{random.choice(domains)}"

def _ssn():
    return f"{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}"

def _phone():
    return f"+1-{random.randint(200,999)}-{random.randint(100,999)}-{random.randint(1000,9999)}"

def _iban():
    return f"GB{random.randint(10,99)}BARC{random.randint(10000000,99999999):08d}{random.randint(10000000,99999999):08d}"

def _aws_key():
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "AKIA" + "".join(random.choices(chars, k=16))

def _aws_secret():
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
    return "".join(random.choices(chars, k=40))

def _password():
    return random.choice(["hunter2", "P@ssw0rd!", "SecretABC123", "Tr0ub4dor&3", "correct-horse"])

def _private_key():
    return "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7\n-----END RSA PRIVATE KEY-----"

def _jwt():
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

def _bitcoin():
    return random.choice(["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"])

# ─── Wait for Oracle ─────────────────────────────────────────────────────────

def wait_for_oracle(retries=40, delay=5):
    import oracledb
    print(f"[oracle] Waiting for {ORACLE_HOST}:{ORACLE_PORT}/{ORACLE_SERVICE}...")
    for attempt in range(1, retries + 1):
        try:
            dsn = oracledb.makedsn(ORACLE_HOST, ORACLE_PORT, service_name=ORACLE_SERVICE)
            conn = oracledb.connect(user=ORACLE_USER, password=ORACLE_PASSWORD, dsn=dsn)
            conn.close()
            print(f"[oracle] Ready after {attempt} attempt(s)")
            return True
        except Exception as e:
            print(f"[oracle] Attempt {attempt}/{retries}: {e}")
            time.sleep(delay)
    return False

# ─── Seed Oracle ─────────────────────────────────────────────────────────────

def setup_oracle():
    import oracledb
    print("[oracle] Seeding demo data...")

    dsn = oracledb.makedsn(ORACLE_HOST, ORACLE_PORT, service_name=ORACLE_SERVICE)
    conn = oracledb.connect(user=ORACLE_USER, password=ORACLE_PASSWORD, dsn=dsn)
    cur = conn.cursor()

    # ── Create tables ────────────────────────────────────────────────────
    tables = {
        "CUSTOMERS": """
            CREATE TABLE customers (
                id NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                name VARCHAR2(255),
                email VARCHAR2(255),
                phone VARCHAR2(50),
                ssn VARCHAR2(20),
                card_number VARCHAR2(50),
                api_key VARCHAR2(255),
                notes VARCHAR2(500)
            )
        """,
        "PAYMENTS": """
            CREATE TABLE payments (
                id NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                customer_id NUMBER,
                card_number VARCHAR2(50),
                iban VARCHAR2(60),
                amount NUMBER(10,2)
            )
        """,
        "EMPLOYEES": """
            CREATE TABLE employees (
                id NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                full_name VARCHAR2(255),
                email VARCHAR2(255),
                ssn VARCHAR2(20),
                password VARCHAR2(255),
                aws_access_key VARCHAR2(100),
                aws_secret_key VARCHAR2(255)
            )
        """,
        "SERVERS": """
            CREATE TABLE servers (
                id NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                hostname VARCHAR2(255),
                private_ip VARCHAR2(50),
                ssh_key CLOB,
                jwt_token CLOB
            )
        """,
    }

    for table_name, ddl in tables.items():
        try:
            cur.execute(ddl)
            print(f"[oracle]   Created table {table_name}")
        except oracledb.DatabaseError as e:
            if "ORA-00955" in str(e):  # table already exists
                print(f"[oracle]   Table {table_name} already exists")
            else:
                raise

    # ── Check if already seeded ──────────────────────────────────────────
    cur.execute("SELECT COUNT(*) FROM customers")
    if cur.fetchone()[0] > 0:
        print("[oracle] Already seeded, skipping.")
        conn.close()
        return

    # ── Insert synthetic data ────────────────────────────────────────────
    print("[oracle] Inserting 20 rows per table...")

    for i in range(20):
        cur.execute(
            "INSERT INTO customers (name, email, phone, ssn, card_number, api_key, notes) "
            "VALUES (:1, :2, :3, :4, :5, :6, :7)",
            (f"Customer {i}", _email(), _phone(), _ssn(), _cc(), _aws_key(), _bitcoin())
        )
        cur.execute(
            "INSERT INTO payments (customer_id, card_number, iban, amount) "
            "VALUES (:1, :2, :3, :4)",
            (i + 1, _cc(), _iban(), round(random.uniform(10, 1000), 2))
        )
        cur.execute(
            "INSERT INTO employees (full_name, email, ssn, password, aws_access_key, aws_secret_key) "
            "VALUES (:1, :2, :3, :4, :5, :6)",
            (f"Employee {i}", _email(), _ssn(), _password(), _aws_key(), _aws_secret())
        )
        cur.execute(
            "INSERT INTO servers (hostname, private_ip, ssh_key, jwt_token) "
            "VALUES (:1, :2, :3, :4)",
            (f"srv-{i:02d}.oracle.internal", f"10.0.{random.randint(1,254)}.{random.randint(2,254)}", _private_key(), _jwt())
        )

    conn.commit()
    conn.close()

    print("[oracle] Done! 4 tables × 20 rows = 80 records with synthetic sensitive data")
    print("[oracle] Tables: CUSTOMERS, PAYMENTS, EMPLOYEES, SERVERS")
    print("[oracle] Data types: credit cards, SSNs, AWS keys, passwords, SSH keys, JWTs, IBANs, Bitcoin addresses")

# ─── Main ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  Poirot DSPM — Oracle XE Demo Seed")
    print("=" * 60)

    if not wait_for_oracle():
        print("[oracle] FATAL: Could not connect to Oracle XE after retries")
        sys.exit(1)

    setup_oracle()
    print("\n[oracle] Seed complete! Configure in Poirot:")
    print(f'  SOURCE_ORACLE_DEMO={{"host":"oracle-xe","port":1521,"service_name":"XEPDB1","user":"{ORACLE_USER}","password":"{ORACLE_PASSWORD}"}}')
