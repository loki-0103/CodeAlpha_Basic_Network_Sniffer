"""
Vulnerable Application - Database Management Module
===================================================
ACADEMIC DEMO ONLY - CONTAINS DELIBERATE VULNERABILITIES FOR CODE REVIEW:
- CWE-89: Unsafe string formatting leading to SQL Injection (Bandit B608)
- CWE-256 / CWE-312: Passwords stored in plain text (No cryptographic hashing)
- CWE-209: Raw database exception bubbling
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'vulnerable.db')


def get_db_connection():
    """Returns a SQLite connection with row factory configured."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Initializes the SQLite database with a users table.
    VULNERABILITY: 'password' is stored as plain text without any hashing algorithm.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Drop table to ensure clean academic state on rerun if needed
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    ''')
    
    # Seed default user credentials in PLAIN TEXT
    cursor.execute("SELECT COUNT(*) as cnt FROM users WHERE username = 'alice'")
    if cursor.fetchone()['cnt'] == 0:
        # VULNERABILITY (CWE-256): Plaintext credentials inserted into DB
        cursor.execute("INSERT INTO users (username, password, role) VALUES ('alice', 'password123', 'user')")
        cursor.execute("INSERT INTO users (username, password, role) VALUES ('admin', 'admin123', 'admin')")
    
    conn.commit()
    conn.close()


def find_user_by_username(username):
    """
    VULNERABILITY (CWE-89 / Bandit B608):
    Unsafe string interpolation in SQL query instead of parameterized queries.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    # Insecure query construction with f-string:
    query = f"SELECT id, username, password, role FROM users WHERE username = '{username}'"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    return user


def authenticate_user(username, password):
    """
    VULNERABILITY (CWE-89 / Bandit B608):
    Direct f-string SQL query concatenation enables authentication bypass via SQL Injection.
    Example payload: admin' --
    Also checks plain text password against plain text database field (CWE-256).
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Insecure query construction vulnerable to SQL Injection:
    query = f"SELECT id, username, password, role FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    return user


def register_user(username, password, role='user'):
    """
    VULNERABILITY (CWE-89 & CWE-256):
    Inserts unvalidated input using string formatting and stores plaintext password.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Insecure SQL query insertion:
    query = f"INSERT INTO users (username, password, role) VALUES ('{username}', '{password}', '{role}')"
    cursor.execute(query)
    conn.commit()
    conn.close()


def get_all_users():
    """Helper to inspect all users (demonstrates plaintext database contents for review)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password, role FROM users")
    users = cursor.fetchall()
    conn.close()
    return users
