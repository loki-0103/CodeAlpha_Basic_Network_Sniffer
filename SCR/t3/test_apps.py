"""
Automated Verification Suite
============================
Tests functional integrity, authentication flows, database representations,
and security controls of both vulnerable and secure Flask applications.
"""

import os
import sys
import sqlite3
from werkzeug.security import check_password_hash

# Set working paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from vulnerable_app.app import app as vuln_app
from secure_app.app import app as sec_app
import vulnerable_app.database as vuln_db
import secure_app.database as sec_db


def test_vulnerable_app():
    print("\n--- Testing Vulnerable Application ---")
    client = vuln_app.test_client()

    import time
    ts = int(time.time())
    bob_user = f"bob_{ts}"

    # Test 1: Register a new user
    res = client.post('/register', data={'username': bob_user, 'password': 'bobpassword'}, follow_redirects=True)
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    print(f"[OK] Vulnerable registration succeeded for {bob_user}.")

    # Test 2: Check database directly to confirm PLAINTEXT password storage (CWE-256)
    conn = sqlite3.connect(os.path.join(BASE_DIR, 'vulnerable_app', 'vulnerable.db'))
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM users WHERE username = ?", (bob_user,)).fetchone()
    conn.close()
    assert row is not None, f"User {bob_user} was not found in DB!"
    assert row['password'] == 'bobpassword', f"Expected plaintext 'bobpassword', got {row['password']}"
    print(f"[OK] CONFIRMED VULNERABILITY (CWE-256): User '{bob_user}' password stored as plaintext: '{row['password']}'")

    # Test 3: Log in as bob
    res = client.post('/login', data={'username': bob_user, 'password': 'bobpassword'}, follow_redirects=True)
    assert f"Welcome back, {bob_user}!".encode() in res.data, "Login flash message missing"
    assert b"Plaintext Database Contents" in res.data, "Dashboard failed to render"
    print("[OK] Vulnerable login and dashboard flow confirmed.")


def test_secure_app():
    print("\n--- Testing Secure Application ---")
    client = sec_app.test_client()

    import time
    ts = int(time.time())
    charlie_user = f"charlie_{ts}"

    # Test 1: Register with weak password (Must FAIL - CWE-20 input validation)
    res = client.post('/register', data={
        'username': charlie_user,
        'password': '123',
        'confirm_password': '123'
    }, follow_redirects=True)
    assert res.status_code == 400 or b"Password must be at least 8 characters" in res.data, "Weak password was unexpectedly accepted!"
    print("[OK] CONFIRMED REMEDIATION (CWE-20): Weak password rejected by complexity policy.")

    # Test 2: Register with invalid username (characters not allowed)
    res = client.post('/register', data={
        'username': 'user<script>',
        'password': 'ComplexPassword2026!',
        'confirm_password': 'ComplexPassword2026!'
    }, follow_redirects=True)
    assert res.status_code == 400 or b"Username may only contain" in res.data, "Invalid username was unexpectedly accepted!"
    print("[OK] CONFIRMED REMEDIATION (CWE-20): Invalid username characters rejected.")

    # Test 3: Register with valid strong credentials
    res = client.post('/register', data={
        'username': charlie_user,
        'password': 'ComplexPassword2026!',
        'confirm_password': 'ComplexPassword2026!'
    }, follow_redirects=True)
    assert res.status_code == 200 and b"Registration successful" in res.data, "Valid registration failed"
    print(f"[OK] Secure registration with strong credentials succeeded for {charlie_user}.")

    # Test 4: Check database directly to confirm HASHED password storage (CWE-256 Remediation)
    conn = sqlite3.connect(os.path.join(BASE_DIR, 'secure_app', 'secure.db'))
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM users WHERE username = ?", (charlie_user,)).fetchone()
    conn.close()
    assert row is not None, f"User {charlie_user} was not found in secure DB!"
    assert row['password_hash'].startswith('pbkdf2:sha256:'), f"Invalid hash format: {row['password_hash']}"
    assert check_password_hash(row['password_hash'], 'ComplexPassword2026!'), "Password hash failed verification!"
    print(f"[OK] CONFIRMED REMEDIATION (CWE-256): User '{charlie_user}' password stored as salted hash: {row['password_hash'][:35]}...")

    # Test 5: Unauthenticated access to /dashboard must redirect to /login
    res = client.get('/dashboard', follow_redirects=False)
    assert res.status_code == 302 and '/login' in res.headers['Location'], "Unauthenticated dashboard access was not redirected!"
    print("[OK] CONFIRMED REMEDIATION: Access control enforced (@login_required protects /dashboard).")

    # Test 6: Authenticate as charlie
    res = client.post('/login', data={'username': charlie_user, 'password': 'ComplexPassword2026!'}, follow_redirects=True)
    assert b"Authenticated successfully" in res.data, "Login failed for charlie"
    assert b"Protected User Dashboard" in res.data, "Dashboard not shown after login"
    print("[OK] Secure authentication and session establishment confirmed.")


if __name__ == '__main__':
    test_vulnerable_app()
    test_secure_app()
    print("\n=======================================================")
    print("ALL AUTOMATED VERIFICATION CHECKS PASSED SUCCESSFULLY!")
    print("=======================================================\n")
