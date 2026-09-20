"""
Vulnerable Application - Main Flask Application
==============================================
ACADEMIC DEMO ONLY - CONTAINS DELIBERATE VULNERABILITIES FOR CODE REVIEW:
- CWE-798: Hardcoded secret key and administrative password (Bandit B105)
- CWE-489: Flask debug mode enabled in production (Bandit B201)
- CWE-20: Missing input validation and sanitization
- CWE-209: Verbose error handling leaking system exception details
- CWE-614 / CWE-1004: Insecure session cookie configuration (HttpOnly disabled)
"""

import os
import sys
from pathlib import Path

# Ensure local module directory is in sys.path for direct execution or root execution
current_dir = Path(__file__).resolve().parent
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))

from flask import Flask, render_template, request, redirect, url_for, session, flash

try:
    from vulnerable_app import database
except (ImportError, ModuleNotFoundError):
    import database

app = Flask(__name__)

# ==============================================================================
# VULNERABILITY 2 & 7: Hardcoded Secret Key & Insecure Session Configuration
# CWE-798 (Bandit B105) & CWE-1004
# ==============================================================================
# Insecure: Secret key is static, publicly visible in source control, and predictable.
app.config['SECRET_KEY'] = "hardcoded_insecure_flask_secret_key_12345"

# Insecure: Disabling HttpOnly allows JavaScript (XSS attacks) to read the session cookie!
app.config['SESSION_COOKIE_HTTPONLY'] = False
# Insecure: No SameSite restriction makes app susceptible to CSRF.
app.config['SESSION_COOKIE_SAMESITE'] = None
# Insecure: Secure flag disabled even if served over TLS.
app.config['SESSION_COOKIE_SECURE'] = False

# VULNERABILITY 2: Hardcoded administrative backdoor password (CWE-798 / Bandit B105)
DEFAULT_ADMIN_PASSWORD = "HardcodedSuperAdminPassword2026!"


# Initialize the SQLite database on launch
with app.app_context():
    database.init_db()


@app.route('/')
def index():
    """Public landing page."""
    user = session.get('user')
    return render_template('index.html', user=user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Login endpoint with multiple vulnerabilities:
    - CWE-89: Calls SQL-injection prone database.authenticate_user()
    - CWE-20: No input validation (length, type, character restrictions)
    - CWE-209: Leaks raw database exception in response on query failure
    """
    if request.method == 'POST':
        # VULNERABILITY 4: Missing input validation - accepted directly without sanitation or length checks
        username = request.form.get('username')
        password = request.form.get('password')

        # Backdoor check using hardcoded password (CWE-798)
        if username == 'superuser' and password == DEFAULT_ADMIN_PASSWORD:
            session['user'] = {'username': 'superuser', 'role': 'superuser'}
            flash('Logged in via Emergency Hardcoded Backdoor Credentials!', 'warning')
            return redirect(url_for('dashboard'))

        try:
            # VULNERABILITY 1: Invokes unsafe SQL query containing raw user strings
            user = database.authenticate_user(username, password)
            
            if user:
                # Store user in session dictionary
                session['user'] = {
                    'id': user['id'],
                    'username': user['username'],
                    'role': user['role']
                }
                flash(f"Welcome back, {user['username']}!", 'success')
                return redirect(url_for('dashboard'))
            else:
                flash("Invalid username or password.", 'danger')
        except Exception as e:
            # VULNERABILITY 6: Information Disclosure / Verbose Error Handling (CWE-209)
            # Exposing raw internal database error messages to the client
            return f"""
            <div style="font-family: sans-serif; padding: 2rem; background: #fee2e2; border: 2px solid #ef4444; border-radius: 8px; margin: 2rem;">
                <h2 style="color: #b91c1c;">[Academic Security Demonstration] Server Exception Details Leaked:</h2>
                <p><strong>CWE-209 Information Disclosure:</strong></p>
                <pre style="background: #1e293b; color: #f87171; padding: 1rem; border-radius: 4px; overflow-x: auto;">{str(e)}</pre>
                <p><em>Notice how SQLite syntax errors disclose internal query structure to attackers.</em></p>
                <a href="/login">&larr; Return to Login</a>
            </div>
            """, 500

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Registration endpoint:
    - CWE-89: SQL Injection through registration query
    - CWE-256: Plain text password storage
    - CWE-20: Missing input validation (accepts empty passwords, unrestricted characters)
    - CWE-209: Raw exception disclosure
    """
    if request.method == 'POST':
        # VULNERABILITY 4: Missing input validation
        username = request.form.get('username')
        password = request.form.get('password')

        # Note: No checks for minimum password length, complexity, or character safety
        try:
            database.register_user(username, password)
            flash("Account registered successfully! You can now log in.", 'success')
            return redirect(url_for('login'))
        except Exception as e:
            # VULNERABILITY 6: Leaking raw DB error (e.g. SQLite UNIQUE constraint or syntax error)
            return f"""
            <div style="font-family: sans-serif; padding: 2rem; background: #fee2e2; border: 2px solid #ef4444; border-radius: 8px; margin: 2rem;">
                <h2 style="color: #b91c1c;">[Academic Security Demonstration] Registration Database Error Leaked:</h2>
                <pre style="background: #1e293b; color: #f87171; padding: 1rem; border-radius: 4px; overflow-x: auto;">{str(e)}</pre>
                <a href="/register">&larr; Return to Register</a>
            </div>
            """, 500

    return render_template('register.html')


@app.route('/dashboard')
def dashboard():
    """
    Protected dashboard.
    Insecure implementation: Minimal role verification, discloses full user table for academic analysis.
    """
    user = session.get('user')
    if not user:
        flash("You must be logged in to access the dashboard.", 'warning')
        return redirect(url_for('login'))

    # Display database table contents to demonstrate plaintext storage in classroom demos
    all_users = database.get_all_users()
    return render_template('dashboard.html', user=user, all_users=all_users)


@app.route('/logout')
def logout():
    """Log out user by popping the session."""
    session.pop('user', None)
    flash("You have been logged out.", 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    # ==============================================================================
    # VULNERABILITY 5: Flask Debug Mode Enabled in Production (CWE-489 / Bandit B201)
    # ==============================================================================
    # Insecure: Running with debug=True enables the interactive Werkzeug debugger,
    # which allows arbitrary remote code execution via PIN bypass or unhandled crashes.
    print("[!] RUNNING VULNERABLE APPLICATION ON http://127.0.0.1:5000 (DEBUG=TRUE)")
    app.run(host='127.0.0.1', port=5000, debug=True)
