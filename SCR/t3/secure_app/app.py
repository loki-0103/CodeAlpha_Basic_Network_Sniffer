"""
Secure Application - Main Flask Application
============================================
HARDENED PRODUCTION-READY IMPLEMENTATION:
- CWE-798 Remediation: Environment variables for SECRET_KEY (Bandit B105 Clean)
- CWE-489 Remediation: Flask debug mode disabled (Bandit B201 Clean)
- CWE-89 Remediation: Parameterized SQL queries via database.py (Bandit B608 Clean)
- CWE-256 Remediation: Werkzeug cryptographic password hashing
- CWE-20 Remediation: Strict input validation for username and password complexity
- CWE-209 Remediation: Safe error handling with custom 404/500 handlers & logging
- CWE-614 / CWE-1004 Remediation: Secure session cookie flags (HttpOnly, SameSite=Lax)
- Session Fixation defense: session.clear() on login
"""

import os
import re
import sys
import secrets
import logging
from pathlib import Path
from datetime import timedelta
from functools import wraps

# Ensure local module directory is in sys.path for direct execution or root execution
current_dir = Path(__file__).resolve().parent
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))

from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from dotenv import load_dotenv

try:
    from secure_app import database
except (ImportError, ModuleNotFoundError):
    import database

# ==============================================================================
# ENVIRONMENT CONFIGURATION & SECRET MANAGEMENT (CWE-798 Remediation)
# ==============================================================================
# Load environment variables from .env if present
load_dotenv()

app = Flask(__name__)

# Configure server-side logging (Never log passwords or sensitive tokens)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger(__name__)

# Secure secret key handling:
# Retrieves from environment variable; generates a secure 256-bit fallback if absent
env_secret = os.environ.get('SECRET_KEY')
if env_secret and len(env_secret) >= 32:
    app.config['SECRET_KEY'] = env_secret
else:
    # Ephemeral cryptographically random key for local development
    app.config['SECRET_KEY'] = secrets.token_hex(32)
    logger.warning("No production SECRET_KEY set in environment! Generated ephemeral random secret key.")

# ==============================================================================
# HARDENED SESSION COOKIE SECURITY CONFIGURATION (CWE-614 / CWE-1004 Remediation)
# ==============================================================================
# Prevent JavaScript from reading the session cookie (Mitigates XSS cookie theft)
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Enforce SameSite to mitigate Cross-Site Request Forgery (CSRF)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Set Secure flag (Enforce over HTTPS in production)
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'False').lower() in ('true', '1')

# Restrict session lifetime to 30 minutes
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Initialize the SQLite database with hardened schema and hashed seeds
with app.app_context():
    database.init_db()


# ==============================================================================
# INPUT VALIDATION HELPERS (CWE-20 Remediation)
# ==============================================================================
def validate_username(username: str) -> tuple[bool, str]:
    """
    Validates username format and length:
    - Must be between 3 and 30 characters
    - Must contain only alphanumeric characters and underscores
    """
    if not username or not isinstance(username, str):
        return False, "Username is required."
    
    username = username.strip()
    if len(username) < 3 or len(username) > 30:
        return False, "Username must be between 3 and 30 characters."
    
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username may only contain letters, numbers, and underscores."
    
    return True, ""


def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Enforces strong password policy:
    - Minimum 8 characters, maximum 128 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if not password or not isinstance(password, str):
        return False, "Password is required."
    
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    
    if len(password) > 128:
        return False, "Password cannot exceed 128 characters."
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must include at least one uppercase letter (A-Z)."
    
    if not re.search(r'[a-z]', password):
        return False, "Password must include at least one lowercase letter (a-z)."
    
    if not re.search(r'[0-9]', password):
        return False, "Password must include at least one number (0-9)."
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>_~`\-+=]', password):
        return False, "Password must include at least one special character (e.g., !@#$%^&*)."
    
    return True, ""


# ==============================================================================
# ACCESS CONTROL / AUTHENTICATION DECORATOR
# ==============================================================================
def login_required(f):
    """Decorator to enforce session authentication on protected routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash("Authentication required. Please sign in to proceed.", 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


# ==============================================================================
# ROUTES
# ==============================================================================
@app.route('/')
def index():
    """Public landing page."""
    user = session.get('user')
    return render_template('index.html', user=user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Hardened login endpoint:
    - Validates inputs before processing
    - Uses constant-time password hash verification
    - Uses session.clear() to prevent Session Fixation
    - Generic error messages prevent username enumeration
    """
    if request.method == 'POST':
        raw_username = request.form.get('username', '')
        raw_password = request.form.get('password', '')

        # Basic input check
        is_valid_user, user_err = validate_username(raw_username)
        if not is_valid_user:
            flash(user_err, 'danger')
            return render_template('login.html'), 400

        if not raw_password:
            flash("Password cannot be blank.", 'danger')
            return render_template('login.html'), 400

        try:
            # Safe authentication via parameterized queries and PBKDF2 hash checking
            user = database.authenticate_user(raw_username.strip(), raw_password)
            
            if user:
                # DEFENSE: Session Fixation Mitigation
                # Clear any pre-existing unauthenticated session tokens
                session.clear()
                
                # Regenerate session data
                session.permanent = True
                session['user'] = {
                    'id': user['id'],
                    'username': user['username'],
                    'role': user['role']
                }
                logger.info(f"Successful login for user: {user['username']}")
                flash(f"Welcome, {user['username']}! Authenticated successfully.", 'success')
                return redirect(url_for('dashboard'))
            else:
                # Safe generic response: Does not reveal whether username exists or password failed
                logger.warning(f"Failed login attempt for username: {raw_username}")
                flash("Invalid username or password.", 'danger')
        except Exception as e:
            # REMEDIATION (CWE-209): Never disclose internal error details to users
            logger.error(f"Unexpected database exception during login: {str(e)}", exc_info=True)
            flash("An unexpected error occurred. Please try again later.", 'danger')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Hardened registration endpoint:
    - Enforces input character and length restrictions
    - Enforces strict password complexity requirements
    - Hashes passwords using Werkzeug PBKDF2
    - Parameterized SQL INSERT avoids SQL Injection
    """
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Validate username
        is_valid_user, user_err = validate_username(username)
        if not is_valid_user:
            flash(user_err, 'danger')
            return render_template('register.html'), 400

        # Validate password strength
        is_valid_pass, pass_err = validate_password_strength(password)
        if not is_valid_pass:
            flash(pass_err, 'danger')
            return render_template('register.html'), 400

        # Verify confirmation match
        if password != confirm_password:
            flash("Passwords do not match. Please verify your entries.", 'danger')
            return render_template('register.html'), 400

        # Check for existing user
        try:
            existing_user = database.find_user_by_username(username)
            if existing_user:
                flash("Username is already taken. Please choose another.", 'warning')
                return render_template('register.html'), 409

            # Register with hashed password
            database.register_user(username, password)
            logger.info(f"New user registered securely: {username}")
            flash("Registration successful! You may now sign in with your credentials.", 'success')
            return redirect(url_for('login'))
        except Exception as e:
            logger.error(f"Error during registration: {str(e)}", exc_info=True)
            flash("Unable to complete registration at this time. Please try again later.", 'danger')

    return render_template('register.html')


@app.route('/dashboard')
@login_required
def dashboard():
    """
    Protected dashboard requiring valid session authentication.
    Demonstrates secure storage of password hashes.
    """
    user = session['user']
    # Safely retrieve user records showing hashed passwords
    all_users = database.get_all_users()
    return render_template('dashboard.html', user=user, all_users=all_users)


@app.route('/logout')
def logout():
    """Safely terminates session by clearing all tokens."""
    username = session.get('user', {}).get('username', 'Anonymous')
    session.clear()
    logger.info(f"User logged out: {username}")
    flash("You have been signed out securely.", 'info')
    return redirect(url_for('login'))


# ==============================================================================
# ERROR HANDLERS (CWE-209 Remediation: Safe Error Handling)
# ==============================================================================
@app.errorhandler(404)
def not_found_error(error):
    return render_template('base.html', custom_message="404 - Page Not Found"), 404


@app.errorhandler(500)
def internal_error(error):
    # Log internal details safely on server
    logger.error(f"Internal Server Error: {error}")
    # Return generic, sanitized page to the client
    return render_template('base.html', custom_message="500 - An unexpected internal server error occurred."), 500


if __name__ == '__main__':
    # ==============================================================================
    # CWE-489 REMEDIATION: Flask Debug Mode Disabled
    # Bandit B201 Clean: debug=False is explicitly enforced.
    # ==============================================================================
    port = int(os.getenv('PORT', 5001))
    host = os.getenv('HOST', '127.0.0.1')
    
    print(f"[OK] RUNNING SECURE APPLICATION ON http://{host}:{port} (DEBUG=FALSE)")
    app.run(host=host, port=port, debug=False)
