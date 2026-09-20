# Secure Coding Review of a Python Flask Login Application
### Academic Cybersecurity Project — Task 3: Secure Coding Review & Static Analysis

[![Python 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![Flask 3.1](https://img.shields.io/badge/Flask-3.1-black.svg)](https://palletsprojects.com/p/flask/)
[![Bandit 1.9](https://img.shields.io/badge/Security-Bandit%20SAST-green.svg)](https://bandit.readthedocs.io/)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Compliant-orange.svg)](https://owasp.org/)

---

## 📖 Project Overview

This cybersecurity laboratory project contrasts an **intentionally vulnerable** Python Flask authentication system against a **hardened, remediated** version following OWASP secure coding principles. It demonstrates both automated Static Application Security Testing (SAST) using **Bandit** and comprehensive **manual source code review**.

- **Vulnerable Application (`vulnerable_app/`)**: Runs on `http://127.0.0.1:5000` and contains 7 deliberate, realistic vulnerabilities (SQL injection, plaintext passwords, hardcoded credentials, debug mode, missing validation, information disclosure, insecure cookies).
- **Secure Application (`secure_app/`)**: Runs on `http://127.0.0.1:5001` and implements complete defense-in-depth mitigations (parameterized queries, Werkzeug PBKDF2:SHA256 password hashing, environment variable secrets, strict input validation, safe logging, debug disabled, secure cookie attributes).
- **Security Review Report (`SECURITY_REVIEW.md`)**: Complete 15-section academic report with CWE/OWASP classifications, code diffs, and Bandit scan outputs.

---

## 📁 Project Directory Structure

```text
secure-coding-review/
├── vulnerable_app/                 # Intentionally insecure baseline (Port 5000)
│   ├── app.py                      # Flask routes with deliberate flaws
│   ├── database.py                 # Insecure SQLite handler (f-string queries & plaintext)
│   ├── vulnerable.db               # SQLite database file (auto-created on startup)
│   ├── templates/                  # Insecure application templates
│   │   ├── base.html               # Base layout with warning banner
│   │   ├── index.html              # Landing page
│   │   ├── login.html              # Login endpoint
│   │   ├── register.html           # Registration endpoint
│   │   └── dashboard.html          # Plaintext credential inspection dashboard
│   └── static/
│       └── style.css               # Modern UI with red alert theme
├── secure_app/                     # Hardened remediated system (Port 5001)
│   ├── app.py                      # Hardened Flask routes & input validation
│   ├── database.py                 # Parameterized queries & PBKDF2 hashing
│   ├── secure.db                   # Hardened SQLite database (auto-created on startup)
│   ├── .env                        # Local environment secrets configuration
│   ├── templates/                  # Hardened application templates
│   │   ├── base.html               # Base layout with security badge
│   │   ├── index.html              # Overview of security features
│   │   ├── login.html              # Hardened login endpoint
│   │   ├── register.html           # Hardened registration with password complexity
│   │   └── dashboard.html          # Protected dashboard showing password hashes
│   └── static/
│       └── style.css               # Modern UI with emerald security theme
├── screenshots/                    # Submission screenshot guides
│   └── README.md
├── test_apps.py                    # Automated test and verification suite
├── requirements.txt                # Python package dependencies
├── .env.example                    # Environment variable template
├── .bandit                         # Bandit static analyzer configuration
├── README.md                       # Setup and execution guide (this file)
└── SECURITY_REVIEW.md              # 15-section academic security review report
```

---

## ⚙️ Setup Instructions for Windows

### 1. Prerequisites
Ensure you have **Python 3.10+** installed on your Windows system. Verify via PowerShell or Command Prompt:

```powershell
python --version
```

### 2. Open Project Folder
Open PowerShell or CMD in the project root directory:

```powershell
cd c:\Users\HP\Documents\t3
```

### 3. Create and Activate a Virtual Environment (Recommended)

**Using PowerShell:**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

*(If PowerShell script execution is restricted, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first).*

**Using Command Prompt (CMD):**
```cmd
python -m venv .venv
.venv\Scripts\activate.bat
```

### 4. Install Dependencies
Install all required packages using `requirements.txt`:

```powershell
pip install -r requirements.txt
```

*(Or install directly)*:
```powershell
pip install flask werkzeug python-dotenv bandit
```

---

## 🚀 How to Run the Applications

Both applications can run concurrently because they listen on separate ports.

### Option A: Run the Vulnerable Application (Port 5000)

Open a terminal and run:

```powershell
python vulnerable_app/app.py
```

- Open your browser and navigate to: **`http://127.0.0.1:5000`**
- Notice the **Red Warning Banner** indicating an insecure educational build.
- **Pre-seeded Accounts**:
  - Username: `alice` | Password: `password123`
  - Username: `admin` | Password: `admin123`
  - Backdoor: `superuser` | Password: `HardcodedSuperAdminPassword2026!`

---

### Option B: Run the Secure Application (Port 5001)

Open a second terminal and run:

```powershell
python secure_app/app.py
```

- Open your browser and navigate to: **`http://127.0.0.1:5001`**
- Notice the **Emerald Security Banner** indicating a hardened system.
- **Pre-seeded Accounts**:
  - Username: `alice` | Password: `Alice@Password2026!`
  - Username: `admin` | Password: `Admin@StrongSecret2026!`

---

## 🔍 How to Run Bandit Static Analysis

Bandit scans Python code by parsing AST nodes for security risks.

### 1. Scan the Entire Project
```powershell
bandit -r .
```

### 2. Scan the Vulnerable Application Only
```powershell
bandit -r vulnerable_app/
```
**Expected Output**: 6 issues detected (1 High, 3 Medium, 2 Low):
- `B105`: Hardcoded secret key and backdoor password string
- `B201`: Flask debug mode enabled (`debug=True`)
- `B608`: SQL injection vector through string construction (3 occurrences)

### 3. Scan the Remediated Secure Application Only
```powershell
bandit -r secure_app/
```
**Expected Output**: `No issues identified.` (0 High, 0 Medium, 0 Low, 100% clean scan).

### 4. Export Bandit Scan Reports to HTML or Text
```powershell
# Export vulnerable report to text file
bandit -r vulnerable_app/ -o bandit_vulnerable_report.txt -f txt

# Export secure report to text file
bandit -r secure_app/ -o bandit_secure_report.txt -f txt
```

---

## 🧪 Automated Verification Suite

An automated end-to-end verification script is included to test both applications, their database stores, and security controls programmatically:

```powershell
python test_apps.py
```

### What `test_apps.py` Verifies:
1. **Plaintext Password Storage in Vulnerable App**: Registers a user and inspects `vulnerable.db` to confirm plaintext password persistence (CWE-256).
2. **Vulnerable Login & Dashboard Flow**: Verifies authentication and table rendering.
3. **Input Validation Enforcement in Secure App**: Submits weak passwords and illegal characters to verify rejection (CWE-20).
4. **PBKDF2 Password Hashing in Secure App**: Registers a user and inspects `secure.db` to confirm salted `pbkdf2:sha256` storage.
5. **Access Control & Session Protection**: Asserts that unauthenticated requests to `/dashboard` are redirected to `/login` via `@login_required`.

---

## 🛡️ Step-by-Step Vulnerability Remediation Guide

| Finding ID | Vulnerability | Location | Vulnerable Code | Secure Fix |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-VULN-01** | SQL Injection | `database.py` | `f"SELECT * FROM users WHERE username = '{u}'"` | `cursor.execute("SELECT * FROM users WHERE username = ?", (u,))` |
| **SEC-VULN-02** | Hardcoded Secret Key | `app.py` | `app.config['SECRET_KEY'] = "hardcoded_123"` | `app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')` |
| **SEC-VULN-03** | Plaintext Passwords | `database.py` | `INSERT INTO users (password) VALUES ('pass')` | `generate_password_hash(pass, method='pbkdf2:sha256')` |
| **SEC-VULN-04** | Missing Validation | `app.py` | Direct assignment from `request.form` | Regex validation + password complexity check |
| **SEC-VULN-05** | Debug Mode Enabled | `app.py` | `app.run(debug=True)` | `app.run(debug=False)` |
| **SEC-VULN-06** | Verbose Error Disclosure | `app.py` | `except Exception as e: return str(e)` | Generic messages shown to client; logged server-side |
| **SEC-VULN-07** | Insecure Session Cookies | `app.py` | `SESSION_COOKIE_HTTPONLY = False` | `SESSION_COOKIE_HTTPONLY = True`, `SameSite = 'Lax'` |

---

## 📑 Security Review Report Summary

For detailed academic discussion, comprehensive CVSS/CWE mapping, methodology, side-by-side code diffs, and full Bandit terminal reproductions, please consult:

👉 **[`SECURITY_REVIEW.md`](SECURITY_REVIEW.md)**

---

## 🎓 Academic Submission Checklist

- [x] Functional vulnerable Flask application on port 5000 (`vulnerable_app/`)
- [x] Functional hardened Flask application on port 5001 (`secure_app/`)
- [x] 7 deliberate, realistic vulnerabilities documented
- [x] All 7 vulnerabilities fully remediated
- [x] Bandit static analyzer configured (`.bandit`)
- [x] Bandit verified on vulnerable app (6 issues) vs secure app (0 issues)
- [x] Complete 15-section academic report (`SECURITY_REVIEW.md`)
- [x] Automated test suite (`test_apps.py`)
- [x] Windows PowerShell & CMD setup instructions
- [x] Clean, well-commented, beginner-friendly code
