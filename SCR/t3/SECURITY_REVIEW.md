# Academic Security Review Report
## Secure Coding Review of a Python Flask Login Application

**Project / Course:** Cybersecurity Academic Laboratory — Task 3: Secure Coding Review  
**Date:** September 2026  
**Auditor / Author:** Security Research & Academic Review Team  
**Target Systems:**
- Vulnerable Baseline Application (`vulnerable_app/` on port 5000)
- Remediated Hardened Application (`secure_app/` on port 5001)

---

## Table of Contents
1. [Introduction](#1-introduction)
2. [Objective](#2-objective)
3. [Technologies Used](#3-technologies-used)
4. [Application Architecture](#4-application-architecture)
5. [Code Review Methodology](#5-code-review-methodology)
6. [Static Analysis Methodology](#6-static-analysis-methodology)
7. [Vulnerability Findings](#7-vulnerability-findings)
8. [Vulnerability Severity](#8-vulnerability-severity)
9. [Vulnerable Code Explanation](#9-vulnerable-code-explanation)
10. [Remediation for Each Vulnerability](#10-remediation-for-each-vulnerability)
11. [Secure Code Explanation](#11-secure-code-explanation)
12. [Before vs After Comparison](#12-before-vs-after-comparison)
13. [Bandit Scan Results](#13-bandit-scan-results)
14. [Secure Coding Best Practices](#14-secure-coding-best-practices)
15. [Conclusion](#15-conclusion)

---

## 1. Introduction

Web application security is an essential discipline in modern software engineering. Vulnerabilities introduced during development—such as improper input handling, insecure storage of credentials, hardcoded secrets, and unsafe server configurations—account for a large percentage of enterprise data breaches.

This academic project conducts an end-to-end **Secure Coding Review** on a Python Flask-based user authentication and dashboard management system. The project contrasts two architectures:
1. **The Intentionally Vulnerable Application (`vulnerable_app/`)**: Built intentionally with realistic architectural and syntactic vulnerabilities to serve as an audit target.
2. **The Hardened Secure Application (`secure_app/`)**: Re-engineered using industry-standard OWASP defensive engineering practices, parameterized data access, and cryptographic primitives.

By conducting both **manual source code inspection** and **automated static security analysis (SAST)** with Bandit, this report documents how software flaws manifest at the code level, how static analysis tools detect them, and how production-ready mitigations are implemented.

---

## 2. Objective

The primary objectives of this academic security review are:
1. **Construct a Functional Baseline Target**: Develop a working Flask authentication system containing common CWE vulnerabilities (SQL injection, plaintext credentials, debug exposure, poor error handling, missing input validation).
2. **Execute Static Analysis (SAST)**: Run Bandit across the source code tree to identify Abstract Syntax Tree (AST) pattern violations and compile security metrics.
3. **Perform Manual Security Code Review**: Audit high-level logic flaws, cryptographic weaknesses, and cookie configurations that automated linters often overlook.
4. **Engineer Complete Remediations**: Re-architect and patch all identified vulnerabilities using defense-in-depth secure coding principles.
5. **Demonstrate Empirical Verification**: Contrast Bandit scan outputs and functional test suites between the vulnerable and remediated systems to provide reproducible academic proof of security improvements.

---

## 3. Technologies Used

| Technology | Version / Specification | Role in Project |
| :--- | :--- | :--- |
| **Python** | 3.12.x | Runtime execution engine |
| **Flask** | 3.1.x | Lightweight WSGI web framework for routing and templating |
| **SQLite** | 3.x | Embedded relational database management system |
| **Werkzeug** | 3.1.x | Password hashing (`pbkdf2:sha256`) and WSGI utility library |
| **Python-Dotenv**| 1.0.x / 1.2.x | Environment variable management for application secrets |
| **Bandit** | 1.9.4 | Python Abstract Syntax Tree (AST) static security analyzer |
| **HTML5 / CSS3** | Custom Modern CSS | User interface, security badges, and layout presentation |

---

## 4. Application Architecture

Both versions of the application implement a classic three-tier web architecture consisting of Presentation, Application/Business Logic, and Persistence layers:

```
[ Web Browser Client ]
         │ HTTP Requests (GET / POST)
         ▼
[ Flask Application Tier (app.py) ]
  ├── Routing & Controllers (/login, /register, /dashboard, /logout)
  ├── Session Management & Access Control
  └── Error Handling & Logging Subsystem
         │ Python Database API (sqlite3)
         ▼
[ Persistence Tier (database.py) ]
  └── SQLite Relational Store (vulnerable.db / secure.db)
```

### Key Differences in Architecture:

```
VULNERABLE APPLICATION (Port 5000):
┌─────────────────────────┐     Unsafe f-strings       ┌──────────────────────┐
│  vulnerable_app/app.py  │ ─────────────────────────> │   SQLite Database    │
│  - debug=True           │                            │   - Plaintext Passwords
│  - Hardcoded Secret Key │ <───────────────────────── │   - SQL Injection Prone
│  - No Input Validation  │     Raw Exceptions (500)   └──────────────────────┘
└─────────────────────────┘

SECURE APPLICATION (Port 5001):
┌─────────────────────────┐     Parameterized Queries  ┌──────────────────────┐
│   secure_app/app.py     │ ─────────────────────────> │   SQLite Database    │
│  - debug=False          │     (Bound parameters '?') │   - PBKDF2:SHA256 Hashes
│  - Environment Secrets  │                            │   - Injection Free   │
│  - Strict Regex Whitelist <───────────────────────── └──────────────────────┘
│  - HttpOnly/SameSite    │     Sanitized Flash (400)
└─────────────────────────┘
```

---

## 5. Code Review Methodology

The security assessment utilized a hybrid methodology combining **top-down architecture review** and **bottom-up line-by-line manual code inspection**:

1. **Information Architecture & Attack Surface Mapping**:
   - Enumerating endpoints (`/`, `/login`, `/register`, `/dashboard`, `/logout`).
   - Tracing user input sources (`request.form.get('username')`, `request.form.get('password')`) into application sinks (SQL execution, session creation, HTTP responses).
2. **Cryptographic & Credential Audit**:
   - Inspecting how passwords are processed during registration and checked during authentication.
   - Auditing configuration files and source code for embedded secrets, API keys, or fallback accounts.
3. **Session & Transport Management Review**:
   - Inspecting Flask session cookie configuration (`SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SAMESITE`, `SESSION_COOKIE_SECURE`).
   - Checking session termination mechanics upon logout (`session.clear()` vs partial deletion).
4. **Exception & Error Handling Analysis**:
   - Tracing `try / except` blocks to verify whether stack traces, SQL syntax strings, or system paths are leaked to client browsers.

---

## 6. Static Analysis Methodology

Static Application Security Testing (SAST) was performed using **Bandit**, an open-source static security analyzer specifically designed for Python.

### How Bandit Works:
- Bandit parses Python source files into an **Abstract Syntax Tree (AST)**.
- It iterates through AST nodes (FunctionCall, Str, Assign, Import, etc.) and tests them against built-in security plugins.
- Bandit assigns each finding a **Severity** (Low, Medium, High) and a **Confidence** score (Low, Medium, High).

### Static Analysis Configuration (`.bandit`):
```ini
[bandit]
exclude = .git,__pycache__,.venv,venv,env,screenshots
skips = 
```

### Static Analysis Execution Commands:
```bash
# Scan entire workspace
bandit -r .

# Scan specific application targets
bandit -r vulnerable_app/
bandit -r secure_app/
```

---

## 7. Vulnerability Findings

A total of **7 distinct security vulnerabilities** were identified in the vulnerable application through a combination of Bandit static analysis and manual source code auditing:

| Finding ID | Vulnerability Name | CWE ID | OWASP Top 10 | Detection Method | Severity |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SEC-VULN-01** | SQL Injection via String Concatenation | CWE-89 | A03:2021-Injection | Bandit (B608) & Manual | **High** |
| **SEC-VULN-02** | Hardcoded Secret Key & Backdoor Credential | CWE-798 | A07:2021-Identification & Auth | Bandit (B105) & Manual | **High** |
| **SEC-VULN-03** | Plaintext Password Storage | CWE-256 | A02:2021-Cryptographic Failures | Manual Code Review | **High** |
| **SEC-VULN-04** | Missing Input Validation & Sanitization | CWE-20 | A04:2021-Insecure Design | Manual Code Review | **Medium** |
| **SEC-VULN-05** | Flask Debug Mode Enabled in Production | CWE-489 | A05:2021-Security Misconfiguration | Bandit (B201) & Manual | **High** |
| **SEC-VULN-06** | Verbose Error Handling & Information Leakage | CWE-209 | A05:2021-Security Misconfiguration | Manual Code Review | **Medium** |
| **SEC-VULN-07** | Insecure Session Cookie Flags | CWE-1004 | A05:2021-Security Misconfiguration | Manual Code Review | **Medium** |

---

## 8. Vulnerability Severity Matrix

The findings are classified according to the Common Weakness Scoring System (CWSS) and qualitative impact:

```
┌─────────────┬────────────────────────────────────────────────────────┐
│ Severity    │ Vulnerabilities Included                               │
├─────────────┼────────────────────────────────────────────────────────┤
│ HIGH (4)    │ SEC-VULN-01: SQL Injection (CWE-89)                    │
│             │ SEC-VULN-02: Hardcoded Secrets (CWE-798)               │
│             │ SEC-VULN-03: Plaintext Passwords (CWE-256)             │
│             │ SEC-VULN-05: Flask Debug Mode (CWE-489)                │
├─────────────┼────────────────────────────────────────────────────────┤
│ MEDIUM (3)  │ SEC-VULN-04: Missing Input Validation (CWE-20)         │
│             │ SEC-VULN-06: Verbose Error Disclosure (CWE-209)        │
│             │ SEC-VULN-07: Insecure Cookie Flags (CWE-1004 / CWE-614)│
├─────────────┼────────────────────────────────────────────────────────┤
│ LOW (0)     │ None                                                   │
└─────────────┴────────────────────────────────────────────────────────┘
```

---

## 9. Vulnerable Code Explanation

### Finding SEC-VULN-01: SQL Injection via String Concatenation
- **File:** `vulnerable_app/database.py` (Lines 60, 78, 94)
- **Code:**
  ```python
  # Line 78:
  query = f"SELECT id, username, password, role FROM users WHERE username = '{username}' AND password = '{password}'"
  cursor.execute(query)
  ```
- **Why Insecure:** The query is dynamically built using Python f-strings without parameter binding. An attacker supplying input containing single quotes and SQL operators can manipulate the query logic (e.g. `admin' --`), bypassing authentication or extracting data. Bandit flags this under rule **B608**.

### Finding SEC-VULN-02: Hardcoded Secret Key & Backdoor Credential
- **File:** `vulnerable_app/app.py` (Lines 35, 45)
- **Code:**
  ```python
  # Line 35:
  app.config['SECRET_KEY'] = "hardcoded_insecure_flask_secret_key_12345"

  # Line 45:
  DEFAULT_ADMIN_PASSWORD = "HardcodedSuperAdminPassword2026!"
  ```
- **Why Insecure:** Committing cryptographic keys and administrative passwords directly into source code means anyone with repository read access can forge signed session cookies or authenticate via the backdoor. Bandit flags this under rule **B105**.

### Finding SEC-VULN-03: Plaintext Password Storage
- **File:** `vulnerable_app/database.py` (Lines 35-43, 94)
- **Code:**
  ```python
  # Line 40:
  cursor.execute("INSERT INTO users (username, password, role) VALUES ('alice', 'password123', 'user')")
  ```
- **Why Insecure:** Passwords are stored in the SQLite database without one-way cryptographic hashing. If the database file is read through SQL injection, local access, or accidental backup exposure, every user's credential is compromised immediately.

### Finding SEC-VULN-04: Missing Input Validation & Sanitization
- **File:** `vulnerable_app/app.py` (Lines 62-63, 116-117)
- **Code:**
  ```python
  username = request.form.get('username')
  password = request.form.get('password')
  # Immediately passed to database without checking length, character whitelist, or null checks
  ```
- **Why Insecure:** Missing input validation permits invalid formats, control characters, excessively long payloads that may lead to denial of service, and blank credentials.

### Finding SEC-VULN-05: Flask Debug Mode Enabled in Production
- **File:** `vulnerable_app/app.py` (Line 173)
- **Code:**
  ```python
  app.run(host='127.0.0.1', port=5000, debug=True)
  ```
- **Why Insecure:** Enabling `debug=True` activates Werkzeug's interactive web-based debugger. Whenever an unhandled exception occurs, an interactive terminal is rendered in the browser. In production, this can lead to Remote Code Execution (RCE). Bandit flags this under rule **B201**.

### Finding SEC-VULN-06: Verbose Error Handling & Information Disclosure
- **File:** `vulnerable_app/app.py` (Lines 90-104)
- **Code:**
  ```python
  except Exception as e:
      return f"<p>Detailed Exception: {str(e)}</p>", 500
  ```
- **Why Insecure:** Returning internal database exception messages exposes internal table structures, column names, and SQLite engine errors to clients, assisting attackers in footprinting the database schema.

### Finding SEC-VULN-07: Insecure Session and Cookie Security Configuration
- **File:** `vulnerable_app/app.py` (Lines 37-41)
- **Code:**
  ```python
  app.config['SESSION_COOKIE_HTTPONLY'] = False
  app.config['SESSION_COOKIE_SAMESITE'] = None
  ```
- **Why Insecure:** Disabling `HttpOnly` exposes the session cookie to `document.cookie` in the browser, making session tokens vulnerable to exfiltration via Cross-Site Scripting (XSS). Disabling `SameSite` removes protections against Cross-Site Request Forgery (CSRF).

---

## 10. Remediation for Each Vulnerability

| Finding ID | Remediation Strategy |
| :--- | :--- |
| **SEC-VULN-01** | Replace all f-string query constructions with SQLite parameterized queries using `?` placeholders. |
| **SEC-VULN-02** | Remove all hardcoded keys and backdoors. Load `SECRET_KEY` from environment variables using `python-dotenv`, with dynamic random generation fallback. |
| **SEC-VULN-03** | Use Werkzeug's cryptographic library (`generate_password_hash` with `pbkdf2:sha256`) and verify passwords using `check_password_hash`. |
| **SEC-VULN-04** | Implement regex validation for usernames (`^[a-zA-Z0-9_]{3,30}$`) and enforce multi-rule password complexity checking. |
| **SEC-VULN-05** | Enforce `debug=False` explicitly in the application entry point and configure via environment variable. |
| **SEC-VULN-06** | Replace raw error reflections with user-friendly generic messages, custom 404/500 error templates, and server-side logging. |
| **SEC-VULN-07** | Set `SESSION_COOKIE_HTTPONLY = True`, `SESSION_COOKIE_SAMESITE = 'Lax'`, configure `SESSION_COOKIE_SECURE`, and invoke `session.clear()` on login. |

---

## 11. Secure Code Explanation

### 1. Parameterized Queries (`secure_app/database.py`):
```python
def find_user_by_username(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    # Safe: Input is passed as parameter tuple, never interpolated into SQL string
    cursor.execute("SELECT id, username, password_hash, role FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user
```
The database engine treats the parameter strictly as data rather than executable SQL syntax, rendering SQL injection mathematically impossible.

### 2. Password Hashing with Werkzeug (`secure_app/database.py`):
```python
from werkzeug.security import generate_password_hash, check_password_hash

# During registration:
password_hash = generate_password_hash(password, method='pbkdf2:sha256')

# During authentication:
if check_password_hash(user['password_hash'], password):
    # Authenticated
```
Passwords are transformed using PBKDF2 (Password-Based Key Derivation Function 2) with SHA-256 and an automatic per-user cryptographic salt. The verification runs in constant time to prevent timing attacks.

### 3. Strict Input Validation (`secure_app/app.py`):
```python
def validate_username(username: str) -> tuple[bool, str]:
    if len(username) < 3 or len(username) > 30:
        return False, "Username must be between 3 and 30 characters."
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username may only contain letters, numbers, and underscores."
    return True, ""
```
Input validation is performed prior to any downstream processing, blocking unexpected characters and malformed requests at the perimeter.

### 4. Hardened Cookie & Secret Key Configuration (`secure_app/app.py`):
```python
load_dotenv()
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
```
Session cookies cannot be read by client-side JavaScript, are restricted on cross-site requests, and expire after 30 minutes of inactivity.

---

## 12. Before vs After Comparison

### Side-by-Side Code Diff Comparison:

#### 1. SQL Query Execution
```diff
--- vulnerable_app/database.py
+++ secure_app/database.py
- query = f"SELECT id, username, password, role FROM users WHERE username = '{username}' AND password = '{password}'"
- cursor.execute(query)
+ cursor.execute(
+     "SELECT id, username, password_hash, role FROM users WHERE username = ?",
+     (username,)
+ )
```

#### 2. Password Storage & Verification
```diff
--- vulnerable_app/database.py
+++ secure_app/database.py
- # Stored in plaintext:
- cursor.execute(f"INSERT INTO users (username, password, role) VALUES ('{username}', '{password}', '{role}')")
+ # Cryptographically hashed:
+ password_hash = generate_password_hash(password, method='pbkdf2:sha256')
+ cursor.execute(
+     "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
+     (username, password_hash, role)
+ )
```

#### 3. Flask Debug Execution
```diff
--- vulnerable_app/app.py
+++ secure_app/app.py
- app.run(host='127.0.0.1', port=5000, debug=True)
+ app.run(host=host, port=port, debug=False)
```

#### 4. Secret Key Management
```diff
--- vulnerable_app/app.py
+++ secure_app/app.py
- app.config['SECRET_KEY'] = "hardcoded_insecure_flask_secret_key_12345"
- DEFAULT_ADMIN_PASSWORD = "HardcodedSuperAdminPassword2026!"
+ load_dotenv()
+ app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
```

### Comprehensive Security Feature Comparison Matrix:

| Security Feature | Vulnerable Application (`vulnerable_app`) | Remediated Application (`secure_app`) |
| :--- | :--- | :--- |
| **SQL Query Handling** | Insecure f-strings / concatenation | Parameterized queries with `?` |
| **Password Storage** | Plaintext (`password123`) | PBKDF2:SHA256 salted hashes |
| **Secret Key Source** | Hardcoded string in source file | `.env` environment variable |
| **Administrative Backdoor** | Hardcoded password in `app.py` | Removed completely |
| **Flask Debug Mode** | `debug=True` (Interactive debugger exposed) | `debug=False` (Strictly disabled) |
| **Input Validation** | None (Any input accepted) | Regex whitelist & password complexity |
| **Error Handling** | Raw exception strings returned to user | Generic error messages + server logging |
| **Session Cookie HttpOnly**| `False` (Vulnerable to XSS theft) | `True` (Protected from JS access) |
| **Session Cookie SameSite**| `None` (Vulnerable to CSRF) | `Lax` (Cross-origin protection) |
| **Session Fixation** | Not addressed | `session.clear()` invoked on login |
| **Bandit Scan Findings** | **6 Security Issues Flagged** | **0 Issues Identified (Clean)** |

---

## 13. Bandit Scan Results

The following scans were executed using Bandit 1.9.4 on Python 3.12.5.

### 13.1 Scan Output on Vulnerable Application (`bandit -r vulnerable_app/`)

```text
[main]	INFO	profile include tests: None
[main]	INFO	profile exclude tests: None
[main]	INFO	cli include tests: None
[main]	INFO	cli exclude tests: None
[main]	INFO	running on Python 3.12.5
Run started: 2026-09-20 11:03:25

Test results:
>> Issue: [B105:hardcoded_password_string] Possible hardcoded password: 'hardcoded_insecure_flask_secret_key_12345'
   Severity: Low   Confidence: Medium
   CWE: CWE-259 (https://cwe.mitre.org/data/definitions/259.html)
   Location: vulnerable_app/app.py:35:11

>> Issue: [B105:hardcoded_password_string] Possible hardcoded password: 'HardcodedSuperAdminPassword2026!'
   Severity: Low   Confidence: Medium
   CWE: CWE-259 (https://cwe.mitre.org/data/definitions/259.html)
   Location: vulnerable_app/app.py:45:25

>> Issue: [B201:flask_debug_true] A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and allows the execution of arbitrary code.
   Severity: High   Confidence: Medium
   CWE: CWE-94 (https://cwe.mitre.org/data/definitions/94.html)
   Location: vulnerable_app/app.py:173:4

>> Issue: [B608:hardcoded_sql_expressions] Possible SQL injection vector through string-based query construction.
   Severity: Medium   Confidence: Low
   CWE: CWE-89 (https://cwe.mitre.org/data/definitions/89.html)
   Location: vulnerable_app/database.py:60:14

>> Issue: [B608:hardcoded_sql_expressions] Possible SQL injection vector through string-based query construction.
   Severity: Medium   Confidence: Low
   CWE: CWE-89 (https://cwe.mitre.org/data/definitions/89.html)
   Location: vulnerable_app/database.py:78:14

>> Issue: [B608:hardcoded_sql_expressions] Possible SQL injection vector through string-based query construction.
   Severity: Medium   Confidence: Low
   CWE: CWE-89 (https://cwe.mitre.org/data/definitions/89.html)
   Location: vulnerable_app/database.py:94:14

--------------------------------------------------
Code scanned:
	Total lines of code: 200
	Total lines skipped (#nosec): 0

Run metrics:
	Total issues (by severity):
		Undefined: 0
		Low: 2
		Medium: 3
		High: 1
	Total issues (by confidence):
		Undefined: 0
		Low: 3
		Medium: 3
		High: 0
```

### 13.2 Scan Output on Remediated Secure Application (`bandit -r secure_app/`)

```text
[main]	INFO	profile include tests: None
[main]	INFO	profile exclude tests: None
[main]	INFO	cli include tests: None
[main]	INFO	cli exclude tests: None
[main]	INFO	running on Python 3.12.5
Run started: 2026-09-20 11:04:28

Test results:
	No issues identified.

--------------------------------------------------
Code scanned:
	Total lines of code: 312
	Total lines skipped (#nosec): 0

Run metrics:
	Total issues (by severity):
		Undefined: 0
		Low: 0
		Medium: 0
		High: 0
	Total issues (by confidence):
		Undefined: 0
		Low: 0
		Medium: 0
		High: 0
```

### 13.3 Scan Comparison Summary

```
Metric                        Vulnerable App       Secure App       Delta / Reduction
Total Lines of Code Scanned        200                312                 +112
Total Security Issues               6                  0                  -100%
High Severity Issues                1                  0                  -100%
Medium Severity Issues              3                  0                  -100%
Low Severity Issues                 2                  0                  -100%
```

---

## 14. Secure Coding Best Practices

Based on the findings and remediations of this review, web developers building Python/Flask applications should enforce the following OWASP-aligned standards:

1. **Always Parameterize Database Queries**:
   - Never use Python format strings (`%s`, `f"..."`, `.format()`) or string concatenation to assemble SQL statements.
   - Always bind variables using driver-provided placeholder semantics (`?` in SQLite, `%s` in PostgreSQL).

2. **Implement Salted Cryptographic Password Hashing**:
   - Never store raw passwords or weak hashes (MD5, SHA-1).
   - Use adaptive hashing algorithms such as PBKDF2, bcrypt, or Argon2 (standard in Werkzeug and Passlib).

3. **Externalize Configuration and Secrets**:
   - Store sensitive keys, tokens, and credentials in environment variables or dedicated secret management vaults (e.g., HashiCorp Vault, AWS Secrets Manager).
   - Keep `.env` files out of public source control by listing them in `.gitignore`.

4. **Strict Input Validation & Whitelisting**:
   - Validate all untrusted input at system boundaries against restrictive type, length, and format whitelists.
   - Reject malformed data early with clear client feedback before passing data to business logic.

5. **Disable Debug Interfaces in Production**:
   - Ensure `FLASK_DEBUG=False` or `debug=False` across production runtime environments.
   - Deploy behind production WSGI servers (Gunicorn, Waitress) with unprivileged service accounts.

6. **Harden HTTP Session Cookies**:
   - Always set `SESSION_COOKIE_HTTPONLY = True` to mitigate credential theft via XSS.
   - Enforce `SESSION_COOKIE_SAMESITE = 'Lax'` or `'Strict'` to guard against CSRF.
   - Enforce `SESSION_COOKIE_SECURE = True` whenever traffic is served over HTTPS.

7. **Implement Safe Error Handling and Logging**:
   - Catch exceptions gracefully and present generic, non-technical error pages to clients.
   - Log complete diagnostics and stack traces server-side, ensuring passwords and sensitive tokens are scrubbed from log outputs.

---

## 15. Conclusion

This academic secure coding review demonstrated the critical importance of defense-in-depth principles in Python web application development. 

Through the intentional design of `vulnerable_app`, 7 common security weaknesses were analyzed. The automated static analyzer **Bandit** successfully flagged syntactic AST violations including hardcoded secrets (`B105`), active debug code (`B201`), and SQL string concatenation (`B608`). However, manual code review was essential to discover higher-level design flaws such as plaintext password storage (`CWE-256`), absent input validation (`CWE-20`), verbose error leakage (`CWE-209`), and insecure session cookie attributes (`CWE-1004`).

By re-engineering the application in `secure_app`, every vulnerability was systematically remediated:
- Parameterized queries eliminated SQL injection vectors.
- Werkzeug PBKDF2 hashing protected credential confidentiality.
- Environment-based secret loading eliminated embedded credentials.
- Input validation and secure cookie attributes hardened session integrity.

Subsequent static analysis confirmed a clean security bill of health with **0 issues identified**, and automated test suites confirmed full functional integrity. This project illustrates that combining static analysis tools with rigorous manual code inspection and OWASP coding standards produces robust, attack-resilient software.
