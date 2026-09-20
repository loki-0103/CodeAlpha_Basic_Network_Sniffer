# Academic Submission Screenshots Directory

This directory is designated for storing screenshots illustrating the code review, Bandit static analysis findings, and application testing for academic grading.

## Recommended Screenshots for Submission

1. **`01_bandit_vulnerable_scan.png`**:
   - Terminal output running `bandit -r vulnerable_app/` displaying detected issues (B105, B201, B608).

2. **`02_bandit_secure_scan.png`**:
   - Terminal output running `bandit -r secure_app/` showing `No issues identified` (0 High, 0 Medium, 0 Low).

3. **`03_vulnerable_app_home_and_login.png`**:
   - Browser showing `http://127.0.0.1:5000` with the Red Warning Academic Banner.

4. **`04_vulnerable_app_plaintext_dashboard.png`**:
   - Browser showing the vulnerable dashboard table with plain text passwords visible in `vulnerable.db`.

5. **`05_vulnerable_error_disclosure.png`**:
   - Triggering a SQLite syntax error or invalid query in the vulnerable app demonstrating raw exception leakage (CWE-209).

6. **`06_secure_app_home_and_login.png`**:
   - Browser showing `http://127.0.0.1:5001` with the Emerald Hardened Banner and defense badges.

7. **`07_secure_app_hashed_dashboard.png`**:
   - Browser showing the secure dashboard with PBKDF2:SHA256 password hashes.

8. **`08_secure_app_input_validation.png`**:
   - Attempting registration with a weak password showing the password complexity enforcement rejection.
