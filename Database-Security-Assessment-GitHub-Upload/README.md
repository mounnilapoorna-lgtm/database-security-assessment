# DBShield — Database Security Hacking and Hardening Assessment Platform

## Capstone
Development of a Database Security Hacking and Hardening Assessment Platform.

## Two Major Modules

### Module 1 — Ethical Hacking & Vulnerability Assessment
- Controlled SQL-injection indicator assessment
- Authentication security assessment
- Weak-password assessment
- Access-control assessment
- Vulnerability severity
- Security scoring

### Module 2 — Database Hardening & Security Management
- Password hashing
- Parameterized-query architecture
- Input validation
- Role-Based Access Control
- Account lockout
- Audit logging
- Secure sessions
- Security-control management

## Demo Credentials

These are demo credentials for the local security laboratory only:

- Admin: `admin` / `Admin@12345`
- Security Tester: `tester` / `Tester@12345`
- Viewer: `viewer` / `Viewer@12345`

Change these credentials before any real deployment.

## Local Run

From the project root:

```bash
cd backend
python -m venv venv
```

Windows:

```bash
venv\Scripts\activate
```

Linux/macOS:

```bash
source venv/bin/activate
```

Install:

```bash
pip install -r requirements.txt
```

Run:

```bash
python app.py
```

Open:

`http://127.0.0.1:5000`

## Production

Use a production WSGI server such as:

```bash
gunicorn app:app
```

Set a strong `SECRET_KEY` environment variable.

## Ethical Scope

Security assessment functions are intentionally limited to this application's controlled security laboratory. The SQL-injection assessment detects suspicious patterns but does not execute attacker-supplied SQL. Do not use this project to attack systems you do not own or have explicit permission to test.
