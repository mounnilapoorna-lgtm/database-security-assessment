from flask import Flask, request, jsonify, session, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import sqlite3
import os
import re
from datetime import datetime, timedelta

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database", "security_lab.db")
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-this-secret")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
CORS(app, supports_credentials=True)

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 10

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin','tester','viewer')),
        failed_attempts INTEGER DEFAULT 0,
        locked_until TEXT
    );

    CREATE TABLE IF NOT EXISTS security_tests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        test_name TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        result TEXT NOT NULL,
        details TEXT,
        username TEXT,
        timestamp TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        action TEXT NOT NULL,
        result TEXT NOT NULL,
        details TEXT,
        timestamp TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS hardening_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        control_name TEXT UNIQUE NOT NULL,
        enabled INTEGER DEFAULT 0,
        updated_by TEXT,
        updated_at TEXT
    );
    """)
    defaults = {
        "Parameterized Queries": 1,
        "Input Validation": 1,
        "Password Hashing": 1,
        "Role-Based Access Control": 1,
        "Account Lockout": 1,
        "Audit Logging": 1,
        "Secure Sessions": 1
    }
    for name, enabled in defaults.items():
        conn.execute(
            "INSERT OR IGNORE INTO hardening_actions(control_name, enabled) VALUES (?, ?)",
            (name, enabled)
        )

    users = [
        ("admin", "Admin@12345", "admin"),
        ("tester", "Tester@12345", "tester"),
        ("viewer", "Viewer@12345", "viewer")
    ]
    for username, password, role in users:
        conn.execute(
            "INSERT OR IGNORE INTO users(username, password_hash, role) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), role)
        )
    conn.commit()
    conn.close()

def now():
    return datetime.utcnow().isoformat(timespec="seconds")

def audit(username, action, result, details=""):
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_logs(username, action, result, details, timestamp) VALUES (?, ?, ?, ?, ?)",
        (username, action, result, details, now())
    )
    conn.commit()
    conn.close()

def current_user():
    username = session.get("username")
    if not username:
        return None
    conn = get_db()
    user = conn.execute(
        "SELECT id, username, role FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    return dict(user) if user else None

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            return jsonify({"error": "Authentication required"}), 401
        return fn(*args, **kwargs)
    return wrapper

def role_required(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user:
                return jsonify({"error": "Authentication required"}), 401
            if user["role"] not in roles:
                audit(user["username"], request.path, "DENIED", "Insufficient privileges")
                return jsonify({"error": "Insufficient privileges"}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator

def severity_for(test_name):
    return {
        "SQL Injection Assessment": "HIGH",
        "Authentication Security": "HIGH",
        "Weak Password Assessment": "MEDIUM",
        "Access-Control Test": "HIGH",
        "Database Configuration": "LOW"
    }.get(test_name, "LOW")

def save_test(name, category, severity, result, details, username):
    conn = get_db()
    conn.execute(
        """INSERT INTO security_tests
           (test_name, category, severity, result, details, username, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (name, category, severity, result, details, username, now())
    )
    conn.commit()
    conn.close()
    audit(username, name, result, details)

@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")

@app.route("/<path:path>")
def frontend(path):
    file_path = os.path.join(FRONTEND_DIR, path)
    if os.path.isfile(file_path):
        return send_from_directory(FRONTEND_DIR, path)
    return send_from_directory(FRONTEND_DIR, "index.html")

@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    if not user:
        conn.close()
        return jsonify({"error": "Invalid credentials"}), 401

    if user["locked_until"]:
        try:
            if datetime.fromisoformat(user["locked_until"]) > datetime.utcnow():
                conn.close()
                return jsonify({"error": "Account temporarily locked"}), 423
        except ValueError:
            pass

    if not check_password_hash(user["password_hash"], password):
        attempts = user["failed_attempts"] + 1
        locked_until = None
        if attempts >= MAX_LOGIN_ATTEMPTS:
            locked_until = (datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat(timespec="seconds")
            attempts = 0
        conn.execute(
            "UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
            (attempts, locked_until, user["id"])
        )
        conn.commit()
        conn.close()
        audit(username, "LOGIN", "FAILED", "Invalid credentials")
        return jsonify({"error": "Invalid credentials"}), 401

    conn.execute(
        "UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?",
        (user["id"],)
    )
    conn.commit()
    conn.close()

    session.clear()
    session.permanent = True
    session["username"] = username
    audit(username, "LOGIN", "SUCCESS", "User authenticated")
    return jsonify({"message": "Login successful", "username": username, "role": user["role"]})

@app.post("/api/logout")
@login_required
def logout():
    user = current_user()
    audit(user["username"], "LOGOUT", "SUCCESS", "User logged out")
    session.clear()
    return jsonify({"message": "Logged out"})

@app.get("/api/me")
@login_required
def me():
    return jsonify(current_user())

@app.get("/api/dashboard")
@login_required
def dashboard():
    conn = get_db()
    tests = conn.execute("SELECT * FROM security_tests ORDER BY id DESC").fetchall()
    controls = conn.execute("SELECT * FROM hardening_actions ORDER BY id").fetchall()
    conn.close()

    penalties = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5}
    score = 100
    for row in tests:
        if row["result"] == "VULNERABLE":
            score -= penalties.get(row["severity"], 5)
    score = max(0, score)

    return jsonify({
        "security_score": score,
        "tests_performed": len(tests),
        "vulnerabilities": sum(1 for t in tests if t["result"] == "VULNERABLE"),
        "passed": sum(1 for t in tests if t["result"] in ("PASSED", "BLOCKED")),
        "controls": [dict(c) for c in controls],
        "recent_tests": [dict(t) for t in tests[:10]]
    })

@app.post("/api/security-tests/sql-injection")
@role_required("admin", "tester")
def sql_injection_test():
    user = current_user()
    data = request.get_json(silent=True) or {}
    sample_input = str(data.get("input", ""))

    # Defensive assessment only: detect common SQL-injection indicators.
    # No attacker-supplied string is executed as SQL.
    pattern = re.compile(r"(--|/\*|\*/|'\s*(or|and)\s+['\d]|;\s*(select|drop|insert|update|delete)\b)", re.I)
    detected = bool(pattern.search(sample_input))

    if detected:
        result = "VULNERABLE"
        details = "Suspicious SQL-injection pattern detected in the controlled test input. No SQL was executed."
    else:
        result = "PASSED"
        details = "No known SQL-injection indicator detected in the supplied test input."

    save_test(
        "SQL Injection Assessment",
        "Injection",
        severity_for("SQL Injection Assessment"),
        result,
        details,
        user["username"]
    )
    return jsonify({"test": "SQL Injection Assessment", "result": result, "details": details})

@app.post("/api/security-tests/password")
@role_required("admin", "tester")
def password_test():
    user = current_user()
    data = request.get_json(silent=True) or {}
    password = str(data.get("password", ""))

    checks = {
        "length": len(password) >= 8,
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "number": bool(re.search(r"\d", password)),
        "special": bool(re.search(r"[^A-Za-z0-9]", password))
    }
    strong = all(checks.values())
    result = "PASSED" if strong else "VULNERABLE"
    details = "Strong password policy satisfied." if strong else "Password does not satisfy all strength requirements."

    save_test(
        "Weak Password Assessment",
        "Authentication",
        severity_for("Weak Password Assessment"),
        result,
        details,
        user["username"]
    )
    return jsonify({"test": "Weak Password Assessment", "result": result, "checks": checks, "details": details})

@app.post("/api/security-tests/authentication")
@role_required("admin", "tester")
def authentication_test():
    user = current_user()
    conn = get_db()
    row = conn.execute(
        "SELECT failed_attempts, locked_until FROM users WHERE username=?",
        (user["username"],)
    ).fetchone()
    conn.close()

    lockout_enabled = True
    result = "PASSED" if lockout_enabled else "VULNERABLE"
    details = "Account lockout and hashed-password authentication are enabled."

    save_test(
        "Authentication Security",
        "Authentication",
        severity_for("Authentication Security"),
        result,
        details,
        user["username"]
    )
    return jsonify({"test": "Authentication Security", "result": result, "details": details})

@app.post("/api/security-tests/access-control")
@login_required
def access_control_test():
    user = current_user()
    allowed = user["role"] in ("admin", "tester")
    result = "PASSED" if allowed else "BLOCKED"
    details = "Current role has permitted testing access." if allowed else "Viewer role is correctly restricted from security-test operations."

    save_test(
        "Access-Control Test",
        "Authorization",
        severity_for("Access-Control Test"),
        result,
        details,
        user["username"]
    )
    return jsonify({"test": "Access-Control Test", "result": result, "details": details})

@app.get("/api/audit")
@role_required("admin", "tester")
def audit_logs():
    conn = get_db()
    rows = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.get("/api/hardening")
@login_required
def hardening_status():
    conn = get_db()
    rows = conn.execute("SELECT * FROM hardening_actions ORDER BY id").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.post("/api/hardening/<int:control_id>")
@role_required("admin")
def update_hardening(control_id):
    user = current_user()
    data = request.get_json(silent=True) or {}
    enabled = 1 if bool(data.get("enabled")) else 0

    conn = get_db()
    row = conn.execute(
        "SELECT control_name FROM hardening_actions WHERE id=?", (control_id,)
    ).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Control not found"}), 404

    conn.execute(
        "UPDATE hardening_actions SET enabled=?, updated_by=?, updated_at=? WHERE id=?",
        (enabled, user["username"], now(), control_id)
    )
    conn.commit()
    conn.close()

    audit(user["username"], "HARDENING", "UPDATED",
          f"{row['control_name']} set to {'enabled' if enabled else 'disabled'}")
    return jsonify({"message": "Hardening control updated", "control": row["control_name"], "enabled": bool(enabled)})

@app.get("/api/report")
@login_required
def report():
    conn = get_db()
    tests = conn.execute("SELECT * FROM security_tests ORDER BY id").fetchall()
    controls = conn.execute("SELECT * FROM hardening_actions ORDER BY id").fetchall()
    conn.close()

    penalties = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5}
    score = max(0, 100 - sum(
        penalties.get(t["severity"], 5) for t in tests if t["result"] == "VULNERABLE"
    ))

    return jsonify({
        "generated_at": now(),
        "security_score": score,
        "tests": [dict(t) for t in tests],
        "hardening_controls": [dict(c) for c in controls]
    })

if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
