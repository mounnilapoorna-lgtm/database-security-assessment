# Database Security Assessment Platform

## Capstone
Development of a Database Security Hacking and Hardening Assessment Platform

## Major Modules

### Module 1 - Ethical Hacking & Vulnerability Assessment
- SQL Injection assessment in a controlled sandbox
- Authentication security testing
- Weak password assessment
- Access-control testing
- Sandbox database enumeration
- Vulnerability severity and scoring

### Module 2 - Database Hardening & Security Management
- Parameterized queries
- Input validation
- Password hashing
- Role-Based Access Control
- Account lockout
- Audit logging
- Secure session management
- Security re-testing

## Technology Stack

- Frontend: HTML, CSS, JavaScript
- Backend: Python Flask
- Database: SQLite
- Security: Flask-Login, Werkzeug, SQLAlchemy

## Run Backend

Open a terminal in the backend folder:

    pip install -r requirements.txt
    python app.py

Then open:

    http://127.0.0.1:5000

## Ethical Use

All security testing is intended for the application's own controlled/sandbox database. Do not use the project to attack systems that you do not own or have explicit permission to test.

## Current Version

Phase 1 foundation:
- Project structure
- Flask API
- Health endpoint
- Initial frontend pages
- Requirements
- README

Database schema, authentication/RBAC, vulnerability assessment, hardening, audit logging, scoring, and reporting will be added in subsequent phases.
