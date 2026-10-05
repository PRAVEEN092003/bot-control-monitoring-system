# Bot Control and Monitoring System Using CAPTCHA

A production-grade, cybersecurity-focused web application designed to detect automated bot behavior, challenge suspicious visitors with CAPTCHA verification, compute dynamic threat risk scores, apply rate limits, enforce temporary IP blocking, and provide real-time monitoring via an administrative dashboard.

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Tech Stack](#tech-stack)
- [System Architecture](#system-architecture)
- [Project Folder Structure](#project-folder-structure)
- [Installation & Setup](#installation--setup)
- [Environment Configuration](#environment-configuration)
- [Database Setup](#database-setup)
- [Running the Application](#running-the-application)
- [Admin Account Setup](#admin-account-setup)
- [Testing & Quality Assurance](#testing--quality-assurance)
- [Security Features & Controls](#security-features--controls)
- [API Endpoints](#api-endpoints)
- [License](#license)

---

## Overview

Automated bots generate substantial malicious web traffic (credential stuffing, scraping, DDoS, brute-force attacks). The **Bot Control and Monitoring System** provides end-to-end detection and mitigation:
- Analyzes user request patterns and failed interaction history.
- Dynamically assigns **Risk Scores** (0–100) and **Risk Levels** (`NORMAL`, `SUSPICIOUS`, `HIGH_RISK`).
- Employs **in-house distortion CAPTCHAs** (cryptographically verified single-use session tokens) to separate humans from automation.
- Enforces multi-tier **Rate Limiting** and **Automatic Temporary IP Blocking**.
- Provides a **Real-Time Admin Dashboard** featuring interactive Chart.js analytics, paginated security audit trails, user account management, and manual IP ban/unban controls.

---

## Key Features

- **Authentication & Role-Based Access Control**:
  - Secure registration and login with bcrypt password hashing.
  - Role management separating standard authenticated users from system administrators.
  - Protection against credential stuffing and brute-force guessing.

- **Dynamic CAPTCHA Challenge System**:
  - In-house PIL/Pillow image generation with random character distortion, rotation, noise arcs, and interference lines.
  - Ambiguity-free character sets (excludes `0`, `O`, `1`, `I`, `l`).
  - Session-bound, single-use, and time-expired challenge tokens.

- **Bot Detection & Risk Scoring Engine**:
  - Real-time heuristic evaluation: repeated failed logins (+20), CAPTCHA failures (+25), excessive request volume (+30), rapid repeat activity (+25).
  - Configurable risk thresholds (`NORMAL`: 0–30, `SUSPICIOUS`: 31–60, `HIGH_RISK`: 61–100).
  - Every activity log record tracks risk score updates.

- **Rate Limiting & Temporary IP Blocking**:
  - Flask-Limiter route-level throttling on registration, authentication, and CAPTCHA submissions.
  - Automatic IP ban enforcement when an IP crosses the high-risk threshold.
  - Clean auto-expiry mechanism unblocking IPs once their ban duration elapses.
  - Pre-request blocking middleware intercepting requests before reaching application endpoints.

- **Comprehensive Admin Monitoring Dashboard**:
  - 6 Key Performance Indicator (KPI) metric cards: Total Users, Total Security Events, CAPTCHA Pass/Fail stats, Suspicious incidents, High-Risk events, and Active Blocked IPs.
  - 3 Interactive Chart.js visualizations (Event distribution bar chart, Risk-level breakdown doughnut chart, CAPTCHA outcome comparison).
  - Paginated audit log viewer with multi-criteria filtering by event type, risk level, status, date range, IP, and full-text keyword search.
  - User accounts directory with last login timestamps and lock status.
  - Live blocked IP management with manual ban and release controls.

- **Defensive Security Hardening**:
  - Full CSRF protection on state-changing endpoints.
  - Strict security headers (`X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`, `Referrer-Policy`, `Permissions-Policy`, `Strict-Transport-Security`).
  - Strict open redirect prevention on `next` URL parameters.
  - Sanitized error responses for `400`, `401`, `403`, `404`, `405`, `429`, and `500`.

---

## Tech Stack

- **Backend**: Python 3.12, Flask 3.0, Werkzeug 3.0
- **Database & ORM**: SQLAlchemy 2.0, Flask-SQLAlchemy 3.1 (SQLite in dev/test, PostgreSQL ready)
- **Authentication**: Flask-Login 0.6, bcrypt 4.2
- **Form Validation & Security**: Flask-WTF 1.2, WTForms 3.1, email-validator 2.3
- **Rate Limiting**: Flask-Limiter 3.8, limits 3.13
- **Image Generation**: Pillow (PIL) 10.4
- **Frontend**: HTML5, CSS3 (Custom Glassmorphism Design System), Bootstrap 5.3, Bootstrap Icons 1.11, Chart.js 4.4
- **Testing**: pytest 8.3

---

## System Architecture

```
                      ┌────────────────────────────────────────┐
                      │             Client / Browser           │
                      └──────────────────┬─────────────────────┘
                                         │
                                         ▼
                      ┌────────────────────────────────────────┐
                      │    Pre-Request IP Block Middleware     │ ──▶ [403 Forbidden]
                      └──────────────────┬─────────────────────┘
                                         │ (Allowed IP)
                                         ▼
                      ┌────────────────────────────────────────┐
                      │          Flask-Limiter Guard           │ ──▶ [429 Too Many Requests]
                      └──────────────────┬─────────────────────┘
                                         │
                   ┌─────────────────────┴─────────────────────┐
                   │                                           │
                   ▼                                           ▼
      ┌─────────────────────────┐                 ┌─────────────────────────┐
      │  User / Auth Endpoints  │                 │   Admin Control Suite   │
      │  (/auth, /captcha, etc) │                 │      (/admin/*)         │
      └────────────┬────────────┘                 └────────────┬────────────┘
                   │                                           │
                   ├─────────────────┐       ┌─────────────────┤
                   ▼                 ▼       ▼                 ▼
          ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
          │  Bot Detection  │   │  Activity Log   │   │  IP Blocker &   │
          │  & Risk Engine  │   │ & Audit Service │   │  Expirations    │
          └────────┬────────┘   └────────┬────────┘   └────────┬────────┘
                   │                     │                     │
                   └─────────────────────┼─────────────────────┘
                                         │
                                         ▼
                      ┌────────────────────────────────────────┐
                      │         Database (SQLite / SQL)        │
                      └────────────────────────────────────────┘
```

---

## Project Folder Structure

```
Bot Control and Monitoring System/
├── app.py                      # Application factory, middleware & error handlers
├── config.py                   # Environment-driven configuration classes
├── extensions.py               # Shared extensions (db, login_manager, csrf, limiter)
├── pytest.ini                  # Pytest configuration settings
├── requirements.txt            # Pinned project dependencies
├── .env.example                # Sample environment variables template
├── .gitignore                  # Git ignore rules (protects secrets & database)
├── README.md                   # Complete system documentation
│
├── forms/                      # Form definitions with WTForms validation
│   ├── __init__.py
│   ├── auth_forms.py           # Registration & Login forms with CSRF
│   └── captcha_forms.py        # CAPTCHA verification challenge forms
│
├── models/                     # SQLAlchemy data models
│   ├── __init__.py
│   ├── activity.py             # ActivityLog model (event types, risk levels)
│   ├── blocked_ip.py           # BlockedIP model with auto-expiry logic
│   ├── captcha.py              # CaptchaAttempt telemetry model
│   └── user.py                 # User model with bcrypt password hashing
│
├── routes/                     # Blueprint route controllers
│   ├── __init__.py
│   ├── admin.py                # Admin dashboard, logs, users, IP management
│   ├── auth.py                 # User registration, login, logout
│   ├── captcha.py              # CAPTCHA challenge rendering & verification
│   └── user.py                 # User personal dashboard and activity view
│
├── services/                   # Modular business logic services
│   ├── __init__.py
│   ├── bot_detector.py         # Behavioral anomaly detection algorithms
│   ├── captcha_service.py      # Image CAPTCHA generation & verification
│   ├── ip_blocker.py           # Temporary IP ban and automatic expiration
│   ├── monitoring.py           # Centralized security audit logging service
│   └── risk_engine.py          # Dynamic risk calculation & level classification
│
├── static/                     # Static frontend assets
│   ├── css/
│   │   └── style.css           # Custom dark glassmorphism design system
│   └── js/                     # Client scripts
│
├── templates/                  # Jinja2 HTML templates
│   ├── base.html               # Shared base layout with navbar and footer
│   ├── captcha.html            # Dedicated CAPTCHA challenge interface
│   ├── index.html              # Landing page
│   ├── login.html              # Secure user sign-in page
│   ├── register.html           # User account registration page
│   ├── admin/
│   │   ├── blocked_ips.html    # Blocked IP records & manual ban/unban panel
│   │   ├── dashboard.html      # KPI metrics, Chart.js graphs & recent events
│   │   ├── logs.html           # Paginated audit logs with multi-filters
│   │   └── users.html          # Registered user accounts directory
│   └── user/
│       ├── activity.html       # Individual user activity history
│       └── dashboard.html      # Individual user personal dashboard
│
└── tests/                      # Automated test suite (131 tests)
    ├── conftest.py             # Isolated function-scoped test fixtures
    ├── test_activity.py        # Activity logging & user audit tests
    ├── test_admin.py           # Admin dashboard, KPIs, logs & filtering tests
    ├── test_auth.py            # Authentication, registration & session tests
    ├── test_bot_detection.py   # Anomaly detection & risk scoring engine tests
    ├── test_captcha.py         # CAPTCHA generation, distortion & verify tests
    ├── test_rate_limit.py      # Rate limiting & temporary IP blocking tests
    └── test_security.py        # Security headers, open redirect & hardening tests
```

---

## Installation & Setup

### Prerequisites

- Python 3.10, 3.11, or 3.12 installed.
- Git installed.

### 1. Clone or Open the Repository

```bash
git clone <repository_url>
cd "Bot Control and Monitoring System"
```

### 2. Create and Activate a Virtual Environment

**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**macOS / Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Environment Configuration

Create a `.env` file in the root directory by copying `.env.example`:

```bash
cp .env.example .env
```

Edit `.env` to configure your settings:

```ini
# Flask Core
SECRET_KEY=generate-a-strong-32-byte-secret-key
FLASK_ENV=development
FLASK_DEBUG=True

# Database (defaults to SQLite; supports PostgreSQL, MySQL)
DATABASE_URL=sqlite:///bot_monitor.db

# Admin Bootstrap Credentials (created automatically on first launch)
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=AdminSecurePassword@2024!

# Rate Limiting Storage (memory:// for dev, redis://localhost:6379/0 for prod)
RATELIMIT_STORAGE_URI=memory://

# Session Security
SESSION_COOKIE_SECURE=False
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE=Lax

# CAPTCHA Configuration
CAPTCHA_LENGTH=6
CAPTCHA_EXPIRY_SECONDS=120

# Risk Thresholds
RISK_SUSPICIOUS_THRESHOLD=31
RISK_HIGH_THRESHOLD=61

# Temporary IP Ban Duration (Minutes)
IP_BLOCK_DURATION_MINUTES=30
```

---

## Database Setup

The database tables and initial administrator account are automatically initialized on application startup via `db.create_all()` and `_seed_admin()`.

To manually verify or reset the database:
```python
python -c "from app import create_app, db; app = create_app(); app.app_context().push(); db.create_all(); print('Database ready.')"
```

---

## Running the Application

### Development Mode

```bash
python app.py
```

The application will start at: `http://127.0.0.1:5000`

### Production Mode

Run using a WSGI server such as Gunicorn (Linux/macOS) or Waitress (Windows):

```bash
# Windows
waitress-serve --port=5000 app:app

# Linux / macOS
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

---

## Admin Account Setup

1. On initial startup, if `ADMIN_EMAIL` and `ADMIN_PASSWORD` are configured in `.env`, the system automatically provisions an admin account.
2. Sign in at `http://127.0.0.1:5000/auth/login` using your configured admin credentials.
3. Access the Admin Security Console at `http://127.0.0.1:5000/admin/dashboard`.

---

## Testing & Quality Assurance

The test suite contains **131 comprehensive tests** covering every layer of the application.

### Running All Tests

```bash
python -m pytest -v
```

### Running Specific Test Modules

```bash
# Admin Dashboard & Analytics tests
python -m pytest tests/test_admin.py -v

# Security Hardening & Headers tests
python -m pytest tests/test_security.py -v

# Bot Detection & Risk Scoring tests
python -m pytest tests/test_bot_detection.py -v

# Rate Limiting & IP Blocking tests
python -m pytest tests/test_rate_limit.py -v

# CAPTCHA generation & verification tests
python -m pytest tests/test_captcha.py -v

# Authentication & Session tests
python -m pytest tests/test_auth.py -v
```

---

## Security Features & Controls

| Feature | Implementation | Benefit |
|---|---|---|
| **Password Hashing** | bcrypt with work factor 12 | Defense against rainbow tables and GPU cracking. |
| **CSRF Protection** | Flask-WTF `FlaskForm` tokens | Prevents cross-site request forgery attacks. |
| **Rate Limiting** | Flask-Limiter | Mitigates brute-force attacks and volumetric DDoS. |
| **IP Blocking** | Pre-request middleware with auto-expiry | Neutralizes high-risk IPs without manual intervention. |
| **HTTP Headers** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options | Protects against XSS, clickjacking, and MIME sniffing. |
| **Open Redirect Defense** | Host validation via `_is_safe_url()` | Rejects phishing and external redirects on `next` parameters. |
| **Cookie Security** | `HttpOnly`, `SameSite=Lax`, `Secure` | Shields session cookies from JavaScript theft. |

---

## API Endpoints

| Method | Endpoint | Access | Description |
|---|---|---|---|
| `GET` | `/` | Public | Home / Redirect to dashboard or login |
| `GET/POST` | `/auth/register` | Public | Account creation |
| `GET/POST` | `/auth/login` | Public | User authentication |
| `GET` | `/auth/logout` | Authenticated | Session termination |
| `GET/POST` | `/captcha/challenge` | Public | Visual CAPTCHA challenge |
| `GET` | `/captcha/refresh` | Public | Regenerate CAPTCHA token/image |
| `GET` | `/captcha/image` | Public | Stream challenge as raw PNG image |
| `GET` | `/user/dashboard` | User | User personal dashboard |
| `GET` | `/user/activity` | User | User activity event history |
| `GET` | `/admin/dashboard` | Admin | Security analytics dashboard |
| `GET` | `/admin/logs` | Admin | Paginated security audit trail |
| `GET` | `/admin/users` | Admin | User account management directory |
| `GET` | `/admin/blocked-ips` | Admin | Blocked IP management & status |
| `POST` | `/admin/block-ip` | Admin | Manually enforce temporary IP ban |
| `POST` | `/admin/unblock-ip` | Admin | Manually release an active IP ban |
| `GET` | `/admin/api/stats` | Admin | JSON telemetry statistics |

---

