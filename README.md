# Open-Source Web Application Firewall (WAF) & SOC Analytics Dashboard

A lightweight, behavioral Web Application Firewall (WAF) built from scratch in Python/Flask. This application inspects application-layer traffic against advanced threat signatures (SQL Injection & Cross-Site Scripting) using regular expressions, enforces IP-based rate limiting to prevent brute-force attacks, and streams real-time telemetry to a secure Security Operations Center (SOC) dashboard.

## 🚀 Key Features

* **Heuristic Threat Detection:** Utilizes regular expressions (`re` library) to run case-insensitive structural matching on input vectors rather than basic keyword checks.
* **Identity & Access Management (IAM):** Protects administrative data via secure Flask Session cookies, rejecting unauthenticated traffic with explicit `401 Unauthorized` responses.
* **IP Rate-Limiting Middleware:** Implements a dynamic, in-memory sliding window penalty clock tracking clients by `request.remote_addr` to drop automated authentication attacks via `429 Too Many Requests` states.
* **Persistent Telemetry Logging:** Features an asynchronous relational logging pipeline with SQLite using absolute path mapping to ensure cross-process transactional integrity.

---

## 🛠️ System Architecture Diagram


```

[ Client / Attacker ]
│
▼
(HTTP POST /login)
┌────────────────────────────────────────────────────────┐
│                 Python/Flask Firewall                  │
├────────────────────────────────────────────────────────┤
│ 1. Rate Limiter: Active Lockout Check?                 │
│ 2. Regex Engine: SQLi Signature Pattern Match?         │
│ 3. Regex Engine: XSS Script/Tag Vector Match?          │
└─────────────────────────┬──────────────────────────────┘
│ (If Threat Triggered)
▼
┌──────────────────────────────────┐
│  SQLite Persistent Log Database  │
│       (security_logs.db)         │
└────────────────┬─────────────────┘
│ (Authenticated Query)
▼
┌────────────────────────────────────────────────────────┐
│           Secure SOC Administrative Panel             │
│          ([http://127.0.0.1:5000/dashboard](https://www.google.com/search?q=http://127.0.0.1:5000/dashboard))             │
└────────────────────────────────────────────────────────┘

```

---

## 📦 Tech Stack

* **Backend Framework:** Python 3 (Flask)
* **Database Engine:** SQLite3 (Relational Binary Engine)
* **Frontend Templating:** HTML5 / CSS3 / Jinja2
* **Security Middleware:** Native `re` (Regular Expressions) & `time` (Sliding Cooldown Arrays)

---

## ⚙️ Installation & Local Setup

### 1. Clone the Environment
```bash
git clone [https://github.com/jeushdev/security_webapp.git](https://github.com/jeushdev/security_webapp.git)
cd security_webapp

```

### 2. Initialize the Database Schema

Before running the application server, compile the relational table layout on your local hardware:

```bash
python init_db.py

```

### 3. Launch the Application

Start up the web server gateway interface:

```bash
python app.py

```

The server will initialize locally at: `http://127.0.0.1:5000/`

---

## 🔒 Simulated Exploit Scenarios (For Verification)

### SQL Injection Mitigation

* **Payload:** `admin' or 5=5 --`
* **Expected Result:** Application catches truth-match pattern structural anomaly, returns a `403 Forbidden` block, and logs the payload parameters to the SOC platform.

### Cross-Site Scripting (XSS) Mitigation

* **Payload:** `<script>alert(window.origin)</script>`
* **Expected Result:** Application flags HTML tag injection boundaries, drops the request context via a `403` handler, and locks data attributes into the system pipeline.

### Brute-Force Rate Limiting

* **Action:** Submit invalid credentials 3 consecutive times.
* **Expected Result:** Server enforces a strict 30-second penalty lockout window via `429 Too Many Requests`.

---

## 👤 Author

* **Jeush Samuel L. Bantayaon** - Computer Science Student
* **Connect:** https://www.linkedin.com/in/jeush-samuel-bantayaon-2ab40b370/ 

```

```
