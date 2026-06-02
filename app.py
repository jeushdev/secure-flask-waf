from flask import Flask, render_template, request, session, redirect
import re
import sqlite3
import os
import time

app = Flask(__name__)

app.secret_key = 'super_secret_admin_key_change_this_later'

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "Password123!"

login_attempts = {}

def detect_sqli(user_input):
    if not user_input:
        return False
    
    # This regex pattern looks for a single quote followed by common SQL words (OR, AND, UNION, SELECT)
    # OR any pattern where something equals itself (like 1=1, 'a'='a', 2=2)
    sqli_pattern = r"('|\b)(or|and)\b\s+\d+=\d+|'|--|\bunion\b|\bselect\b"
    
    # re.search scans the string for the pattern. flags=re.IGNORECASE makes it case-insensitive
    if re.search(sqli_pattern, user_input, re.IGNORECASE):
        print(f"[REGEX ALERT] SQL Injection pattern matched in input: '{user_input}'")
        return True
    return False

def detect_xss(user_input):
    if not user_input:
        return False
    
    # This pattern catches <script> tags, HTML brackets containing keywords, or event handlers like onerror/onload
    xss_pattern = r"<script.*?>|<\/script>|javascript:|onerror=|onload=|html|<body>|<iframe"
    
    if re.search(xss_pattern, user_input, re.IGNORECASE):
        print(f"[REGEX ALERT] XSS pattern matched in input: '{user_input}'")
        return True
    return False

def log_attack_to_db(attack_type, payload, endpoint):
    conn = None
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        db_path = os.path.join(base_dir, 'security_logs.db')

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()  

        cursor.execute('''
            INSERT INTO attack_logs (attack_type, payload, vulnerable_endpoint)
            VALUES (?, ?, ?)
        ''', (attack_type, str(payload), str(endpoint)))

        conn.commit()
        print(f"[SUCCESS WRITE] Logged {attack_type} into file at: {db_path}")
        
    except Exception as e:
        print(f"[CRITICAL DATABASE ERROR] Failed to save attack log: {e}")
        
    finally:
        if conn:
            conn.close()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    user_ip = request.remote_addr
    current_time = time.time()

    if user_ip in login_attempts:
        ip_data = login_attempts[user_ip]

        if current_time < ip_data["lockout_until"]:
            time_left = int(ip_data["lockout_until"] - current_time)
            print(f"[RATE LIMIT] Blocked request from {user_ip}. Lockout active for {time_left}s.")
            return f"<h2>Access Denied: Too many failed login attempts. Try again in {time_left} seconds.</h2>", 429 # 429 is HTTP for Too Many Requests

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if detect_sqli(username):
            log_attack_to_db(attack_type="SQL Injection", payload=username, endpoint="/login")
            return "<h2>Access Denied: Malicious Activity Detected.</h2>", 403
            
        if detect_sqli(password):
            log_attack_to_db(attack_type="SQL Injection", payload=password, endpoint="/login")
            return "<h2>Access Denied: Malicious Activity Detected.</h2>", 403
        
        if detect_xss(username):
            log_attack_to_db(attack_type="Cross-Site Scripting (XSS)", payload=username, endpoint="/login")
            return "<h2>Access Denied: Malicious Activity Detected.</h2>", 403

        if detect_xss(password):
            log_attack_to_db(attack_type="Cross-Site Scripting (XSS)", payload=password, endpoint="/login")
            return "<h2>Access Denied: Malicious Activity Detected.</h2>", 403

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            if user_ip in login_attempts:
                del login_attempts[user_ip]
            session['logged_in'] = True # Give them the session "wristband"!
            print("[AUTH SUCCESS] Administrator logged in. Session granted.")
            return redirect('/dashboard') 
        
        print(f"[AUTH FAILURE] Invalid credentials submitted from IP: {user_ip}")
        
        if user_ip not in login_attempts:
            login_attempts[user_ip] = {"count": 1, "lockout_until": 0}
        else:
            login_attempts[user_ip]["count"] += 1
        
        if login_attempts[user_ip]["count"] >= 3:
            login_attempts[user_ip]["lockout_until"] = current_time + 30 # 30-second penalty time window
            login_attempts[user_ip]["count"] = 0 # Reset counter container
            log_attack_to_db(attack_type="Brute Force Attempt", payload=f"IP Locked out: {user_ip}", endpoint="/login")
            
            return "<h2>Access Denied: Too many failed attempts. You are locked out for 30 seconds.</h2>", 429
        
        return "<h3>Invalid Username or Password.</h3>", 401
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        print("[UNAUTHORIZED ACCESS] Attempt to access dashboard without active session!")
        return "<h2>Access Denied: Unauthorized. You must log in as Administrator first.</h2>", 401
    
    base_dir = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(base_dir, 'security_logs.db')
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute('SELECT id, timestamp, attack_type, payload, vulnerable_endpoint FROM attack_logs ORDER BY id DESC')
    all_logs = cursor.fetchall()

    print("\n=== SYSTEM DATABASE CHECK ===")
    print(f"RAW DATABASE LOGS: {all_logs}\n")
    
    conn.close()
    return render_template('dashboard.html', logs=all_logs)

@app.route('/logout')
def logout():
    session.clear() # Throw away the wristband
    print("[AUTH] Administrator logged out.")
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)