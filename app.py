from flask import Flask, render_template, request
import re
import sqlite3
import os

app = Flask(__name__)

def detect_sqli(user_input):
    if not user_input:
        return False
    
    lowercased_input = user_input.lower()

    sql_signatures = [
        "'",
        "--",
        "or 1=1",
        "union select"
    ]

    for signature in sql_signatures:
        if signature in lowercased_input:
            print(f"[ALERT] Security Violation! Detected SQLi Signature: '{signature}' in input: '{user_input}'")
            return True
    
    return False

def detect_xss(user_input):
    if not user_input:
        return False
    
    lowercased_input = user_input.lower()

    xss_signatures = [
        "<script>",
        "</script>",
        "javascript:",
        "onerror=",
        "onload="
    ]

    for signature in xss_signatures:
        if signature in lowercased_input:
            print(f"[ALERT] Security Violation! Detected XSS Signature: '{signature}'")
            return True
    
    if "<" in lowercased_input and ">" in lowercased_input:
        print(f"[ALERT] Security Violation! Detected HTML Tag Injection symbols '< >'")
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

        print(f"DEBUG: Login attempt with Username: {username}")
        return f"<h3>Attempted login for user: {username}. Backend received data!</h3>"
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
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

if __name__ == '__main__':
    app.run(debug=True)