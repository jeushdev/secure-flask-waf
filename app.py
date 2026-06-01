from flask import Flask, render_template, request
import re

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

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if detect_sqli(username) or detect_sqli(password):
            return "<h2>Access Denied: Malicious Activity Detected.</h2>", 403

        print(f"DEBUG: Login attempt with Username: {username}")
        return f"<h3>Attempted login for user: {username}. Backend received data!</h3>"
    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)