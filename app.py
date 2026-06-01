from flask import Flask, render_template, request

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        print(f"DEBUG: Login attempt with Username: {username}")
        return f"<h3>Attempted login for user: {username}. Backend received data!</h3>"
    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)