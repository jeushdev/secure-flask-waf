import sqlite3

def setup_database():
    connection = sqlite3.connect('security_logs.db')
    cursor = connection.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attack_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            attack_type TEXT NOT NULL,
            payload TEXT NOT NULL,
            vulnerable_endpoint TEXT NOT NULL
        )
    ''')

    connection.commit()
    connection.close()
    print("[SUCCESS] security_logs.db initialized and attack_logs table created.")

if __name__ == '__main__':
    setup_database()