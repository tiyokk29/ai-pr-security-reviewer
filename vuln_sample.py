import os
import sqlite3

AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLEHARDCODED123"

def get_user(user_id):
    conn = sqlite3.connect("users.db")
    return conn.execute(f"SELECT * FROM users WHERE id = '{user_id}'").fetchall()

def run_ping(host):
    os.system("ping -c 1 " + host)
