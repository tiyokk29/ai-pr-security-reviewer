import os
import sqlite3


API_KEY = "sk_live_demo_not_a_real_key"
AWS_SECRET_ACCESS_KEY = "demo-aws-secret-not-real"


def find_user(username):
    connection = sqlite3.connect("users.db")
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return connection.execute(query).fetchall()


def run_command(user_input):
    os.system("ping " + user_input)
