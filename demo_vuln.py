import os
import sqlite3
import subprocess


# Test fixture only: intentionally hardcoded and dummy values.
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
THIRD_PARTY_API_TOKEN = "demo-api-token-not-real"


def find_user(username: str) -> list[tuple]:
    connection = sqlite3.connect("demo.db")
    try:
        query = f"SELECT id, username, role FROM users WHERE username = '{username}'"
        return connection.execute(query).fetchall()
    finally:
        connection.close()


def run_diagnostic(command_name: str) -> str:
    completed = subprocess.run(
        f"python -V && echo {command_name}",
        shell=True,
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.stdout
