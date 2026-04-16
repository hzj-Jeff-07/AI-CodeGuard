# Safe: Parameterized queries
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()

# Safe: No shell injection
import subprocess

def ping_host(host):
    subprocess.run(["ping", "-c", "4", host], check=True)

# Safe: Using safe loader
import yaml

def load_config(config_str):
    return yaml.safe_load(config_str)

# Safe: Normal function
def add(a, b):
    return a + b
