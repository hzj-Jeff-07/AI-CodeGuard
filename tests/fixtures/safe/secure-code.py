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

# Safe: mark_safe on a fixed literal, not attacker-controlled input
from django.utils.safestring import mark_safe

def render_banner():
    return mark_safe("<b>Welcome</b>")

# Safe: cryptographic RNG for a reset token
import secrets

def generate_password_reset_token():
    return secrets.token_hex(16)

# Safe: no nested/overlapping quantifiers
import re

def is_valid_email(value):
    return re.compile(r"^[a-zA-Z0-9]+@").match(value)

# Safe: querying by a specific validated field, not the whole request body
def login(users, username):
    return users.find_one({"username": username})

# Safe: redirect target is a fixed, known path
def go_to_login():
    return redirect("/login")
