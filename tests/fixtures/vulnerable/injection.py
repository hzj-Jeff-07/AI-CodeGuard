# Vulnerable: SQL Injection (CG-001) - Python
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    return cursor.fetchone()

# Vulnerable: Command Injection (CG-002) - Python
import os
import subprocess

def run_command(user_input):
    os.system("ls " + user_input)

def ping_host(host):
    subprocess.call(f"ping -c 4 {host}", shell=True)

# Vulnerable: Insecure Deserialization (CG-041) - Python
import pickle
import yaml

def load_data(data):
    return pickle.loads(data)

def load_config(config_str):
    return yaml.load(config_str)

# Vulnerable: Cross-Site Scripting (CG-010) - Python
from django.utils.safestring import mark_safe

def render_comment(comment):
    return mark_safe(comment)

# Vulnerable: Insecure Randomness (CG-022) - Python
import random

def generate_password_reset_token():
    return random.choice(range(1000000))

# Vulnerable: Insecure Regular Expression / ReDoS (CG-023) - Python
import re

def is_valid_email(value):
    return re.compile(r"^([a-zA-Z0-9]+)+@").match(value)
