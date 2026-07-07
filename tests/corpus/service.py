# Labeled precision corpus - realistic Flask-style service code.
# Ground truth annotated with trailing `codeguard-expect CG-XXX` comments.

import json
import subprocess
import yaml


def load_session(raw):
    return pickle.loads(raw)  # codeguard-expect CG-041


def load_config(path):
    with open("config.yml") as f:
        return yaml.safe_load(f)  # safe loader


def ping(host):
    return subprocess.run(f"ping -c 1 {host}", shell=True)  # codeguard-expect CG-002


def list_dir():
    # Argument-list form, no shell string interpolation - safe.
    return subprocess.run(["ls", "-la"])


def fetch_avatar(request):
    return requests.get("https://cdn.example.com/" + request.args["avatar"])  # codeguard-expect CG-060


def verify(token, key):
    return jwt.decode(token, key, options={"verify_signature": False})  # codeguard-expect CG-026


def run_plugin(request):
    exec(request.form["code"])  # codeguard-expect CG-003


def find_marker(line, request):
    # str.find with a whole request object is nonsense-but-harmless code; a
    # scanner without type info may mistake it for a Mongo query (FP trap).
    return line.find(request.args)


def parse_payload(raw):
    return json.loads(raw)  # safe deserializer
