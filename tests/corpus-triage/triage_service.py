# Stage 2 triage corpus - see triage-app.ts for the annotation contract.

import subprocess

APP_VERSION = "2.4.1"


def load_session(request):
    return pickle.loads(request.data)  # codeguard-real CG-041


def ping(request):
    host = request.args["host"]
    return subprocess.run(f"ping -c 1 {host}", shell=True)  # codeguard-real CG-002


def find_marker(line, request):
    # str.find on a string; Stage 1 mistakes it for a Mongo query.
    return line.find(request.args)  # codeguard-fp CG-024


def changelog_url():
    # URL built from a hard-coded constant, not user input.
    return requests.get("https://updates.example.com/notes/" + APP_VERSION)  # codeguard-fp CG-060
