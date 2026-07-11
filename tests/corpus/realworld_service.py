# Labeled precision corpus — Python patterns sourced from the real-world
# validation run against flask (docs/dev/REALWORLD.md). Unannotated lines
# were live Stage 1 false positives before the CG-060 / CG-001 gates were
# tightened; the ratchet keeps them fixed.

import flask


def parse_payload():
    # Reading the incoming request is not an outgoing HTTP call.
    return flask.request.get_json()


def register_cleanup(request, reset_path):
    # pytest's `request` fixture shares its name with the HTTP client.
    request.addfinalizer(reset_path)


def load_user(db, user_id):
    # DB-API parameterized query — the SQL string is a constant.
    return db.execute("SELECT * FROM user WHERE id = ?", (user_id,))


def insert_user(db, username, pw_hash):
    db.execute(
        "INSERT INTO user (username, password) VALUES (?, ?)",
        (username, pw_hash),
    )


def find_user_unsafe(db, name):
    return db.execute("SELECT * FROM users WHERE name = '%s'" % name)  # codeguard-expect CG-001


def find_user_format(db, name):
    return db.execute("SELECT * FROM users WHERE name = '{}'".format(name))  # codeguard-expect CG-001
