import os
import secrets

import psycopg
from flask import (
    Flask, abort, flash, redirect,
    render_template_string, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ["SECRET_KEY"],
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=64 * 1024,
)


def database():
    return psycopg.connect(os.environ["DATABASE_URL"])


@app.cli.command("init-db")
def init_db():
    with database() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(80) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS notes (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                content TEXT NOT NULL
            )
        """)
    print("Database tables are ready.")


@app.before_request
def protect_forms():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(32)
    if request.method == "POST":
        token = request.form.get("csrf", "")
        if not secrets.compare_digest(token, session["csrf"]):
            abort(400)


PAGE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Cloud Notes</title>
    <style>
        * { box-sizing: border-box; }
        body {
            margin: 0; padding: 40px 18px;
            background: #eef2f7; color: #172033;
            font-family: Arial, sans-serif;
        }
        main {
            max-width: 700px; margin: auto; padding: 30px;
            background: white; border-radius: 16px;
            box-shadow: 0 8px 30px #17203312;
        }
        h1 { color: #2454a6; margin-top: 0; }
        label { display: block; margin-top: 16px; }
        input, textarea {
            width: 100%; padding: 12px; margin: 8px 0;
            border: 1px solid #bac4d2; border-radius: 8px;
            font: inherit;
        }
        button {
            background: #2454a6; color: white;
            border: 0; border-radius: 8px;
            padding: 11px 18px; cursor: pointer;
        }
        a { color: #2454a6; }
        article {
            border-top: 1px solid #dce3ec;
            margin-top: 20px; padding-top: 16px;
        }
        .note { white-space: pre-wrap; overflow-wrap: anywhere; }
        .message { color: #9b3416; }
        footer { margin-top: 28px; color: #64748b; font-size: 14px; }
    </style>
</head>
<body>
<main>
    <h1>Cloud Notes</h1>
    <p>Your personal notebook in the cloud</p>

    {% for message in get_flashed_messages() %}
        <p class="message">{{ message }}</p>
    {% endfor %}

    {% if mode == "notes" %}
        <h2>My notes</h2>
        <p>Signed in as <strong>{{ session["username"] }}</strong></p>

        <form method="post" action="{{ url_for('logout') }}">
            <input type="hidden" name="csrf" value="{{ session['csrf'] }}">
            <button type="submit">Log out</button>
        </form>

        <form method="post" action="{{ url_for('notes') }}">
            <input type="hidden" name="csrf" value="{{ session['csrf'] }}">
            <label for="content">Write a new note</label>
            <textarea id="content" name="content" rows="4"
                      maxlength="2000" required></textarea>
            <button type="submit">Save note</button>
        </form>

        {% for note in notes %}
            <article>
                <p class="note">{{ note[1] }}</p>
                <form method="post"
                      action="{{ url_for('delete_note', note_id=note[0]) }}">
                    <input type="hidden" name="csrf"
                           value="{{ session['csrf'] }}">
                    <button type="submit">Delete note</button>
                </form>
            </article>
        {% else %}
            <p>No notes yet. Save your first note above.</p>
        {% endfor %}
    {% else %}
        <h2>{{ "Create account" if mode == "register" else "Log in" }}</h2>
        <form method="post">
            <input type="hidden" name="csrf" value="{{ session['csrf'] }}">
            <label for="username">Username</label>
            <input id="username" name="username"
                   minlength="3" maxlength="80" required>
            <label for="password">Password</label>
            <input id="password" type="password" name="password"
                   minlength="8" maxlength="128" required>
            <button type="submit">
                {{ "Register" if mode == "register" else "Log in" }}
            </button>
        </form>
        <p>
            <a href="{{ url_for('login') }}">Log in</a>
            &nbsp;|&nbsp;
            <a href="{{ url_for('register') }}">Create account</a>
        </p>
    {% endif %}

    <footer>CCEN 448 · Flask application · PostgreSQL database</footer>
</main>
</body>
</html>
"""


@app.get("/")
def home():
    return redirect(url_for("notes" if "user_id" in session else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not (3 <= len(username) <= 80 and 8 <= len(password) <= 128):
            flash("Use a username of 3–80 characters and a password of 8–128 characters.")
        else:
            try:
                with database() as connection:
                    connection.execute(
                        "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                        (username, generate_password_hash(password)),
                    )
            except psycopg.errors.UniqueViolation:
                flash("That username is already taken.")
            else:
                flash("Account created. You can now log in.")
                return redirect(url_for("login"))

    return render_template_string(PAGE, mode="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with database() as connection:
            user = connection.execute(
                "SELECT id, username, password_hash FROM users WHERE username = %s",
                (username,),
            ).fetchone()

        if user and check_password_hash(user[2], password):
            session.clear()
            session["user_id"] = user[0]
            session["username"] = user[1]
            session["csrf"] = secrets.token_hex(32)
            return redirect(url_for("notes"))

        flash("Incorrect username or password.")

    return render_template_string(PAGE, mode="login")


@app.route("/notes", methods=["GET", "POST"])
def notes():
    if "user_id" not in session:
        return redirect(url_for("login"))

    with database() as connection:
        if request.method == "POST":
            content = request.form.get("content", "").strip()
            if 1 <= len(content) <= 2000:
                connection.execute(
                    "INSERT INTO notes (user_id, content) VALUES (%s, %s)",
                    (session["user_id"], content),
                )
                flash("Note saved to PostgreSQL.")
            else:
                flash("Enter a note between 1 and 2000 characters.")
        else:
            saved_notes = connection.execute(
                "SELECT id, content FROM notes WHERE user_id = %s ORDER BY id DESC",
                (session["user_id"],),
            ).fetchall()

    if request.method == "POST":
        return redirect(url_for("notes"))

    return render_template_string(PAGE, mode="notes", notes=saved_notes)


@app.post("/notes/<int:note_id>/delete")
def delete_note(note_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    with database() as connection:
        connection.execute(
            "DELETE FROM notes WHERE id = %s AND user_id = %s",
            (note_id, session["user_id"]),
        )

    return redirect(url_for("notes"))


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))
