from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
import os
import json
import base64
import secrets
import string
import tempfile
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import PasswordHasher

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
VAULT_DIR = "vaults"
os.makedirs(VAULT_DIR, exist_ok=True)
ph = PasswordHasher()

# ------------------ Crypto Functions ------------------

def generate_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(master_password.encode())

# ------------------ Utility Functions ------------------

def get_vault_path(username):
    return os.path.join(VAULT_DIR, f"{username}.json")

def load_vault(username):
    with open(get_vault_path(username), "r") as f:
        return json.load(f)

def save_vault(username, data):
    with open(get_vault_path(username), "w") as f:
        json.dump(data, f, indent=4)

# ------------------ Routes ------------------

@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        filepath = get_vault_path(username)

        if os.path.exists(filepath):
            flash("Username already exists.", "error")
            return redirect(url_for("register"))

        password_hash = ph.hash(password)
        salt = os.urandom(16)

        vault = {
            "master_hash": password_hash,
            "salt": base64.b64encode(salt).decode(),
            "entries": []
        }

        save_vault(username, vault)
        flash("Account created successfully.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        filepath = get_vault_path(username)

        if not os.path.exists(filepath):
            flash("User does not exist.", "error")
            return redirect(url_for("login"))

        vault = load_vault(username)

        try:
            if not ph.verify(vault["master_hash"], password):
                raise Exception("Bad password")
        except Exception:
            flash("Incorrect password.", "error")
            return redirect(url_for("login"))

        session["username"] = username
        session["password"] = password
        return redirect(url_for("dashboard"))

    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    password = session["password"]
    vault = load_vault(username)
    salt = base64.b64decode(vault["salt"])
    key = generate_key(password, salt)
    aesgcm = AESGCM(key)

    entries = []
    for i, entry in enumerate(vault["entries"]):
        try:
            nonce = base64.b64decode(entry["nonce"])
            ct = base64.b64decode(entry["password"])
            pt = aesgcm.decrypt(nonce, ct, None).decode()
            entries.append({"id": i, "site": entry["site"], "username": entry["username"], "password": pt})
        except Exception:
            entries.append({"id": i, "site": entry["site"], "username": entry["username"], "password": "[decryption error]"})

    return render_template("dashboard.html", entries=entries)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/add", methods=["GET", "POST"])
def add():
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        site = request.form["site"]
        uname = request.form["username"]
        pwd = request.form["password"]

        username = session["username"]
        password = session["password"]
        vault = load_vault(username)
        salt = base64.b64decode(vault["salt"])
        key = generate_key(password, salt)

        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, pwd.encode(), None)

        vault["entries"].append({
            "site": site,
            "username": uname,
            "password": base64.b64encode(ct).decode(),
            "nonce": base64.b64encode(nonce).decode()
        })

        save_vault(username, vault)
        flash("Entry added.", "success")
        return redirect(url_for("dashboard"))

    return render_template("add.html")

@app.route("/generate")
def generate():
    length = int(request.args.get("length", 16))
    use_symbols = request.args.get("symbols", "true").lower() == "true"
    chars = string.ascii_letters + string.digits
    if use_symbols:
        chars += "!@#$%^&*()-_=+[]{}|;:,.<>?/"

    pwd = ''.join(secrets.choice(chars) for _ in range(length))
    return jsonify({"password": pwd})

@app.route("/delete_entry/<int:entry_id>")
def delete_entry(entry_id):
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    vault = load_vault(username)
    if 0 <= entry_id < len(vault["entries"]):
        del vault["entries"][entry_id]
        save_vault(username, vault)
        flash("Entry deleted.", "success")
    return redirect(url_for("dashboard"))

@app.route("/delete_vault")
def delete_vault():
    if "username" in session:
        username = session["username"]
        path = get_vault_path(username)
        if os.path.exists(path):
            os.remove(path)
        session.clear()
        flash("Vault deleted.", "success")
    return redirect(url_for("login"))

@app.route("/export_vault")
def export_vault():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    vault = load_vault(username)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(vault, f, indent=4)
        temp_path = f.name

    return send_file(temp_path, as_attachment=True, download_name=f"vault-{username}.json")

@app.route("/import_vault", methods=["POST"])
def import_vault():
    if "username" not in session:
        return redirect(url_for("login"))

    uploaded = request.files.get("vault")
    if uploaded:
        username = session["username"]
        data = json.load(uploaded)
        save_vault(username, data)
        flash("Vault imported.", "success")

    return redirect(url_for("dashboard"))

if __name__ == "__main__":
    debug_mode = os.environ.get("PASSMAN_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode)
