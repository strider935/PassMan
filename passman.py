import os
import json
import base64
import getpass
import secrets
import string
import pyperclip  # ← new
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2 import PasswordHasher

def generate_password(length=16, use_symbols=True):
    chars = string.ascii_letters + string.digits
    if use_symbols:
        chars += "!@#$%^&*()-_=+[]{}|;:,.<>?/"

    return ''.join(secrets.choice(chars) for _ in range(length))

# Constants
VAULT_DIR = "vaults"
ph = PasswordHasher()

# ========== Cryptographic Utilities ==========

def hash_master_password(master_password):
    return ph.hash(master_password)

def verify_master_password(stored_hash, input_password):
    try:
        ph.verify(stored_hash, input_password)
        return True
    except Exception:
        return False

def generate_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(master_password.encode())

# ========== Account Management ==========

def create_account():
    username = input("Choose a username: ").strip()
    filepath = os.path.join(VAULT_DIR, f"{username}.json")

    if os.path.exists(filepath):
        print("❗ Account already exists.")
        return None

    os.makedirs(VAULT_DIR, exist_ok=True)
    master_password = getpass.getpass("Choose a master password: ")
    password_hash = hash_master_password(master_password)
    salt = os.urandom(16)

    with open(filepath, "w") as f:
        json.dump({
            "master_hash": password_hash,
            "salt": base64.b64encode(salt).decode(),
            "entries": []
        }, f)

    print("✅ Account created.")
    return username, master_password

def login_user():
    username = input("Username: ").strip()
    filepath = os.path.join(VAULT_DIR, f"{username}.json")

    if not os.path.exists(filepath):
        print("❗ No such user.")
        return None

    with open(filepath, "r") as f:
        vault = json.load(f)

    master_password = getpass.getpass("Master password: ")
    if not verify_master_password(vault["master_hash"], master_password):
        print("❗ Incorrect password.")
        return None

    return username, master_password

def login_or_create_account():
    while True:
        print("\n==== Welcome to PassMan ====")
        print("1. Login")
        print("2. Create Account")
        print("3. Exit")
        choice = input("> ")

        if choice == "1":
            result = login_user()
            if result:
                return result
        elif choice == "2":
            result = create_account()
            if result:
                return result
        elif choice == "3":
            exit(0)
        else:
            print("❗ Invalid choice.")

# ========== Vault Operations ==========

def add_entry(key, vault, site=None, username=None, password=None):
    if site is None:
        site = input("Site: ")
    if username is None:
        username = input("Username: ")
    if password is None:
        password = getpass.getpass("Password: ")

    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    encrypted_pw = aesgcm.encrypt(nonce, password.encode(), None)

    vault["entries"].append({
        "site": site,
        "username": username,
        "password": base64.b64encode(encrypted_pw).decode(),
        "nonce": base64.b64encode(nonce).decode()
    })

    print("✅ Entry added.")

def view_entries(key, vault):
    aesgcm = AESGCM(key)

    if not vault["entries"]:
        print("🔒 No entries stored.")
        return

    for entry in vault["entries"]:
        try:
            nonce = base64.b64decode(entry["nonce"])
            ct = base64.b64decode(entry["password"])
            pt = aesgcm.decrypt(nonce, ct, None).decode()
            print(f"\n📁 Site: {entry['site']}")
            print(f"👤 Username: {entry['username']}")
            print(f"🔑 Password: {pt}")
        except Exception as e:
            print(f"❗ Error decrypting entry: {e}")

def search_entries(key, vault, term):
    aesgcm = AESGCM(key)
    matches = []

    for entry in vault["entries"]:
        if term in entry["site"].lower() or term in entry["username"].lower():
            try:
                nonce = base64.b64decode(entry["nonce"])
                ct = base64.b64decode(entry["password"])
                pt = aesgcm.decrypt(nonce, ct, None).decode()
                matches.append((entry["site"], entry["username"], pt))
            except Exception as e:
                print(f"❗ Error decrypting entry: {e}")

    if not matches:
        print("🔍 No matching entries found.")
        return

    print(f"\n🔍 Found {len(matches)} match(es):")
    for site, user, pw in matches:
        print(f"\n📁 Site: {site}")
        print(f"👤 Username: {user}")
        print(f"🔑 Password: {pw}")

def delete_vault(username):
    filepath = os.path.join(VAULT_DIR, f"{username}.json")
    confirm = input("Are you sure you want to delete your vault? (yes/no): ")
    if confirm.lower() == "yes":
        os.remove(filepath)
        print("🗑️ Vault deleted.")
        return True
    else:
        print("❌ Cancelled.")
        return False

def export_vault(username):
    src = os.path.join(VAULT_DIR, f"{username}.json")
    dest = input("Enter filename to export to (e.g. backup.json): ").strip()

    try:
        with open(src, "r") as fsrc, open(dest, "w") as fdst:
            fdst.write(fsrc.read())
        print(f"✅ Vault exported to '{dest}'")
    except Exception as e:
        print(f"❗ Export failed: {e}")

def import_vault(username):
    dest = os.path.join(VAULT_DIR, f"{username}.json")
    src = input("Enter filename to import from: ").strip()

    if not os.path.exists(src):
        print("❗ File not found.")
        return

    confirm = input("⚠️ This will overwrite your existing vault. Continue? (yes/no): ").lower()
    if confirm != "yes":
        print("❌ Import cancelled.")
        return

    try:
        with open(src, "r") as fsrc, open(dest, "w") as fdst:
            fdst.write(fsrc.read())
        print(f"✅ Vault imported from '{src}'")
    except Exception as e:
        print(f"❗ Import failed: {e}")

# ========== User Session ==========

def user_menu(username, master_password):
    filepath = os.path.join(VAULT_DIR, f"{username}.json")
    with open(filepath, "r") as f:
        vault = json.load(f)

    salt = base64.b64decode(vault["salt"])
    key = generate_key(master_password, salt)

    while True:
        print(f"\n== Logged in as {username} ==")
        print("1. Add Entry")
        print("2. View Entries")
        print("3. Search Entries")
        print("4. Delete Vault")
        print("5. Generate Password")
        print("6. Export Vault")
        print("7. Import Vault")
        print("8. Logout")
        choice = input("> ")

        if choice == "1":
            add_entry(key, vault)
        elif choice == "2":
            view_entries(key, vault)

        elif choice == "3":
            search_term = input("Enter search term: ").lower()
            search_entries(key, vault, search_term)

        elif choice == "4":
            if delete_vault(username):
                break
        elif choice == "5":
            try:
                length = int(input("Password length (e.g. 16): "))
            except ValueError:
                print("❗ Invalid input.")
                continue
            use_symbols = input("Include symbols? (y/n): ").lower().startswith('y')
            pwd = generate_password(length, use_symbols)
            pyperclip.copy(pwd)
            print(f"\n🔐 Generated password copied to clipboard:\n>>> {pwd} <<<\n")

            save = input("Save this password to your vault now? (y/n): ").lower()
            if save == 'y':
                site = input("Site: ")
                username = input("Username: ")
                add_entry(key, vault, site, username, pwd)
        elif choice == "6":
            export_vault(username)
        elif choice == "7":
            import_vault(username)
        elif choice == "8":
            print("👋 Logged out.")
            break
        else:
            print("❗ Invalid choice.")

        with open(filepath, "w") as f:
            json.dump(vault, f)

# ========== Main Entry Point ==========

def main():
    while True:
        result = login_or_create_account()
        if result:
            username, master_password = result
            user_menu(username, master_password)

if __name__ == "__main__":
    main()
