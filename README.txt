# PassMan

**PassMan** is a secure, offline password manager built with Python. It offers both a clean terminal interface and a modern browser-based GUI for securely managing your passwords without relying on any cloud services.

## 🔐 Features

- Secure master-password login with Argon2
- AES-GCM encryption of credentials
- Unique per-entry encryption nonces
- Store, view, search, delete, import, and export entries
- Local-only vault stored in JSON format
- Password generator with clipboard copy
- Two interfaces:
  - `passman.py`: CLI (Terminal) version
  - `gui.py`: Web-based Flask GUI version

## 📂 Project Structure

```
passman/
├── vaults/                 # Encrypted user vaults (ignored by git)
├── templates/              # HTML templates for the GUI
├── static/                 # (Optional) static assets like CSS
├── passman.py              # Terminal version
├── gui.py                  # Flask GUI version
├── .env.example            # Sample environment config
├── .gitignore
├── requirements.txt
├── README.md
├── CONTRIBUTING.md
└── LICENSE
```

## 📦 Requirements

- Python 3.8+
- Flask
- Cryptography
- Argon2-CFFI
- Pyperclip (CLI only)


## 🖥️ Running the Terminal Version

python passman.py

You'll be prompted to log in or create an account. Use the menu to manage entries.

## 🌐 Running the GUI Version

python gui.py

Then visit [http://127.0.0.1:5000](http://127.0.0.1:5000)

## 🛡️ Security Design

- Master passwords are hashed with Argon2
- AES-GCM provides authenticated encryption
- Keys are derived from master password and per-user salt using PBKDF2-HMAC-SHA256
- Vault is stored locally in `vaults/<username>.json`
- All cryptographic secrets (keys, nonces, salt) are stored in base64 format

## ⚠️ Important Notes

- Designed for local, **personal use** only — not for multi-user or production deployments
- Ensure your vault file is backed up securely
- Never expose this app to the internet without proper hardening

## 📄 License

This project is licensed under the MIT License.

## 🙌 Contributions

See [CONTRIBUTING.txt]