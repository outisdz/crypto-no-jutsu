# 🔑 PBKDF2 Key Tool

A command-line utility for deriving and verifying cryptographic keys using PBKDF2 (SHA-256). Supports key generation, password verification, file saving/loading, and custom parameters.

## 🚀 Features

- 🔒 Derive secure keys from passwords and salt
- ✅ Verify passwords against stored keys
- 📝 Save/load Base64 keys from files
- ⚙️ Custom key length & iterations

## 🛠️ Usage

**Derive a key:**
```bash
python pbkdf2_key_tool.py --derive
```

**Verify a key:**
```bash
python pbkdf2_key_tool.py --verify --key "<Base64Key>"
```

**Options:**
- `--length`: Key length (bytes, default: 128)
- `--iterations`: PBKDF2 iterations (default: 1,200,000)
- `--key`: Base64 key for verification
- `--path`: File path for stored key

## 📦 Requirements

- Python 3.7+
- cryptography library (`pip install cryptography`)

## 🛡️ Security Tips

- Use strong, random salts
- Never share your password or salt