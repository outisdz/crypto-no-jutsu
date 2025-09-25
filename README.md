# PBKDF2 Key Tool

A command-line utility for securely deriving and verifying cryptographic keys using PBKDF2 (Password-Based Key Derivation Function 2) with SHA-256. Supports both key derivation and verification modes, with customizable parameters for security and flexibility.

## Features

- **Key Derivation**: Generate a secure Base64-encoded key from your password and a salt.
- **Key Verification**: Verify that a password and salt match a stored, previously derived key.
- **Customizable Parameters**: Configure key length and PBKDF2 iteration count for added security.
- **Interactive Prompts**: No passwords or salts exposed in command history; entered securely via prompts.
- **File Operations**: Save derived keys to a file, load stored keys from a file for verification.

## Requirements

- Python 3.7+
- [`cryptography`](https://cryptography.io/en/latest/) library

Install requirements:
```bash
pip install cryptography
```

## Usage

### Key Derivation

Generate a new Base64-encoded key using a password and salt:
```bash
python pbkdf2_key_tool.py --derive --length 128 --iterations 1200000
```
- You will be prompted to enter your salt and password.
- The derived key can be saved to a file or displayed on the screen.

### Key Verification

Verify a password against a stored key:
```bash
python pbkdf2_key_tool.py --verify --path path/to/stored_key.txt --length 128 --iterations 1200000
```
_or_
```bash
python pbkdf2_key_tool.py --verify --key "Base64KeyHere" --length 128 --iterations 1200000
```
- You will be prompted to enter the salt and password.
- The tool will confirm whether the password and salt match the stored key.

### Parameters

- `--length`: Length of the derived key in bytes (default: 128).
- `--iterations`: Number of PBKDF2 iterations (default: 1,200,000).
- `--key`: Provide the Base64-encoded key directly for verification.
- `--path`: Path to a file containing the Base64-encoded key for verification.
- `-v, --verify`: Enter verification mode.
- `-d, --derive`: Enter key derivation mode.

## Example Workflows

**Derive and save a new key:**
```bash
python pbkdf2_key_tool.py --derive
```
Follow prompts and choose to save the key to a file.

**Verify an existing key stored in a file:**
```bash
python pbkdf2_key_tool.py --verify --path derived_key.txt
```

## Security Notes

- Always use a strong, random salt for key derivation.
- Never share your password or salt.
- Store derived keys securely.
- Adjust iteration count and key length for your security requirements.

## License

MIT License

## Author

[@outisdz](https://github.com/outisdz)