import base64
import argparse
import math
import string
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass
import secrets


def parse_arguments():
    """
    Parse command-line arguments.
    Supports key verification or key derivation mode.
    """
    parser = argparse.ArgumentParser(description="PBKDF2 key derivation and verification tool")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-v', '--verify', action='store_true', help='Verify a password against a stored key')
    group.add_argument('-d', '--derive', action='store_true', help='Derive a new key from a password and salt')
    group.add_argument('-g', '--random', action='store_true', help='Generate random password')

    parser.add_argument('-k', '--key', type=str, help='Provide the Base85-encoded key directly')
    parser.add_argument('-p', '--path', type=str, help='Path to a file containing the Base85-encoded key')

    # Key derivation parameters
    parser.add_argument('-l', '--length', type=int, default=128, help='Length of the derived key (bytes)')
    parser.add_argument('-i', '--iterations', type=int, default=2_000_000, help='Number of PBKDF2 iterations')

    return parser.parse_args()


def gen_random_password(length: int) -> str:
    """
    Generate a strong random password with at least one lowercase,
    one uppercase, one digit, and one symbol.
    Uses secrets for cryptographic randomness.
    """
    if length < 4:
        raise ValueError("Password length must be at least 4")

    # Safer punctuation set (avoids problematic characters in shells/filenames)
    symbols = "!@#$%^&*()-_=+[]{};:,.<>?/|"

    # Ensure at least one char from each category
    categories = [secrets.choice(string.ascii_lowercase), secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits), secrets.choice(symbols), ]

    # Fill the rest randomly
    all_chars = string.ascii_letters + string.digits + symbols
    categories.extend(secrets.choice(all_chars) for _ in range(length - 4))

    # Shuffle to avoid predictable placement
    secrets.SystemRandom().shuffle(categories)

    return ''.join(categories)


def derive_key(key_length, iterations):
    """
    Derive a Base85-encoded key using PBKDF2 with SHA-256.
    Asks the user for a salt and password.
    """
    salt = getpass.getpass('Enter the salt: ').encode()
    password = getpass.getpass('Enter your password: ').encode()

    kdf = PBKDF2HMAC(hashes.SHA256(), length=key_length, salt=salt, iterations=iterations)
    derived_key_b85 = base64.b85encode(kdf.derive(password)).decode()
    return derived_key_b85


def verify_key(stored_key_b85: bytes, key_length, iterations):
    """
    Verify a stored Base85-encoded key against a password and salt.
    """
    salt = getpass.getpass('Enter the salt: ').encode()
    password = getpass.getpass('Enter your password: ').encode()

    kdf = PBKDF2HMAC(hashes.SHA256(), length=key_length, salt=salt, iterations=iterations)
    try:
        kdf.verify(password, base64.b85decode(stored_key_b85))
        print('✅ Key verification successful')
    except InvalidKey:
        print('❌ Invalid key - password or salt does not match')


def confirm_prompt(message: str) -> bool:
    """
    Prompt user for a yes/no confirmation.
    Only accepts 'y' or 'n' (case-insensitive).
    """
    while True:
        response = input(f"{message} [y/n]: ").strip().lower()
        if response in {"y", "n"}:
            return response == "y"
        print("Please enter 'y' or 'n'.")


def print_entropy(password: str):
    """Estimate Shannon entropy of a password in bits (assuming random choice)."""
    pool_size = len(set(password))
    if pool_size <= 1:
        print("Estimated entropy: 0.0 bits")
        return
    entropy = len(password) * math.log2(pool_size)
    print(f"Estimated entropy: {entropy:.2f} bits")

if __name__ == '__main__':
    args = parse_arguments()
    iterations = args.iterations
    key_length = args.length

    if args.verify:
        # Load the key from file or direct argument
        stored_key = ''
        if args.path:
            with open(args.path, 'r') as file:
                stored_key = file.read().strip()
        elif args.key:
            stored_key = args.key
        verify_key(stored_key.encode(), key_length, iterations)

    elif args.derive:
        # Derive a new key
        derived_key_b85 = derive_key(key_length, iterations)
        print_entropy(derived_key_b85)
        if confirm_prompt("Do you want to save the key to a file?"):
            file_path = input("Enter file name [default: derived_key.txt]: ").strip()
            if not file_path:
                file_path = "derived_key.txt"
            try:
                with open(file_path, 'w') as file:
                    file.write(derived_key_b85)
                print(f"✅ Key saved to {file_path}")
            except Exception as e:
                print(f"❌ Failed to save key: {e}")
        else:
            # Just display the key if not saving
            print("Derived key (Base85):", derived_key_b85)
    elif args.random:
        random_password = gen_random_password(key_length)
        print_entropy(random_password)
        if confirm_prompt("Do you want to save the key to a file?"):
            file_path = input("Enter file name [default: derived_key.txt]: ").strip()
            if not file_path:
                file_path = "derived_key.txt"
            try:
                with open(file_path, 'w') as file:
                    file.write(random_password)
                print(f"✅ Key saved to {file_path}")
            except Exception as e:
                print(f"❌ Failed to save key: {e}")
        else:
            # Just display the key if not saving
            print("random key:", random_password)
