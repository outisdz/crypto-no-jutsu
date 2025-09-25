import base64
import argparse
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass


def parse_arguments():
    """
    Parse command-line arguments.
    Supports key verification or key derivation mode.
    """
    parser = argparse.ArgumentParser(description="PBKDF2 key derivation and verification tool")
    parser.add_argument('--key', type=str, help='Provide the Base64-encoded key directly')
    parser.add_argument('--path', type=str, help='Path to a file containing the Base64-encoded key')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-v', '--verify', action='store_true', help='Verify a password against a stored key')
    group.add_argument('-d', '--derive', action='store_true', help='Derive a new key from a password and salt')

    # Key derivation parameters
    parser.add_argument('--length', type=int, default=128, help='Length of the derived key (bytes)')
    parser.add_argument('--iterations', type=int, default=1_200_000, help='Number of PBKDF2 iterations')

    return parser.parse_args()


def derive_key(key_length, iterations):
    """
    Derive a Base64-encoded key using PBKDF2 with SHA-256.
    Asks the user for a salt and password.
    """
    salt = getpass.getpass('Enter the salt: ').encode()
    password = getpass.getpass('Enter your password: ').encode()

    kdf = PBKDF2HMAC(hashes.SHA256(), length=key_length, salt=salt, iterations=iterations)
    derived_key_b64 = base64.b64encode(kdf.derive(password)).decode()
    return derived_key_b64


def verify_key(stored_key_b64: bytes, key_length, iterations):
    """
    Verify a stored Base64-encoded key against a password and salt.
    """
    salt = getpass.getpass('Enter the salt: ').encode()
    password = getpass.getpass('Enter your password: ').encode()

    kdf = PBKDF2HMAC(hashes.SHA256(), length=key_length, salt=salt, iterations=iterations)
    try:
        kdf.verify(password, base64.b64decode(stored_key_b64))
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
        derived_key_b64 = derive_key(key_length, iterations)
        if confirm_prompt("Do you want to save the key to a file?"):
            file_path = input("Enter file name [default: derived_key.txt]: ").strip()
            if not file_path:
                file_path = "derived_key.txt"
            try:
                with open(file_path, 'w') as file:
                    file.write(derived_key_b64)
                print(f"✅ Key saved to {file_path}")
            except Exception as e:
                print(f"❌ Failed to save key: {e}")
        else:
            # Just display the key if not saving
            print("Derived key (Base64):", derived_key_b64)
