"""
decrypt_messages.py
Author: Indrajit Ghosh
Created On: Apr 20, 2025

An interactive script to decrypt RSA-encrypted messages using a private key.

Usage:
    1. Run the script.
    2. Enter the path to your RSA private key (.pem). Paths using `~` are supported.
    3. Paste the base64-encoded encrypted message when prompted. End input with an empty line.
    4. The decrypted message will be printed to the terminal.

Note:
    - The private key must be in PEM format.
    - The encrypted message must be base64-encoded.
    - The encryption must use OAEP padding with SHA-256 (as in the Flask app logic).

Dependencies:
    - This script depends on a `decrypt_with_private_key` function defined in utils.py
"""

import os
from utils import decrypt_with_private_key

def main():
    print("=== RSA Message Decryption Tool ===")
    private_key_path = os.path.expanduser(input("Enter the path to your private RSA key (.pem): ").strip())

    if not os.path.isfile(private_key_path):
        print(f"[Error] No file found at: {private_key_path}")
        return

    print("\nPaste the base64-encoded encrypted message (end with an empty line):")
    lines = []
    while True:
        line = input()
        if line.strip() == "":
            break
        lines.append(line.strip())

    encrypted_message = ''.join(lines)

    if not encrypted_message:
        print("[Error] No encrypted message received.")
        return

    try:
        decrypted_message = decrypt_with_private_key(private_key_path, encrypted_message)
        print("\n=== Decrypted Message ===")
        print(decrypted_message)
        print()
    except Exception as e:
        print(f"\n[Decryption Failed] {e}")

if __name__ == '__main__':
    main()
