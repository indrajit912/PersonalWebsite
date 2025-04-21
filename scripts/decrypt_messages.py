"""
decrypt_messages.py
Author: Indrajit Ghosh
Created On: Apr 20, 2025

An interactive script to decrypt hybrid RSA+AES encrypted messages using a private key.

Usage:
    1. Run the script.
    2. Enter the path to your RSA private key (.pem). Paths using `~` are supported.
    3. Paste the base64-encoded encrypted message (a JSON structure) when prompted. End input with an empty line.
    4. The decrypted message will be printed to the terminal.

Note:
    - The private key must be in PEM format.
    - The encrypted message must be base64-encoded JSON with AES + RSA hybrid encryption.
    - The `decrypt_with_private_key` function must handle this structure accordingly.

Dependencies:
    - This script depends on a `decrypt_with_private_key` function defined in utils.py
"""

import os
from utils import decrypt_with_private_key

def main():
    print("=== Hybrid RSA+AES Message Decryption Tool ===")
    key_path = input("Enter the path to your private RSA key (.pem): ").strip()
    key_path = os.path.expanduser(key_path)

    print("\nPaste the base64-encoded encrypted message (end with an empty line):")
    b64_blob = ""
    while True:
        line = input()
        if not line.strip():
            break
        b64_blob += line.strip()

    try:
        decrypted_text = decrypt_with_private_key(key_path, b64_blob)
        print("\nDecrypted message:")
        print(decrypted_text)
    except Exception as e:
        print(f"\n[Decryption Failed] {e}")

if __name__ == "__main__":
    main()
