"""
Hybrid RSA+AES Decryption Utility

Author: Indrajit Ghosh
Created On: Apr 21, 2025

This script assists in securely managing and using RSA private keys for hybrid
encryption/decryption workflows. It includes:

1. Encrypting a private RSA key using GPG with AES256 symmetric encryption.
2. Storing the encrypted key in the user's home directory (~/.keys/).
3. Decrypting the RSA private key when needed using a passphrase.
4. Accepting a base64-encoded encrypted message as input and decrypting it using the RSA key.

Sensitive passphrase inputs are masked using getpass for improved security.
"""
import subprocess
from pathlib import Path
import sys
import os
import getpass
from utils import decrypt_with_private_key, decrypt_file_with_private_key

def prompt_passphrase_with_confirmation(prompt="Enter passphrase", confirm_prompt="Confirm passphrase"):
    """
    Prompts the user to enter and confirm a passphrase securely.

    Args:
        prompt (str): The initial prompt for the passphrase.
        confirm_prompt (str): The prompt for passphrase confirmation.

    Returns:
        str: The confirmed passphrase entered by the user.

    Raises:
        SystemExit: If the passphrases do not match after 3 attempts.
    """
    max_attempts = 3
    for attempt in range(max_attempts):
        passphrase = getpass.getpass(f"{prompt}: ").strip()
        confirm = getpass.getpass(f"{confirm_prompt}: ").strip()
        if passphrase == confirm:
            return passphrase
        else:
            print("[Error] Passphrases do not match. Please try again.")
    print("[Error] Maximum attempts reached. Exiting.")
    sys.exit(1)


def encrypt_private_key_with_gpg(private_key_path, passphrase):
    """
    Encrypts the given RSA private key file using GPG with AES256 encryption.

    Args:
        private_key_path (Path): Path to the RSA private key file.
        passphrase (str): Passphrase used for encryption.

    Returns:
        Path or None: Path to the encrypted key file if successful, else None.
    """
    encrypted_key_path = Path.home() / ".keys" / "rsa_private_key.pem.gpg"
    
    try:
        subprocess.run(
            [
                'gpg', '--batch', '--yes', '--passphrase', passphrase,
                '--symmetric', '--cipher-algo', 'AES256',
                '--output', str(encrypted_key_path), str(private_key_path)
            ],
            check=True
        )
        print(f"Private key encrypted and saved to: {encrypted_key_path}")
        return encrypted_key_path
    except subprocess.CalledProcessError as e:
        print(f"[Error] Failed to encrypt private key: {e}")
        return None

def decrypt_private_key_with_gpg(encrypted_key_path, passphrase):
    """
    Decrypts the given encrypted RSA private key file using GPG.

    Args:
        encrypted_key_path (Path): Path to the encrypted private key file (.gpg).
        passphrase (str): Passphrase used for decryption.

    Returns:
        Path or None: Path to the decrypted private key file if successful, else None.
    """
    decrypted_key_path = encrypted_key_path.with_suffix('')
    
    try:
        subprocess.run(
            [
                'gpg', '--batch', '--yes', '--passphrase', passphrase,
                '--output', str(decrypted_key_path), '--decrypt', str(encrypted_key_path)
            ],
            check=True
        )
        print(f"Private key decrypted and saved to: {decrypted_key_path}")
        return decrypted_key_path
    except subprocess.CalledProcessError as e:
        print(f"Failed to decrypt private key with GPG: {e}")
        return None

def main():
    """
    Entry point for the hybrid RSA+AES message decryption tool.
    Handles checking for encrypted key, encryption/decryption, and message decryption.
    """
    print("=== Hybrid RSA+AES Message Decryption Tool ===")

    DEFAULT_KEYS_DIR = Path.home() / ".keys" # This can be change to any pendrive too
    
    if not DEFAULT_KEYS_DIR.exists():
        DEFAULT_KEYS_DIR.mkdir()
    
    encrypted_key_path = DEFAULT_KEYS_DIR / "rsa_private_key.pem.gpg"
    
    if not encrypted_key_path.exists():
        print(f"\n[Info] No encrypted RSA key found at: {encrypted_key_path}")
        
        private_key_path_input = input("Enter the path to your RSA private key (.pem): ").strip()
        private_key_path = Path(private_key_path_input).expanduser()
        
        if not private_key_path.exists():
            print(f"[Error] Private key file not found at: {private_key_path}")
            sys.exit(1)
        
        passphrase = prompt_passphrase_with_confirmation("Enter passphrase to encrypt the private key", "Confirm passphrase")
        
        encrypted_key_path = encrypt_private_key_with_gpg(private_key_path, passphrase)
        
        if not encrypted_key_path:
            print("[Error] Encryption failed.")
            sys.exit(1)
        
        print(f"\nPrivate key has been encrypted and stored at: {encrypted_key_path}")
        print("Remember this passphrase for future use!")

    passphrase = getpass.getpass("\nEnter passphrase to decrypt the private key: ").strip()
        
    decrypted_key_path = decrypt_private_key_with_gpg(encrypted_key_path, passphrase)
    
    if not decrypted_key_path:
        print("\n[Error] Failed to decrypt the private key.")
        sys.exit(1)

    key_path = decrypted_key_path

    # Ask the user whether to decrypt email message (text) or email attachments (file)
    choice = input("\n\nWhat do you want to decrypt?\n1. Encrypted message (text)\n2. Encrypted attachment (file)\nEnter 1 or 2: ").strip()

    if choice == "1":
        print("\nPaste the base64-encoded encrypted message (end with an empty line):")
        b64_blob = ""
        while True:
            line = input()
            if not line.strip():
                break
            b64_blob += line.strip()

        try:
            decrypted_text = decrypt_with_private_key(str(key_path), b64_blob)
            print("\nDecrypted message:")
            print(decrypted_text)

        except Exception as e:
            print(f"\n[Decryption Failed] {e}")

    elif choice == "2":
        encrypted_file_path = Path(input("\nEnter the path to the encrypted file (e.g. instance/encrypted_attachments/xyz.enc): ").strip()).expanduser()

        try:
            decrypted_file_path = decrypt_file_with_private_key(
                private_key_path=str(key_path), 
                encrypted_file_path=encrypted_file_path,
                output_dir=encrypted_file_path.parent
            )
            print(f"\nDecrypted file saved as: {decrypted_file_path}")

        except Exception as e:
            print(f"\n[Decryption Failed] {e}")

    else:
        print("Invalid input. Please enter 1 or 2.")

if __name__ == "__main__":
    main()
