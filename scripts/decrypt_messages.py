"""
Decryption Utility for Whisper Messages
=======================================

This script provides a secure mechanism to handle RSA private keys used to 
decrypt Whisper messages or attachments. It encrypts the RSA private key using 
GPG symmetric encryption (AES256) with a user-defined passphrase and stores the 
encrypted key in the user's home directory (`~/.keys/`). The passphrase is stored 
securely as a SHA-256 hash for verification purposes. Optionally, the passphrase 
can also be saved to a connected USB drive for easier retrieval.

Author:
-------
Indrajit Ghosh  
Created on: April 21, 2025
Modified on: Jun 19, 2025

Commands:
---------
  decrypt --message    Decrypt a message
  decrypt --attachment Decrypt a file attachment
  change-passphrase    Change your passphrase
  help                 Show command list and usage


Features:
---------
1. **Secure Key Storage**:
   - Encrypts the RSA private key (`.pem`) using GPG with AES256.
   - Stores the encrypted key as `~/.keys/rsa_private_key.pem.gpg`.
   - Stores a hashed version of the passphrase locally to verify future entries.

2. **Decryption of Messages or Files**:
   - Prompts the user to provide a passphrase to decrypt the stored private key.
   - Supports decryption of encrypted message JSON (base64) or encrypted file attachments.
   - Uses utility functions (`decrypt_with_private_key`, `decrypt_file_with_private_key`) for actual decryption logic.

3. **Passphrase Management**:
   - Provides functionality to change the passphrase used to protect the RSA key.
   - Uses `getpass` to securely collect user input without echoing it to the terminal.
   - Verifies passphrase integrity using SHA-256 hashing.
   - Optionally saves the passphrase to a USB flashdrive (e.g., `/media/<user>/Indrajit/.secret_keys/.whisper_passphrase`) 
   for automatic loading.

4. **USB flashdrive Integration**:
   - If a flashdrive labeled `Indrajit` is connected, the script checks for an existing saved passphrase.
   - If found, the passphrase is automatically loaded and validated.

Usage:
------
1. On first use, the user will be prompted to provide their RSA private key and a passphrase.
2. The private key is then encrypted and stored securely.
3. On subsequent uses, the user can decrypt a Whisper message or attachment by:
   - Providing the passphrase manually, or
   - Allowing the script to retrieve it from a connected flashdrive.
4. The script offers to decrypt either a JSON-based message or a file attachment.
"""
import subprocess
from pathlib import Path
import sys
import getpass

import click

from utils import decrypt_with_private_key, decrypt_file_with_private_key, is_flashdrive_connected, sha256_hash

DEFAULT_KEYS_DIR = Path.home() / ".keys"
PASSPHRASE_HASH_FILE = DEFAULT_KEYS_DIR / "passphrase_hash"
FLASHDRIVE_LABEL = "Indrajit"
FLASHDRIVE_SECRET_DIR_NAME = ".secret_keys"
FLASHDRIVE_PASSPHRASE_FILENAME = ".whisper_passphrase"

def _verify_passphrase_hash(passphrase: str, hash_file: Path):
    """
    Verifies that the SHA-256 hash of the given passphrase matches
    the stored hash in the specified hash filFLASHDRIVE
        passphrase (str): The passphrase to verify.
        hash_file (Path): Path to the file containing the stored hash.

    Returns:
        bool: True if hash matches, False otherwise.
    """
    if not hash_file.exists():
        # Save the hash
        PASSPHRASE_HASH_FILE.write_text(sha256_hash(passphrase), encoding='utf-8')
        print("[Info] Password hash saved for future use.\n")
        return True

    stored_hash = hash_file.read_text(encoding='utf-8').strip()
    computed_hash = sha256_hash(passphrase)

    return computed_hash == stored_hash


def _prompt_passphrase_with_confirmation(prompt="Enter passphrase", confirm_prompt="Confirm passphrase"):
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

def _load_passphrase_from_flashdrive():
    flashdrive_path = is_flashdrive_connected(label=FLASHDRIVE_LABEL)
    secret_dir_name = FLASHDRIVE_SECRET_DIR_NAME
    passphrase_file_name = FLASHDRIVE_PASSPHRASE_FILENAME
    
    passphrase = secret_dir = passphrase_file = None

    if flashdrive_path:
        secret_dir = Path(flashdrive_path) / secret_dir_name
        passphrase_file = secret_dir / passphrase_file_name

        if passphrase_file.is_file():
            try:
                passphrase = passphrase_file.read_text(encoding='utf-8').strip()

                # Check whether this is valid passphrase or not
                if not _verify_passphrase_hash(passphrase, PASSPHRASE_HASH_FILE):
                    passphrase = None
                else:
                    print("[Info] Passphrase loaded from flashdrive.\n")
            except Exception as e:
                print(f"[Warning] Could not read passphrase file: {e}")
    
    return passphrase, flashdrive_path, secret_dir, passphrase_file


def _prompt_passphrase_from_user_and_get_keypath(encrypted_key_path):
    """
    Attempt to load the passphrase for Whisper messages.
    
    If a USB drive named 'Indrajit' is connected and contains the file
    `.secret_keys/.whisper_passphrase`, load the passphrase from it.
    Otherwise, prompt the user to enter the passphrase manually.

    If the flashdrive is connected but the passphrase is not saved,
    offer to save it securely for future use.

    Parameters:
        encrypted_key_path (str or Path): Path to the encrypted private key.

    Returns:
        Path: Path to the decrypted private key.

    Exits the program if decryption fails.
    """
    print("-" * 30 + " Decryption " + "-" * 30)

    passphrase, flashdrive_path, secret_dir, passphrase_file = _load_passphrase_from_flashdrive()

    if not passphrase:
        # Prompt user for passphrase
        passphrase = getpass.getpass("\nEnter passphrase to decrypt the private key: ").strip()

        # Offer to save to flashdrive if connected
        if flashdrive_path:
            save_choice = input("Do you want to save this passphrase to your flashdrive for future use? [y/N]: ").strip().lower()
            if save_choice == 'y':
                try:
                    secret_dir.mkdir(parents=True, exist_ok=True)
                    passphrase_file.write_text(passphrase, encoding='utf-8')
                    print(f"[Info] Passphrase saved to: {passphrase_file}\n\n")
                except Exception as e:
                    print(f"[Error] Failed to save passphrase to flashdrive: {e}")

    decrypted_key_path = _decrypt_private_key_with_gpg(encrypted_key_path, passphrase)

    if not decrypted_key_path:
        print("\n[Error] Failed to decrypt the private key.")
        sys.exit(1)

    return decrypted_key_path

def change_passphrase():
    """
    Allows the user to change the passphrase protecting the encrypted private key.
    """
    encrypted_key_path = DEFAULT_KEYS_DIR / "rsa_private_key.pem.gpg"

    if not encrypted_key_path.exists():
        print(f"[Error] Encrypted private key not found at {encrypted_key_path}")
        sys.exit(1)

    # Step 1: Get current passphrase and verify hash
    # If the flashdrive is connected check it first
    current_passphrase, _, _, _ = _load_passphrase_from_flashdrive()
    
    if current_passphrase is None:
        current_passphrase = getpass.getpass("Enter current passphrase: ").strip()

    if not _verify_passphrase_hash(current_passphrase, PASSPHRASE_HASH_FILE):
        print("[Error] Incorrect current passphrase.")
        sys.exit(1)
    
    # Step 2: Prompt for new passphrase
    new_passphrase = _prompt_passphrase_with_confirmation("Enter new passphrase", "Confirm new passphrase")

    # Step 3: Decrypt the private key
    decrypted_key_path = _decrypt_private_key_with_gpg(encrypted_key_path, current_passphrase)

    if not decrypted_key_path or not decrypted_key_path.exists():
        print("[Error] Failed to decrypt the private key.")
        sys.exit(1)

    # Step 4: Re-encrypt the private key using the new passphrase
    encrypted_path = _encrypt_private_key_with_gpg(decrypted_key_path, new_passphrase)

    if not encrypted_path:
        print("[Error] Failed to re-encrypt private key.")
        sys.exit(1)

    print("[Success] Passphrase changed successfully.")
    return decrypted_key_path

def _encrypt_private_key_with_gpg(private_key_path, passphrase):
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

        # Save the passphrase hash
        PASSPHRASE_HASH_FILE.write_text(sha256_hash(passphrase), encoding='utf-8')

        # Save the passphrase to the flashdrive if connected
        flashdrive_path = is_flashdrive_connected(label=FLASHDRIVE_LABEL)
        secret_dir_name = FLASHDRIVE_SECRET_DIR_NAME
        passphrase_file_name = FLASHDRIVE_PASSPHRASE_FILENAME

        if flashdrive_path:
            secret_dir = Path(flashdrive_path) / secret_dir_name
            passphrase_file = secret_dir / passphrase_file_name

            passphrase_file.write_text(passphrase, encoding='utf-8')
            print(f"[Info] Passphrase saved to: {passphrase_file}\n\n")


        return encrypted_key_path
    except subprocess.CalledProcessError as e:
        print(f"[Error] Failed to encrypt private key: {e}")
        return None

def _decrypt_private_key_with_gpg(encrypted_key_path, passphrase):
    """
    Decrypts the given encrypted RSA private key file using GPG.

    Before decryption, verifies that the SHA-256 hash of the given passphrase
    matches the one stored in PASSPHRASE_HASH_FILE. If not, exits with an error.

    Args:
        encrypted_key_path (Path): Path to the encrypted private key file (.gpg).
        passphrase (str): Passphrase used for decryption.

    Returns:
        Path or None: Path to the decrypted private key file if successful, else None.
    """
    # --- Step 1: Verify passphrase hash ---
    if not _verify_passphrase_hash(passphrase, PASSPHRASE_HASH_FILE):
        print("[Error] Passphrase verification failed: hash mismatch.")
        sys.exit(1)

    # --- Step 2: Decrypt using GPG ---
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
    
def _get_encrypted_key_path():
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
        
        passphrase = _prompt_passphrase_with_confirmation("Enter passphrase to encrypt the private key", "Confirm passphrase")
        
        encrypted_key_path = _encrypt_private_key_with_gpg(private_key_path, passphrase)
        
        if not encrypted_key_path:
            print("[Error] Encryption failed.")
            sys.exit(1)
        
        print(f"\nPrivate key has been encrypted and stored at: {encrypted_key_path}")
        print("Remember this passphrase for future use!")

    return encrypted_key_path
    
def decrypt_message(encrypted_key_path):
    print("\nPaste the content of the message.json file (end with an empty line):")
    b64_blob = ""
    while True:
        line = input()
        if not line.strip():
            break
        b64_blob += line.strip()

    try:
        # Get the key_path
        key_path = _prompt_passphrase_from_user_and_get_keypath(encrypted_key_path)
        decrypted_text = decrypt_with_private_key(str(key_path), b64_blob)
        print("\n\nDecrypted message:")
        print(decrypted_text)
        return key_path

    except Exception as e:
        print(f"\n[Decryption Failed] {e}")

def decrypt_attachment(encrypted_key_path, encrypted_file_path=None):
    try:
        # Get the key_path
        key_path = _prompt_passphrase_from_user_and_get_keypath(encrypted_key_path)

        decrypted_file_path = decrypt_file_with_private_key(
            private_key_path=str(key_path), 
            encrypted_file_path=encrypted_file_path,
            output_dir=encrypted_file_path.parent
        )
        print(f"\nDecrypted file saved as: {decrypted_file_path}")

        return key_path

    except Exception as e:
        print(f"\n[Decryption Failed] {e}")

def _cleanup_key(key_path):
    try:
        key_path.unlink()
        click.secho("[✓] Decrypted private key removed from disk.", fg="green")
    except Exception as e:
        click.secho(f"[!] Warning: Failed to delete decrypted private key: {e}", fg="yellow")


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """
    🔐 Whisper Message Decryption Utility

    Author: Indrajit Ghosh
    Last modified: Jun 19, 2025
    """
    click.secho("=== Decryption Utility For Whisper Messages ===", fg="cyan", bold=True)
    click.secho("Author: Indrajit Ghosh", fg="magenta")
    click.secho("Last modified: Jun 19, 2025\n", fg="magenta")

    if ctx.invoked_subcommand is None:
        click.secho("Use one of the following commands:", fg="blue", bold=True)
        click.echo("  decrypt --message    Decrypt a message")
        click.echo("  decrypt --attachment Decrypt a file attachment")
        click.echo("  change-passphrase    Change your passphrase")
        click.echo("  help                 Show command list and usage")
        click.echo("\nRun with --help after any command for more options.")


@cli.command("decrypt")
@click.option("--message", "-m", is_flag=True, help="Decrypt an encrypted message (JSON data)")
@click.option("--attachment", "-a", is_flag=True, help="Decrypt an encrypted attachment (file)")
def decrypt_cmd(message, attachment):
    """Decrypt a message or attachment."""
    encrypted_key_path = _get_encrypted_key_path()

    if message:
        key_path = decrypt_message(encrypted_key_path)

    elif attachment:
        while True:
            raw_path = click.prompt("Enter the path to the encrypted file (e.g. ~/instance/encrypted_attachments/xyz.enc)")
            file_path = Path(raw_path).expanduser()
            if file_path.exists() and file_path.is_file():
                break
            click.secho("❌ Invalid file path. Please try again.", fg="red")

        key_path = decrypt_attachment(
            encrypted_key_path=encrypted_key_path,
            encrypted_file_path=file_path
        )
    else:
        click.secho("❌ Please specify either --message or --attachment.", fg="red")
        return

    _cleanup_key(key_path)


@cli.command("change-passphrase")
def change_passphrase_cmd():
    """Change your encrypted private key passphrase."""
    key_path = change_passphrase()
    _cleanup_key(key_path)


if __name__ == "__main__":
    cli()
