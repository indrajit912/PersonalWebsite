# Some utility functions
#
# Author: Indrajit Ghosh
#
# Date: Nov 15, 2023
#
import os
import json
import uuid
import base64
import random
import hashlib
from pathlib import Path
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

def format_size(size):
    for unit in ['bytes', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"

def generate_otp():
    """Generate a random 6-digit OTP (One-Time Password).

    Returns:
        str: A string representing the randomly generated OTP.

    Example:
        >>> generate_otp()
        '657432'
    """
    return str(random.randint(100000, 999999))

def sha256_hash(raw_text):
    """Hash the given text using SHA-256 algorithm.

    Args:
        raw_text (str): The input text to be hashed.

    Returns:
        str: The hexadecimal representation of the hashed value.

    Example:
        >>> sha256_hash('my_secret_password')
        'e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4'
    """
    hashed = hashlib.sha256(raw_text.encode()).hexdigest()
    return hashed


def convert_zip_to_base64(file_path):
    """
    Convert a ZIP file to a base64-encoded data URL.

    Parameters:
    - file_path (str): The path to the ZIP file.

    Returns:
    str: The base64-encoded data URL for the ZIP file.
    """
    with open(file_path, "rb") as file:
        zip_data = file.read()
        base64_data = base64.b64encode(zip_data).decode('utf-8')
        return f"data:application/zip;base64,{base64_data}"


def convert_utc_to_ist(utc_datetime_str):
    """
    Convert a UTC datetime string to Indian Standard Time (IST) format.

    Args:
        utc_datetime_str (str): A string representing a UTC datetime in the format '%Y-%m-%d %H:%M:%S'.

    Returns:
        str: A string representing the datetime in IST format, e.g., 'Dec 13, 2023 07:06 AM IST'.

    Example:
        >>> convert_utc_to_ist('2023-12-13 07:06:16')
        'Dec 13, 2023 07:06 AM IST'
    """
    # Convert string to datetime object
    utc_datetime = datetime.strptime(utc_datetime_str, "%Y-%m-%d %H:%M:%S")

    # Define UTC and IST timezones
    utc_timezone = timezone.utc
    ist_timezone = timezone(timedelta(hours=5, minutes=30))

    # Convert UTC datetime to IST
    ist_datetime = utc_datetime.replace(tzinfo=utc_timezone).astimezone(ist_timezone)

    # Format datetime in the desired string format
    formatted_datetime = ist_datetime.strftime("%b %d, %Y %I:%M %p IST")

    return formatted_datetime


def encrypt_with_public_key(public_key_path: str, plaintext: str):
    """
    Hybrid encryption using AES for the data and RSA to encrypt the AES key.
    Returns a JSON string with base64-encoded encrypted AES key, IV, and ciphertext.
    """
    # Load RSA public key
    with open(public_key_path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    # Generate AES key and IV
    aes_key = os.urandom(32)  # AES-256
    iv = os.urandom(16)       # AES block size for CBC mode

    # Pad the plaintext to be a multiple of 16 bytes
    pad_len = 16 - len(plaintext.encode('utf-8')) % 16
    padded_plaintext = plaintext + chr(pad_len) * pad_len

    # Encrypt plaintext with AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext.encode('utf-8')) + encryptor.finalize()

    # Encrypt AES key with RSA public key
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Return the entire JSON object as a base64 string (single-line encoded blob)
    raw_json = json.dumps({
        'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8'),
        'iv': base64.b64encode(iv).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
    })
    return base64.b64encode(raw_json.encode('utf-8')).decode('utf-8')


def decrypt_with_private_key(private_key_path: str, b64_blob: str, password: bytes = None):
    """
    Decrypts a base64-encoded JSON blob containing:
        - 'encrypted_key': RSA-encrypted AES key
        - 'iv': AES IV
        - 'ciphertext': AES-encrypted message

    Returns:
        Decrypted plaintext (str)
    """

    # Step 1: Decode base64-encoded blob to get JSON string
    try:
        json_string = base64.b64decode(b64_blob).decode('utf-8')
    except Exception as e:
        raise ValueError(f"Failed to decode base64 blob: {e}")

    # Step 2: Parse the JSON string
    try:
        encrypted_data = json.loads(json_string)
    except Exception as e:
        raise ValueError(f"Failed to parse JSON: {e}")

    # Step 3: Decode individual fields
    try:
        encrypted_key = base64.b64decode(encrypted_data['encrypted_key'])
        iv = base64.b64decode(encrypted_data['iv'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
    except Exception as e:
        raise ValueError(f"Failed to base64-decode fields: {e}")

    # Step 4: Load private RSA key
    with open(os.path.expanduser(private_key_path), 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=password,
            backend=default_backend()
        )

    # Step 5: Decrypt AES key using RSA
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Step 6: Decrypt message using AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Step 7: Remove padding (PKCS#7)
    pad_len = padded_plaintext[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding.")
    plaintext = padded_plaintext[:-pad_len]

    return plaintext.decode('utf-8')

def encrypt_file_with_public_key(public_key_path: str, input_file_path: str, output_dir: str):

    # Load the file data
    with open(input_file_path, 'rb') as f:
        file_data = f.read()

    # Encrypt the file content as text encryption
    encrypted_content = encrypt_with_public_key(public_key_path, file_data.decode('latin1'))

    # Encrypt the filename
    original_filename = Path(input_file_path).name
    encrypted_filename = encrypt_with_public_key(public_key_path, original_filename)

    # Save encrypted file
    output_path = os.path.join(output_dir, f"{uuid.uuid4()}.enc")
    with open(output_path, 'w') as f:
        json.dump({
            'encrypted_filename': encrypted_filename,
            'encrypted_content': encrypted_content
        }, f)

    return output_path

def decrypt_file_with_private_key(private_key_path: str, encrypted_file_path: str, output_dir: str, password: bytes = None):
    # Load encrypted data
    with open(encrypted_file_path, 'r') as f:
        data = json.load(f)

    # Decrypt filename and content
    decrypted_filename = decrypt_with_private_key(private_key_path, data['encrypted_filename'], password)
    decrypted_content = decrypt_with_private_key(private_key_path, data['encrypted_content'], password)

    # Save to output
    output_path = os.path.join(output_dir, decrypted_filename)
    with open(output_path, 'wb') as f:
        f.write(decrypted_content.encode('latin1'))

    return output_path
