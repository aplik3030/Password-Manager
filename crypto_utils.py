from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os
from tkinter import messagebox


def hash_password(password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    storage = urlsafe_b64encode(salt + key).decode()
    return storage


def verify_password(stored_password, provided_password):
    decoded = urlsafe_b64decode(stored_password.encode())

    salt = decoded[:16]
    key = decoded[16:]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    try:
        kdf.verify(provided_password.encode(), key)
        return True
    except Exception:
        return False


def setup_master_password(master_password):
    hashed_master_password = hash_password(master_password)
    with open("master_password.txt", "w") as file:
        file.write(hashed_master_password)
    messagebox.showinfo("Setup Complete", "Master password has been successfully set.")


def check_master_password(master_password):
    try:
        with open("master_password.txt", "r") as file:
            stored_hash = file.read()
        is_correct = verify_password(stored_hash, master_password)
        if is_correct:
            print("Provided password is correct.")
            return True, False
        else:
            print("Provided password is incorrect.")
            return False, False
    except FileNotFoundError:
        print("No master password found. Setting up a new master password.")
        setup_master_password(master_password)
        return True, True


def derive_key(master_password, salt=None):
    """Derive a cryptographic key from the master password."""
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key, salt


def encrypt_password(user_password, master_password):
    key, salt = derive_key(master_password)
    f = Fernet(key)
    encrypted_password = f.encrypt(user_password.encode())
    return encrypted_password, salt.hex()


def decrypt_password(encrypted_password, master_password, salt):
    try:
        salt_bytes = bytes.fromhex(salt)
        key, _ = derive_key(master_password, salt=salt_bytes)
        f = Fernet(key)
        decrypted_password = f.decrypt(encrypted_password).decode()
        return decrypted_password
    except ValueError as e:
        print(f"Error converting salt from hex: {e}")

