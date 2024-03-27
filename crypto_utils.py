from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os

def hash_password(password):
    salt = os.urandom(16)
    print(f"Generated salt: {salt.hex()}")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())  # Derive the key
    print(f"Derived key: {key.hex()}")  # Print the derived key in hexadecimal
    storage = urlsafe_b64encode(salt + key).decode()  # Store salt and key together
    print(f"Stored (salt + key) encoded: {storage}")  # Print the base64 encoded salt + key
    return storage

# Function to verify a provided password against a stored hash
def verify_password(stored_password, provided_password):
    decoded = urlsafe_b64decode(stored_password.encode())
    print(f"Decoded stored value (salt + key): {decoded.hex()}")  # Print the decoded stored value in hexadecimal

    salt = decoded[:16]  # Extract salt
    key = decoded[16:]  # Extract key
    print(f"Extracted salt: {salt.hex()}")  # Print the extracted salt in hexadecimal
    print(f"Extracted key: {key.hex()}")  # Print the extracted key in hexadecimal

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    try:
        kdf.verify(provided_password.encode(), key)
        print("Provided password is correct.")  # Print success message
        return True
    except Exception:
        print("Provided password is incorrect.")  # Print failure message
        return False

def setup_master_password():
    master_password = input("Set your master password: ")
    hashed_master_password = hash_password(master_password)
    # Save the hashed master password to a file
    with open("master_password.txt", "w") as file:
        file.write(hashed_master_password)
    print("Master password set and securely stored.")

def check_master_password():
    try:
        with open("master_password.txt", "r") as file:
            stored_hash = file.read()
        master_password = input("Enter your master password to unlock: ")
        if verify_password(stored_hash, master_password):
            return master_password, False  # Not a new setup
        else:
            print("Access denied. Please try again.")
            return None, False
    except FileNotFoundError:
        print("No master password found. Please set up a new master password.")
        master_password = setup_master_password()
        return master_password, True  # New setup


def derive_key(master_password, salt=os.urandom(16)):
    """Derive a cryptographic key from the master password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key


def encrypt_password(user_password, key):
    """Encrypt the user password using the derived key."""
    f = Fernet(key)
    encrypted_password = f.encrypt(user_password.encode())
    return encrypted_password


def decrypt_password(encrypted_password, key):
    """Decrypt the user password using the derived key."""
    f = Fernet(key)
    try:
        decrypted_password = f.decrypt(encrypted_password).decode()
        return decrypted_password
    except InvalidToken:
        print("Invalid key - Unsuccessful decryption.")
        return None