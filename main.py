from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os


# Function to create a salt and hash a password
def hash_password(password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())  # Derive the key
    storage = urlsafe_b64encode(salt + key).decode()  # Store salt and key together
    return storage


# Function to verify a provided password against a stored hash
def verify_password(stored_password, provided_password):
    decoded = urlsafe_b64decode(stored_password.encode())
    salt = decoded[:16]  # Extract salt
    key = decoded[16:]  # Extract key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    try:
        kdf.verify(provided_password.encode(), key)
        return True  # Password match
    except Exception:
        return False  # Password does not match


# Main Program
if __name__ == "__main__":
    master_password = input("Set your master password: ")
    hashed_master_password = hash_password(master_password)
    print("Master password set and securely stored.")

    # For demonstration, let's verify the master password
    attempt_password = input("Enter your master password to unlock: ")
    if verify_password(hashed_master_password, attempt_password):
        print("Access granted.")
    else:
        print("Access denied.")