from crypto_utils import hash_password, verify_password, setup_master_password, check_master_password, derive_key, encrypt_password
from excel_utils import add_password_to_excel

def main():
    # Attempt to check the master password or set a new one if it doesn't exist
    master_password, is_new_setup = check_master_password()
    if not master_password:
        print("Exiting the application.")
        return

    # For a new setup, no need to verify again
    if not is_new_setup:
        attempt_password = input("Enter your master password to unlock: ")
        with open("master_password.txt", "r") as file:
            stored_hash = file.read()
        if not verify_password(stored_hash, attempt_password):
            print("Access denied.")
            return

    print("Access granted.")
    key = derive_key(master_password)

    # Main application logic for storing new passwords
    site = input("Enter the site name: ")
    username = input("Enter the username: ")
    user_password = input("Enter the password: ")

    encrypted_password = encrypt_password(user_password, key)
    add_password_to_excel(site, username, encrypted_password)
    print("Password added successfully.")

if __name__ == "__main__":
    main()
