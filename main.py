from crypto_utils import (hash_password, verify_password, setup_master_password, check_master_password, derive_key, encrypt_password)
from excel_utils import add_password_to_excel
from gui import PasswordManagerGUI, LoginWindow
from crypto_utils import check_master_password
from ttkthemes import ThemedTk



def on_login(master_password, root):
    verified, _ = check_master_password(master_password)
    if verified:
        app = PasswordManagerGUI(root, master_password)
        app.root.deiconify()  # If the main window was hidden, show it.
    else:
        print("Access denied. Please try again.")

def main():
    root = ThemedTk(theme="equilux")
    root.withdraw()  # Hide the main window until login is successful
    login_window = LoginWindow(root, lambda mp: on_login(mp, root))  # Pass root as an argument to on_login
    root.mainloop()

if __name__ == "__main__":
    main()