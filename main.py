from gui import PasswordManagerGUI, LoginWindow
from crypto_utils import check_master_password
import customtkinter as ctk

def on_login(master_password, root):
    verified, _ = check_master_password(master_password)
    if verified:
        app = PasswordManagerGUI(root, master_password)
        root.deiconify()
        return True
    else:
        print("Access denied. Please try again.")
        return False

def main():
    ctk.set_appearance_mode("light")
    root = ctk.CTk()
    root.title("Password Manager")
    root.withdraw()
    login_window = LoginWindow(root, lambda mp: on_login(mp, root))

    root.mainloop()


if __name__ == "__main__":
    main()
