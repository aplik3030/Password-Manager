from gui import PasswordManagerGUI, LoginWindow
from crypto_utils import check_master_password
import customtkinter as ctk

def on_login(master_password, root):
    verified, _ = check_master_password(master_password)
    if verified:
        # Assuming PasswordManagerGUI is adapted to customtkinter and requires a master password
        app = PasswordManagerGUI(root, master_password)
        root.deiconify()  # If the main window was hidden, show it.
    else:
        ctk.CTkMessageBox.show_error("Login Failed", "Access denied. Please try again.")
        # Consider also resetting the login form or closing the program based on your design.

def main():
    # Set the appearance mode for customtkinter globally, if desired
    ctk.set_appearance_mode("dark")  # 'light' is also available
    ctk.set_default_color_theme("dark-blue")  # You can choose a theme that matches your design

    root = ctk.CTk()  # Using customtkinter's CTk instead of ThemedTk
    root.title("Password Manager by Aplik")
    root.geometry("600x300")  # Adjust the size as needed
    root.withdraw()  # Hide the main window until login is successful

    # Pass root as an argument to on_login, ensure LoginWindow is using customtkinter if you've modified it
    login_window = LoginWindow(root, lambda mp: on_login(mp, root))

    root.mainloop()


if __name__ == "__main__":
    main()
