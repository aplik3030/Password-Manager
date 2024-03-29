import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
from ttkthemes import ThemedTk
from crypto_utils import derive_key, encrypt_password, decrypt_password
from excel_utils import add_password_to_excel
from openpyxl import load_workbook


class LoginWindow:
    def __init__(self, parent, login_function):
        self.top = tk.Toplevel(parent)
        self.top.title("Password Manager")
        self.login_function = login_function
        ctk.set_appearance_mode("dark")
        self.top.configure(bg='#333333')
        self.style = ttk.Style()
        self.style.theme_use('equilux')

        ctk_label = ctk.CTkLabel(self.top, text="Enter Master Password:")
        ctk_label.grid(row=0, column=0, padx=10, pady=10)
        self.password_entry = ttk.Entry(self.top, show="*")
        self.password_entry.grid(row=0, column=1, padx=10, pady=10)
        self.password_entry.focus()

        login_button = ttk.Button(self.top, text="Login", command=self.on_login)
        login_button.grid(row=1, column=0, columnspan=2, pady=10)

    def on_login(self):
        master_password = self.password_entry.get()
        self.login_function(master_password)
        self.top.destroy()


class PasswordManagerGUI:
    def __init__(self, root, master_password):
        self.root = root
        self.master_password = master_password
        self.key = derive_key(master_password)
        # Set customtkinter appearance mode
        ctk.set_appearance_mode("dark")  # Or "light", depending on your preference

        self.root.title("Password Manager by Aplik v1.0")

        # Setting the main window background color
        self.root.configure(bg='#333333')  # Example hex color for dark theme

        # Apply ttk theme for ttk widgets
        self.style = ttk.Style()
        # Assuming 'equilux' theme is available in your ttkthemes installation
        self.style.theme_use('equilux')
        # Configure ttk Style for widgets, e.g., for frames, labels, etc.
        self.style.configure("TLabel", background="#333333", foreground="white")  # Example configuration

        # Initialize UI after configuring styles
        self.create_widgets()

    def create_widgets(self):
        # Create and place the labels and entries for site name, username, password, and notes
        labels_texts = ["Site Name:", "Username:", "Password:", "Notes:"]
        self.entries = []
        for i, text in enumerate(labels_texts):
            label = ttk.Label(self.root, text=text)
            label.grid(column=0, row=i, padx=10, pady=10, sticky="W")
            entry = ttk.Entry(self.root)
            entry.grid(column=1, row=i, padx=10, pady=10, sticky="EW")
            self.entries.append(entry)

        # Button to add a password
        add_button = ctk.CTkButton(self.root, text="Add Password", command=self.add_password)
        add_button.grid(column=0, row=4, columnspan=2, padx=10, pady=20)

        add_button = ctk.CTkButton(self.root, text="View Passwords", command=self.view_passwords)
        add_button.grid(column=0, row=5, columnspan=2, padx=10, pady=20)

        # Make the second column fill the extra space
        self.root.grid_columnconfigure(1, weight=1)
        # Dropdown for sort order



    def add_password(self):
        site, username, password, notes = (entry.get() for entry in self.entries)
        encrypted_password, salt = encrypt_password(password,
                                                    self.master_password)  # Get both encrypted password and salt
        add_password_to_excel(site, username, encrypted_password, salt, notes)  # Pass salt to Excel utility

        # Clear entries after adding
        for entry in self.entries:
            entry.delete(0, tk.END)
        print(f"Password for {site} added successfully.")

    def view_passwords(self):
        filename = "passwords.xlsx"
        wb = load_workbook(filename)
        sheet = wb.active

        new_window = tk.Toplevel(self.root)
        new_window.title("View Stored Passwords")
        new_window.configure(bg='#333333')

        # Sorting controls inside new_window
        sort_order = ttk.Combobox(new_window, values=["Ascending", "Descending"], state="readonly")
        sort_order.grid(row=0, column=0, padx=10, pady=5)
        sort_order.set("Ascending")

        sort_button = ttk.Button(new_window, text="Sort", command=lambda: self.fill_passwords(
            sheet, new_window, "Platform", sort_order.get().lower()))
        sort_button.grid(row=0, column=1, padx=10, pady=5)

        # Initial call to display passwords without sorting
        self.fill_passwords(sheet, new_window)

    def fill_passwords(self, sheet, window, sort_by=None, sort_order='ascending'):
        # Starting from row 1 to leave room for headers
        row_offset = 1
        for widget in window.grid_slaves():
            if int(widget.grid_info()["row"]) > row_offset:
                widget.grid_forget()

        passwords = [
            (row[0], row[1], decrypt_password(row[2], self.master_password, row[3]), row[4] or "")
            for row in sheet.iter_rows(min_row=2, values_only=True)  # Assuming the first row is headers
        ]

        if sort_by:
            sort_index = ["Platform", "Username", "Notes"].index(sort_by)
            passwords.sort(key=lambda x: x[sort_index], reverse=(sort_order == 'descending'))

        for i, (site, username, decrypted_password, notes) in enumerate(passwords, start=row_offset + 1):
            tk.Label(window, text=site, bg='#333333', fg='white').grid(row=i, column=0, padx=10, pady=5, sticky='w')
            tk.Label(window, text=username, bg='#333333', fg='white').grid(row=i, column=1, padx=10, pady=5, sticky='w')
            tk.Label(window, text=decrypted_password, bg='#333333', fg='white').grid(row=i, column=2, padx=10, pady=5, sticky='w')
            tk.Label(window, text=notes, bg='#333333', fg='white').grid(row=i, column=3, padx=10, pady=5, sticky='w')

            delete_button = tk.Button(window, text="X", command=lambda row=i: self.confirm_delete(sheet, window, row))
            delete_button.grid(row=i, column=4, padx=10, pady=5, sticky='w')

    def confirm_delete(self, sheet, window, row):
        confirm = tk.messagebox.askyesno("Confirm Deleting", "This will delete the credentials, proceed?")
        if confirm:
            # Delete the row from the sheet
            sheet.delete_rows(row)

            # Save the workbook
            sheet.parent.save("passwords.xlsx")

            # Refresh the displayed passwords
            self.fill_passwords(sheet, window)



    def apply_sort(self, sheet, window, sort_by, sort_order):
        self.fill_passwords(sheet, window, sort_by=sort_by, sort_order=sort_order)

