from openpyxl import Workbook, load_workbook
from openpyxl.utils.exceptions import InvalidFileException

def add_password_to_excel(site, username, encrypted_password, filename="passwords.xlsx"):
    """Add a new password entry to the Excel file."""
    try:
        wb = load_workbook(filename)
    except FileNotFoundError:
        wb = Workbook()
        sheet = wb.active
        sheet.append(["Site", "Username", "Password"])
    else:
        sheet = wb.active

    sheet.append([site, username, encrypted_password])
    wb.save(filename)
