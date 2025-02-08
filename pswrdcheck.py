import hashlib
import requests
import tkinter as tk
from tkinter import messagebox

# Function to check password strength
def check_password_strength(password):
    length = len(password)
    
    if length < 6:
        return "Weak ❌"
    elif length < 10:
        return "Moderate ⚠️"
    elif length >= 10 and any(char.isdigit() for char in password) and any(char.isupper() for char in password):
        return "Strong ✅"
    else:
        return "Moderate ⚠️"

# Function to check if password is leaked
def check_password_breach(password):
    sha1_password = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)

    if suffix in response.text:
        return "⚠️ Warning: This password has been leaked!"
    else:
        return "✅ This password is safe."

# Function to evaluate password and allow new inputs
def evaluate_password():
    password = entry.get().strip()

    if not password:
        messagebox.showwarning("Input Error", "Please enter a password.")
        return

    strength = check_password_strength(password)
    breach_status = check_password_breach(password)

    result_label.config(text=f"Strength: {strength}", fg="blue")
    breach_label.config(text=breach_status, fg="red" if "leaked" in breach_status else "green")

    # Clear input for new password entry
    entry.delete(0, tk.END)

# Function to toggle password visibility
def toggle_password():
    if show_password_var.get():
        entry.config(show="")  # Show password
    else:
        entry.config(show="*")  # Hide password

# GUI Setup
root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("500x450")
root.resizable(False, False)

tk.Label(root, text="Enter a Password:", font=("Arial", 12)).pack(pady=10)
entry = tk.Entry(root, show="*", width=30, font=("Arial", 12))
entry.pack(pady=5)

# Checkbox for showing/hiding password
show_password_var = tk.BooleanVar()
show_password_check = tk.Checkbutton(root, text="Show Password", variable=show_password_var, command=toggle_password)
show_password_check.pack(pady=8)

check_button = tk.Button(root, text="Check Password", command=evaluate_password, font=("Arial", 12), bg="#4CAF50", fg="white")
check_button.pack(pady=10)

result_label = tk.Label(root, text="", font=("Arial", 12))
result_label.pack()

breach_label = tk.Label(root, text="", font=("Arial", 12))
breach_label.pack()

exit_button = tk.Button(root, text="Exit", command=root.quit, font=("Arial", 12), bg="red", fg="white")
exit_button.pack(pady=10)

root.mainloop()

