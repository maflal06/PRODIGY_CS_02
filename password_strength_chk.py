import tkinter as tk
from tkinter import messagebox

# Function to check password strength
def assess_password_strength(password):
    strength_score = 0
    strength_message = ""

    # Criteria 1: Check length of password
    if len(password) >= 8:
        strength_score += 1
    else:
        strength_message += "Password must be at least 8 characters long.\n"

    # Criteria 2: Check for uppercase letters
    if any(char.isupper() for char in password):
        strength_score += 1
    else:
        strength_message += "Password should include at least one uppercase letter.\n"

    # Criteria 3: Check for lowercase letters
    if any(char.islower() for char in password):
        strength_score += 1
    else:
        strength_message += "Password should include at least one lowercase letter.\n"

    # Criteria 4: Check for digits
    if any(char.isdigit() for char in password):
        strength_score += 1
    else:
        strength_message += "Password should include at least one number.\n"

    # Criteria 5: Check for special characters
    special_characters = "!@#$%^&*()-_=+[]{}|;:'\",.<>?/\\`~"
    if any(char in special_characters for char in password):
        strength_score += 1
    else:
        strength_message += "Password should include at least one special character.\n"

    # Determine the strength of the password based on the score
    if strength_score == 5:
        return "Strong", "Your password is strong!"
    elif strength_score >= 3:
        return "Medium", "Your password is medium strength. Consider improving it."
    else:
        return "Weak", f"Your password is weak.\n{strength_message}"

# Function to display password strength in the GUI
def check_password_strength():
    password = password_entry.get()
    if not password:
        messagebox.showwarning("Input Error", "Please enter a password.")
        return

    strength, message = assess_password_strength(password)
    result_label.config(text=f"Password Strength: {strength}")
    feedback_label.config(text=message)

# Create the GUI
root = tk.Tk()
root.title("Password Strength Checker")

# Create a frame for the content
frame = tk.Frame(root, padx=20, pady=20)
frame.pack()

# Create UI elements
password_label = tk.Label(frame, text="Enter Password:")
password_label.grid(row=0, column=0, sticky="w")

password_entry = tk.Entry(frame, show="*", width=30)
password_entry.grid(row=0, column=1, padx=10, pady=10)

check_button = tk.Button(frame, text="Check Strength", command=check_password_strength)
check_button.grid(row=1, columnspan=2, pady=10)

result_label = tk.Label(frame, text="", font=("Arial", 12, "bold"))
result_label.grid(row=2, columnspan=2, pady=10)

feedback_label = tk.Label(frame, text="", font=("Arial", 10), justify="left")
feedback_label.grid(row=3, columnspan=2)

# Start the GUI event loop
root.mainloop()