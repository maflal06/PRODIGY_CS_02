import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import numpy as np

def encrypt_image(image_path, key):
    img = Image.open(image_path).convert("RGB")
    np_img = np.array(img, dtype=np.int16)
    encrypted_img = (np_img + key) % 256
    encrypted_img = encrypted_img.astype('uint8')
    encrypted_img = Image.fromarray(encrypted_img)
    encrypted_img.save('encrypted_image.png')
    return 'encrypted_image.png'

def decrypt_image(image_path, key):
    img = Image.open(image_path).convert("RGB")
    np_img = np.array(img, dtype=np.int16)
    decrypted_img = (np_img - key) % 256
    decrypted_img = decrypted_img.astype('uint8')
    decrypted_img = Image.fromarray(decrypted_img)
    decrypted_img.save('decrypted_image.png')
    return 'decrypted_image.png'

def load_image():
    file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
    if file_path:
        global img_path
        img_path = file_path
        img = Image.open(img_path)
        img.thumbnail((250, 250))
        img_tk = ImageTk.PhotoImage(img)
        image_label.config(image=img_tk)
        image_label.image = img_tk

def encrypt():
    if img_path:
        key = int(key_entry.get())
        output_path = encrypt_image(img_path, key)
        messagebox.showinfo("Success", f"Image encrypted and saved as {output_path}")

def decrypt():
    if img_path:
        key = int(key_entry.get())
        output_path = decrypt_image(img_path, key)
        messagebox.showinfo("Success", f"Image decrypted and saved as {output_path}")

# Initialize GUI
root = tk.Tk()
root.title("Image Encryption Tool")

img_path = ""

# Create UI elements
load_button = tk.Button(root, text="Load Image", command=load_image)
load_button.pack(pady=10)

image_label = tk.Label(root)
image_label.pack(pady=10)

key_label = tk.Label(root, text="Encryption/Decryption Key:")
key_label.pack(pady=5)

key_entry = tk.Entry(root)
key_entry.pack(pady=5)

encrypt_button = tk.Button(root, text="Encrypt", command=encrypt)
encrypt_button.pack(pady=10)

decrypt_button = tk.Button(root, text="Decrypt", command=decrypt)
decrypt_button.pack(pady=10)

# Run the GUI event loop
root.mainloop()
