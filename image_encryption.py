from PIL import Image
import numpy as np


def encrypt_image(image_path, key):
    # Open the image and convert to RGB mode
    img = Image.open(image_path).convert("RGB")
    np_img = np.array(img, dtype=np.int16)  # Convert to a larger data type

    # Perform encryption by modifying pixel values using the key
    encrypted_img = (np_img + key) % 256

    # Convert back to uint8 to ensure proper image format
    encrypted_img = encrypted_img.astype('uint8')

    # Convert back to an image and save
    encrypted_img = Image.fromarray(encrypted_img)
    encrypted_img.save('encrypted_image.png')
    print("Image encrypted and saved as 'encrypted_image.png'")


def decrypt_image(image_path, key):
    # Open the encrypted image and convert to RGB mode
    img = Image.open(image_path).convert("RGB")
    np_img = np.array(img, dtype=np.int16)  # Convert to a larger data type

    # Perform decryption by reversing the pixel value modification
    decrypted_img = (np_img - key) % 256

    # Convert back to uint8 to ensure proper image format
    decrypted_img = decrypted_img.astype('uint8')

    # Convert back to an image and save
    decrypted_img = Image.fromarray(decrypted_img)
    decrypted_img.save('decrypted_image.png')
    print("Image decrypted and saved as 'decrypted_image.png'")


# Example usage
key = 50  # A simple key for encryption/decryption

# Encrypt an image
encrypt_image('input_image.png', key)

# Decrypt the image
decrypt_image('encrypted_image.png', key)
