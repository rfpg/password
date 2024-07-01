import os
import base64
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a cryptographic key from a password using PBKDF2 with HMAC-SHA256.

    Args:
        password (str): The password to derive the key from.
        salt (bytes): The salt to use in the key derivation function.

    Returns:
        bytes: The derived key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Use SHA256 as the hashing algorithm
        length=32,                  # The length of the derived key (32 bytes for AES-256)
        salt=salt,                  # The salt to use for the KDF
        iterations=100000,          # The number of iterations to perform
        backend=default_backend()   # The cryptographic backend to use
    )
    return kdf.derive(password.encode())  # Derive the key and return it

def encrypt(plaintext: str, password: str) -> (bytes, bytes):
    """
    Encrypts a plaintext message using AES with a key derived from a password.

    Args:
        plaintext (str): The message to encrypt.
        password (str): The password to derive the encryption key from.

    Returns:
        (bytes, bytes): The base64-encoded ciphertext and the encryption key.
    """
    salt = os.urandom(16)  # Generate a random 16-byte salt
    key = derive_key(password, salt)  # Derive the key from the password and salt
    iv = os.urandom(16)  # Generate a random 16-byte initialization vector (IV)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())  # Create the AES cipher in CFB mode
    encryptor = cipher.encryptor()  # Create an encryptor object
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()  # Encrypt the plaintext
    return base64.b64encode(salt + iv + ciphertext), key  # Return the encoded ciphertext and the key

def decrypt(ciphertext: bytes, password: str) -> str:
    """
    Decrypts a ciphertext message using AES with a key derived from a password.

    Args:
        ciphertext (bytes): The base64-encoded ciphertext to decrypt.
        password (str): The password to derive the decryption key from.

    Returns:
        str: The decrypted plaintext message.
    """
    data = base64.b64decode(ciphertext)  # Decode the base64-encoded ciphertext
    salt, iv, ciphertext = data[:16], data[16:32], data[32:]  # Extract the salt, IV, and ciphertext
    key = derive_key(password, salt)  # Derive the key from the password and salt
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())  # Create the AES cipher in CFB mode
    decryptor = cipher.decryptor()  # Create a decryptor object
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()  # Decrypt the ciphertext
    return plaintext.decode()  # Return the decrypted plaintext

def main():
    """
    The main function that handles user input and performs encryption or decryption.
    """
    choice = input("Would you like to (e)ncrypt or (d)ecrypt?: ").lower()  # Ask the user whether to encrypt or decrypt
    if choice == 'e':  # If the user chooses to encrypt
        plaintext = input("Enter the plaintext: ")  # Get the plaintext from the user
        password = getpass.getpass("Enter the password: ")  # Get the password from the user (hidden input)
        ciphertext, key = encrypt(plaintext, password)  # Encrypt the plaintext
        with open('secret.enc', 'wb') as f:  # Open a file to write the ciphertext
            f.write(ciphertext)  # Write the ciphertext to the file
        print("Secret encrypted and stored in 'secret.enc'.")  # Inform the user that the encryption was successful
    elif choice == 'd':  # If the user chooses to decrypt
        with open('secret.enc', 'rb') as f:  # Open the file containing the ciphertext
            ciphertext = f.read()  # Read the ciphertext from the file
        password = getpass.getpass("Enter the password: ")  # Get the password from the user (hidden input)
        try:
            plaintext = decrypt(ciphertext, password)  # Decrypt the ciphertext
            print("Decrypted text:", plaintext)  # Print the decrypted plaintext
        except Exception as e:  # If an error occurs during decryption
            print("Decryption failed:", str(e))  # Inform the user that decryption failed
    else:
        print("Invalid choice. Please select either 'e' or 'd'.")  # Inform the user of an invalid choice

if __name__ == "__main__":
    main()  # Run the main function if this script is executed directly
