# os is used for salts; base64 is used for encoding and decoding processes; getpass is handy for grabbing a password from terminal;

import os
import base64
import getpass

# i used PBKDF2HMAC because it's simple to implement and generally considered resistant to dictionary attacks
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# -> is a type hint in python. not necessary but improves readability
def derive_key(password: str, salt: bytes) -> bytes:
    """this give us a key based on the provided password which will be stored in our hashfile"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),

        # number size equates to increased security at the expense of time efficiency
        # length is in bytes 32 for SHA-256; iterations is how many times the thing is hashed
        
        # 8 * 32 = 256
        length=32,

        # adds random variable that helps protect against pre-computed tables
        salt=salt,
        
        iterations=10000,

        # based on https://cryptography.io/en/latest/fernet/#implementation
    )
    return kdf.derive(password.encode())

def encrypt(plaintext: str, password: str) -> bytes:
 
    """encrypt users plaintext using AES + a key derived from password."""
    salt = os.urandom(16)
    key = derive_key(password, salt)

    """random init vector for aes encryption - this is needed for the mode"""
    init_vector = os.urandom(16)

    # CTR is Counter, i.e., Uses a counter as the IV to generate unique keystream blocks for encryption. It avoids padding and is secure enough for my purposes.
    cipher = Cipher(algorithms.AES(key), modes.CTR(init_vector))

    # AES is a standard and it's efficient and secure
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    
    """add random value (salt) + init vector + ciphertext"""
    return base64.b64encode(salt + init_vector + ciphertext)

def decrypt(ciphertext: bytes, password: str) -> str:
   
    """Decrypts ciphertext using AES with a key derived from the password."""
    data = base64.b64decode(ciphertext)
    
    # slice/dice and assign
    salt, init_vector, ciphertext = data[:16], data[16:32], data[32:]

    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CTR(init_vector))
    decryptor = cipher.decryptor()
    return (decryptor.update(ciphertext) + decryptor.finalize()).decode()

def main():
    """this is the main function to handle encryption and decryption."""
    choice = input("Press 'e' to encrypt plaintext or 'd' to decrypt using a password:").lower()
    if choice == 'e':
        plaintext = input("Enter the plaintext: ")
        password = getpass.getpass("Enter the password: ")
        ciphertext = encrypt(plaintext, password)
        with open('hash.me', 'wb') as f:
            f.write(ciphertext)
        print("Secret encrypted and stored in 'hash.me'. Run it again and enter password to decrypt!")
    elif choice == 'd':
        with open('hash.me', 'rb') as f:
            ciphertext = f.read()
        password = getpass.getpass("Enter your password to decrypt the hash: ")
        try:
            plaintext = decrypt(ciphertext, password)
            print("Decrypted message:", plaintext)
        except Exception as e:
            print("Oh boy! Embrace the failure. Ain't no password like that, mate.", str(e))
    else:
        print("Enter 'e' or 'd', my good human.")


# this lets us run a python script directly "python main.py" and also if we wanted to use this program as a module in another script
if __name__ == "__main__":
    main()
