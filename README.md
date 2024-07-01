# Encryption and Decryption Utility

This utility program provides an interface for encrypting and decrypting plaintext using AES (Advanced Encryption Standard) encryption with a key derived from a user-provided password. It uses Python's `cryptography` library to secure your data.

## Features

- Encrypt plaintext with AES-CTR mode, ensuring high security and performance.
- Decrypt ciphertext back into plaintext using the same password.
- Utilize a key derivation function (PBKDF2HMAC) to derive a cryptographic key from the password.
- Salting and iterative hashing to enhance security against brute-force and dictionary attacks.
- Use of `getpass` to securely input passwords without echoing them on the terminal.

## Requirements

- Python 3.6 or newer
- `cryptography` library

Install the required library using pip:

```bash
pip install cryptography
