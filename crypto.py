import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import getpass

backend = default_backend()
BLOCK_SIZE = 128  # AES block size in bits

def derive_key(password: bytes, salt: bytes) -> bytes:
    # Derive a secret key from the password and salt using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits for AES-256
        salt=salt,
        iterations=100000,
        backend=backend
    )
    return kdf.derive(password)

def encrypt_file(input_path, output_path, password):
    salt = os.urandom(16)
    key = derive_key(password.encode(), salt)
    iv = os.urandom(16)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(BLOCK_SIZE).padder()

    with open(input_path, 'rb') as f:
        plaintext = f.read()

    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Save salt + iv + ciphertext
    with open(output_path, 'wb') as f:
        f.write(salt + iv + ciphertext)
    print(f"[+] File encrypted and saved to: {output_path}")

def decrypt_file(input_path, output_path, password):
    with open(input_path, 'rb') as f:
        data = f.read()

    salt = data[:16]
    iv = data[16:32]
    ciphertext = data[32:]
    
    key = derive_key(password.encode(), salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    try:
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    except ValueError:
        print("[!] Incorrect password or corrupted file.")
        return

    with open(output_path, 'wb') as f:
        f.write(plaintext)
    print(f"[+] File decrypted and saved to: {output_path}")

def main():
    print("=== AES-256 File Encryptor/Decryptor ===")
    while True:
        choice = input("Choose (E)ncrypt / (D)ecrypt / (Q)uit: ").strip().lower()
        if choice == 'e':
            input_path = input("Enter path of file to encrypt: ").strip()
            if not os.path.isfile(input_path):
                print("[!] File not found.")
                continue
            output_path = input("Enter output encrypted file path: ").strip()
            password = getpass.getpass("Enter encryption password: ")
            confirm = getpass.getpass("Confirm password: ")
            if password != confirm:
                print("[!] Passwords do not match. Try again.")
                continue
            encrypt_file(input_path, output_path, password)
        elif choice == 'd':
            input_path = input("Enter path of file to decrypt: ").strip()
            if not os.path.isfile(input_path):
                print("[!] File not found.")
                continue
            output_path = input("Enter output decrypted file path: ").strip()
            password = getpass.getpass("Enter decryption password: ")
            decrypt_file(input_path, output_path, password)
        elif choice == 'q':
            print("Exiting.")
            break
        else:
            print("[!] Invalid option. Please choose E, D, or Q.")

if __name__ == "__main__":
    main()

