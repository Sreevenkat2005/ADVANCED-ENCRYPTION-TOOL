import streamlit as st
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

backend = default_backend()
BLOCK_SIZE = 128

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    return kdf.derive(password)

def encrypt_bytes(data, password):
    salt = os.urandom(16)
    key = derive_key(password.encode(), salt)
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(BLOCK_SIZE).padder()

    padded_data = padder.update(data) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return salt + iv + ciphertext

def decrypt_bytes(data, password):
    salt = data[:16]
    iv = data[16:32]
    ciphertext = data[32:]

    key = derive_key(password.encode(), salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext

st.title("AES-256 File Encryptor / Decryptor")

mode = st.radio("Choose Mode:", ("Encrypt", "Decrypt"))

uploaded_file = st.file_uploader("Upload file", type=None)

password = st.text_input("Enter password", type="password")

if st.button(f"{mode} File"):
    if not uploaded_file:
        st.error("Please upload a file.")
    elif not password:
        st.error("Please enter a password.")
    else:
        file_bytes = uploaded_file.read()
        try:
            if mode == "Encrypt":
                encrypted_data = encrypt_bytes(file_bytes, password)
                st.success("File encrypted successfully!")
                st.download_button(
                    label="Download Encrypted File",
                    data=encrypted_data,
                    file_name=uploaded_file.name + ".enc",
                    mime="application/octet-stream"
                )
            else:  # Decrypt
                decrypted_data = decrypt_bytes(file_bytes, password)
                st.success("File decrypted successfully!")
                # Remove .enc extension if present
                orig_name = uploaded_file.name
                if orig_name.endswith(".enc"):
                    orig_name = orig_name[:-4]
                st.download_button(
                    label="Download Decrypted File",
                    data=decrypted_data,
                    file_name=orig_name,
                    mime="application/octet-stream"
                )
        except Exception as e:
            st.error(f"Error during {mode.lower()}ion: {e}")
