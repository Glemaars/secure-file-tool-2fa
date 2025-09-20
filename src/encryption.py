from cryptography.fernet import Fernet
import os

def generate_key():
    return Fernet.generate_key()

def save_key(key, filepath):
    with open(filepath, "wb") as f:
        f.write(key)

def load_key(filepath):
    with open(filepath, "rb") as f:
        return f.read()

def encrypt_file(file_path, key):
    f = Fernet(key)
    with open(file_path, "rb") as file:
        data = file.read()
    encrypted = f.encrypt(data)
    with open(file_path + ".enc", "wb") as file:
        file.write(encrypted)
    os.remove(file_path)

def decrypt_file(file_path, key):
    f = Fernet(key)
    with open(file_path, "rb") as file:
        encrypted_data = file.read()
    decrypted = f.decrypt(encrypted_data)
    new_path = file_path.replace(".enc", "")
    with open(new_path, "wb") as file:
        file.write(decrypted)
    os.remove(file_path)