import os
from cryptography.fernet import Fernet
from src.auth import load_device_key, generate_auth_token, verify_auth_token

def encrypt_file(file_path):
    key = load_device_key()
    f = Fernet(key)
    with open(file_path, "rb") as file:
        data = file.read()
    encrypted = f.encrypt(data)

    output_file = file_path + ".enc"
    if os.path.exists(output_file):
        confirm = input(f"{output_file} already exists. Overwrite? (Y/N): ").lower()
        if confirm != "y":
            print("Encryption cancelled.")
            return

    with open(output_file, "wb") as file:
        file.write(encrypted)

    share = input("Generate authorization token for sharing? (Y/N): ").lower()
    if share == "y":
        token = generate_auth_token(key)
        print("Authorization token:", token.decode())

    os.remove(file_path)

def decrypt_file(file_path):
    if not file_path.endswith(".enc"):
        print("Error: file must have .enc extension")
        return

    new_path = file_path[:-4]
    if os.path.exists(new_path):
        confirm = input(f"{new_path} already exists. Overwrite? (Y/N): ").lower()
        if confirm != "y":
            print("Decryption cancelled.")
            return

    key = load_device_key()
    f = Fernet(key)
    with open(file_path, "rb") as file:
        encrypted_data = file.read()

    try:
        decrypted = f.decrypt(encrypted_data)
    except:
        token_input = input("Enter authorization token: ").encode()
        if not verify_auth_token(key, token_input):
            print("Invalid authorization token.")
            return
        decrypted = f.decrypt(encrypted_data)

    with open(new_path, "wb") as file:
        file.write(decrypted)
    os.remove(file_path)