import os
from src.auth import setup_2fa, verify_2fa
from src.encryption import generate_key, save_key, load_key, encrypt_file, decrypt_file

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_FOLDER = os.path.join(PROJECT_ROOT, "data")
KEY_FILE = os.path.join(DATA_FOLDER, "key.key")

def main():
    totp = setup_2fa()
    if not verify_2fa(totp):
        print("Exiting program...")
        return

    print("Access granted. You can now encrypt/decrypt files!")

    os.makedirs(DATA_FOLDER, exist_ok=True)

    if not os.path.exists(KEY_FILE):
        key = generate_key()
        save_key(key, KEY_FILE)
    else:
        key = load_key(KEY_FILE)

    while True:
        action = input("Choose action: [E]ncrypt, [D]ecrypt, [Q]uit: ").lower()
        if action == "e":
            path = input("Enter file path to encrypt: ")
            encrypt_file(path, key)
            print(f"{path} encrypted.")
        elif action == "d":
            path = input("Enter file path to decrypt: ")
            decrypt_file(path, key)
            print(f"{path} decrypted.")
        elif action == "q":
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()