from src.auth import setup_2fa, verify_2fa
from src.encryption import generate_key, save_key, load_key, encrypt_file, decrypt_file
import os

def main():
    totp = setup_2fa()
    if not verify_2fa(totp):
        print("Exiting program...")
        return

    print("You can now encrypt/decrypt files!")
    key_file = "data/key.key"
    if not os.path.exists(key_file):
        key = generate_key()
        os.makedirs("data", exist_ok=True)
        save_key(key, key_file)
    else:
        key = load_key(key_file)

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