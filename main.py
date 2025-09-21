from src.auth import setup_2fa, verify_2fa
from src.encryption import encrypt_file, decrypt_file

def main():
    totp = setup_2fa()
    if not verify_2fa(totp):
        print("Exiting program...")
        return

    print("Access granted. You can now encrypt/decrypt files!")

    while True:
        action = input("Choose action: [E]ncrypt, [D]ecrypt, [Q]uit: ").lower()
        if action == "e":
            path = input("Enter file path to encrypt: ")
            encrypt_file(path)
            print(f"{path} encrypted.")
        elif action == "d":
            path = input("Enter file path to decrypt: ")
            decrypt_file(path)
            print(f"{path} decrypted.")
        elif action == "q":
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()