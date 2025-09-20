from src.auth import setup_2fa, verify_2fa

def main():
    totp = setup_2fa()
    if verify_2fa(totp):
        print("You can now encrypt/decrypt files!")
    else:
        print("Exiting program...")

if __name__ == "__main__":
    main()
