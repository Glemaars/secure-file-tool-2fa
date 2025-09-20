import pyotp
import os

DATA_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")
TOTP_FILE = os.path.join(DATA_FOLDER, "totp.key")

def setup_2fa():
    if not os.path.exists(TOTP_FILE):
        secret = pyotp.random_base32()
        os.makedirs(DATA_FOLDER, exist_ok=True)
        with open(TOTP_FILE, "w") as f:
            f.write(secret)
        print("Your secret key:", secret)
    else:
        with open(TOTP_FILE, "r") as f:
            secret = f.read().strip()
    return pyotp.TOTP(secret)

def verify_2fa(totp):
    code = input("Enter 2FA code: ")
    if totp.verify(code):
        print("Access granted")
        return True
    else:
        print("Access denied")
        return False

if __name__ == "__main__":
    totp = setup_2fa()
    verify_2fa(totp)