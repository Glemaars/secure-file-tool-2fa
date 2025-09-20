import pyotp

def setup_2fa():
    secret = pyotp.random_base32()
    print("Your secret key:", secret)
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