import os
import uuid
import base64
import hashlib
import pyotp
from cryptography.fernet import Fernet

DATA_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")
TOTP_FILE = os.path.join(DATA_FOLDER, "totp.key")
KEY_FILE = os.path.join(DATA_FOLDER, "key.key")

def get_hardware_key():
    hw_id = str(uuid.getnode()).encode()
    hashed = hashlib.sha256(hw_id).digest()
    key = base64.urlsafe_b64encode(hashed)
    return Fernet(key)

def generate_device_key():
    key = Fernet.generate_key()
    f = get_hardware_key()
    encrypted_key = f.encrypt(key)
    os.makedirs(DATA_FOLDER, exist_ok=True)
    with open(KEY_FILE, "wb") as f_key:
        f_key.write(encrypted_key)
    return key

def load_device_key():
    if not os.path.exists(KEY_FILE):
        return generate_device_key()
    f = get_hardware_key()
    with open(KEY_FILE, "rb") as f_key:
        encrypted_key = f_key.read()
    return f.decrypt(encrypted_key)

def setup_2fa():
    os.makedirs(DATA_FOLDER, exist_ok=True)
    key = load_device_key()
    f = Fernet(key)
    if not os.path.exists(TOTP_FILE):
        secret = pyotp.random_base32().encode()
        encrypted_secret = f.encrypt(secret)
        with open(TOTP_FILE, "wb") as f_totp:
            f_totp.write(encrypted_secret)
        print("Your secret key:", secret.decode())
    else:
        with open(TOTP_FILE, "rb") as f_totp:
            encrypted_secret = f_totp.read()
        secret = f.decrypt(encrypted_secret)
    return pyotp.TOTP(secret.decode())

def verify_2fa(totp):
    code = input("Enter 2FA code: ")
    if totp.verify(code):
        print("Access granted")
        return True
    else:
        print("Access denied")
        return False

def generate_auth_token(key):
    f = Fernet(key)
    token = Fernet.generate_key()
    encrypted_token = f.encrypt(token)
    return encrypted_token

def verify_auth_token(key, token):
    f = Fernet(key)
    try:
        f.decrypt(token)
        return True
    except:
        return False