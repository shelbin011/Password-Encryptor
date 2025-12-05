from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
import os

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(filename: str, password: str):
    if not os.path.exists(filename):
        print("❌ File not found!")
        return

    salt = os.urandom(16)  # random per file
    key = derive_key_from_password(password, salt)
    fernet = Fernet(key)

    with open(filename, "rb") as f:
        data = f.read()

    encrypted_data = fernet.encrypt(data)

    new_path = filename + ".enc"

    with open(new_path, "wb") as f:
        f.write(salt + encrypted_data)  # prepend salt

    print(f"🔐 File '{filename}' encrypted successfully as '{new_path}'")

if __name__ == "__main__":
    file = input("Enter filename to encrypt: ")
    pwd = input("Set a password: ")
    encrypt_file(file, pwd)
