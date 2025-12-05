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

def decrypt_file(filename: str, password: str):
    if not filename.endswith(".enc"):
        print("❌ This file is not encrypted!")
        return

    with open(filename, "rb") as f:
        file_data = f.read()

    salt = file_data[:16]  # first 16 bytes
    encrypted_data = file_data[16:]
    key = derive_key_from_password(password, salt)
    fernet = Fernet(key)

    try:
        decrypted = fernet.decrypt(encrypted_data)
    except Exception:
        print("❌ Incorrect password!")
        return

    new_path = filename[:-4]  # remove .enc

    with open(new_path, "wb") as f:
        f.write(decrypted)

    print(f"🔓 File decrypted successfully as '{new_path}'")

if __name__ == "__main__":
    file = input("Enter encrypted filename: ")
    pwd = input("Enter password: ")
    decrypt_file(file, pwd)
