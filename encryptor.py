from cryptography.fernet import Fernet
import hashlib

def load_key():
    return open("secret.key", "rb").read()

def encrypt_file(filename):
    key = load_key()
    fernet = Fernet(key)

    password = input("Set a password for this file: ")
    hashed_pass = hashlib.sha256(password.encode()).hexdigest().encode()

    with open(filename, "rb") as file:
        original = file.read()

    encrypted_data = fernet.encrypt(original)

    final_data = hashed_pass + b"||" + encrypted_data  # Store password hash in file

    with open(filename + ".encrypted", "wb") as enc_file:
        enc_file.write(final_data)

    print(f"🔐 File '{filename}' encrypted with password successfully!")

if __name__ == "__main__":
    file_name = input("Enter the file name to encrypt: ")
    encrypt_file(file_name)
