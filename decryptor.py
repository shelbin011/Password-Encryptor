from cryptography.fernet import Fernet
import hashlib

def load_key():
    return open("secret.key", "rb").read()

def decrypt_file(filename):
    key = load_key()
    fernet = Fernet(key)

    with open(filename, "rb") as enc_file:
        file_data = enc_file.read()

    stored_hash, encrypted_data = file_data.split(b"||", 1)

    password = input("Enter password to decrypt: ")
    hashed_input = hashlib.sha256(password.encode()).hexdigest().encode()

    if hashed_input != stored_hash:
        print("❌ Incorrect password! Access denied.")
        return

    decrypted = fernet.decrypt(encrypted_data)

    original_name = filename.replace(".encrypted", "")
    with open(original_name, "wb") as dec_file:
        dec_file.write(decrypted)

    print(f"🔓 File '{filename}' decrypted successfully!")

if __name__ == "__main__":
    file_name = input("Enter encrypted file name: ")
    decrypt_file(file_name)
