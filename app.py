import os
import hashlib
import logging
from datetime import datetime
from tkinter import (
    Tk,
    Button,
    Label,
    StringVar,
    Radiobutton,
    filedialog,
    messagebox,
    DISABLED,
    NORMAL,
)
from cryptography.fernet import Fernet

# ---------------- Logging ----------------
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger.addHandler(handler)


# ---------------- Key Management ----------------
KEY_FILE = "secret.key"


def generate_key() -> bytes:
    """
    Generate a new Fernet key and save it to secret.key.
    Returns the key.
    """
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    logger.info("New key generated and saved to %s", KEY_FILE)
    return key


def load_key() -> bytes:
    """
    Load the Fernet key from secret.key.
    If it doesn't exist, ask user and create it.
    """
    if not os.path.exists(KEY_FILE):
        answer = messagebox.askyesno(
            "Key not found",
            "secret.key not found.\n\nDo you want to generate a new encryption key?",
        )
        if not answer:
            raise FileNotFoundError("secret.key not found and user cancelled key generation.")
        return generate_key()

    with open(KEY_FILE, "rb") as f:
        key = f.read().strip()
    if not key:
        raise ValueError("secret.key is empty or invalid.")
    return key


# ---------------- Encryption / Decryption ----------------
def encrypt_file(filepath: str, key: bytes) -> str:
    """
    Encrypt the file at filepath using the provided key.
    Saves as <original>.enc and returns new path.
    """
    fernet = Fernet(key)

    with open(filepath, "rb") as file:
        data = file.read()

    encrypted_data = fernet.encrypt(data)

    new_path = filepath + ".enc"
    with open(new_path, "wb") as file:
        file.write(encrypted_data)

    logger.info("Encrypted %s -> %s", filepath, new_path)
    return new_path


def decrypt_file(filepath: str, key: bytes) -> str:
    """
    Decrypt the file at filepath using the provided key.
    Expects .enc extension, removes it when saving.
    """
    if not filepath.endswith(".enc"):
        raise ValueError("File must have .enc extension for decryption.")

    fernet = Fernet(key)

    with open(filepath, "rb") as file:
        encrypted_data = file.read()

    decrypted_data = fernet.decrypt(encrypted_data)

    orig_path = filepath[:-4]  # remove .enc
    with open(orig_path, "wb") as file:
        file.write(decrypted_data)

    logger.info("Decrypted %s -> %s", filepath, orig_path)
    return orig_path


# ---------------- GUI App ----------------
class EncryptorApp:
    def __init__(self, root: Tk):
        self.root = root
        self.root.title("File Encryptor & Decryptor")
        self.root.geometry("520x260")
        self.root.resizable(False, False)

        # Selected file path
        self.file_path = StringVar(value="No file selected")
        # Mode: encrypt or decrypt
        self.mode = StringVar(value="encrypt")

        # UI
        self._build_ui()

    def _build_ui(self):
        # Title
        Label(
            self.root,
            text="🔐 File Encryptor & Decryptor",
            font=("Segoe UI", 14, "bold"),
        ).pack(pady=10)

        # File label
        self.file_label = Label(
            self.root,
            textvariable=self.file_path,
            wraplength=480,
            justify="center",
            fg="#444",
        )
        self.file_label.pack(pady=5)

        # Browse button
        Button(
            self.root,
            text="Browse File",
            command=self.browse_file,
            width=20,
        ).pack(pady=5)

        # Mode selection (Encrypt / Decrypt)
        Label(self.root, text="Mode:", font=("Segoe UI", 10, "bold")).pack(pady=(10, 0))

        mode_frame_y = 140
        Radiobutton(
            self.root,
            text="Encrypt",
            value="encrypt",
            variable=self.mode,
        ).place(x=190, y=mode_frame_y)
        Radiobutton(
            self.root,
            text="Decrypt",
            value="decrypt",
            variable=self.mode,
        ).place(x=280, y=mode_frame_y)

        # Action & Exit buttons
        self.run_button = Button(
            self.root,
            text="Run",
            command=self.run_action,
            width=12,
            state=DISABLED,
        )
        self.run_button.pack(pady=20)

        Button(
            self.root,
            text="Exit",
            command=self.root.quit,
            width=10,
        ).pack()

    def browse_file(self):
        path = filedialog.askopenfilename(
            title="Select a file",
            filetypes=[("All files", "*.*")],
        )
        if path:
            self.file_path.set(path)
            self.run_button.config(state=NORMAL)
        else:
            # If user cancels, keep previous selection, but if it was none, disable Run
            if self.file_path.get() == "No file selected":
                self.run_button.config(state=DISABLED)

    def run_action(self):
        filepath = self.file_path.get()
        if not filepath or filepath == "No file selected":
            messagebox.showwarning("No file", "Please select a file first.")
            return

        if not os.path.isfile(filepath):
            messagebox.showerror("Error", "Selected file does not exist.")
            return

        try:
            key = load_key()
        except Exception as e:
            logger.error("Key load error: %s", e)
            messagebox.showerror("Key Error", str(e))
            return

        try:
            if self.mode.get() == "encrypt":
                new_path = encrypt_file(filepath, key)
                messagebox.showinfo(
                    "Success",
                    f"✅ File encrypted successfully!\n\nSaved as:\n{new_path}",
                )
            else:
                new_path = decrypt_file(filepath, key)
                messagebox.showinfo(
                    "Success",
                    f"✅ File decrypted successfully!\n\nSaved as:\n{new_path}",
                )

        except Exception as e:
            logger.error("Action error: %s", e)
            messagebox.showerror("Error", f"Operation failed:\n{e}")


# ---------------- Main ----------------
def main():
    root = Tk()
    app = EncryptorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
