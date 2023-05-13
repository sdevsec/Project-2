import tkinter as tk
from tkinter import messagebox, scrolledtext
from encryption import encrypt, decrypt


class App(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Caesar Cipher Encryption")
        self.geometry("450x400")
        self.resizable(False, False)

        # Create the encrypt section
        encrypt_label = tk.Label(self, text="Encrypt")
        encrypt_label.pack()

        # Input box for plaintext
        self.encrypt_text = tk.scrolledtext.ScrolledText(self, height=4, width=40)
        self.encrypt_text.insert("1.0", "Enter plaintext...")
        self.encrypt_text.bind("<FocusIn>", self.clear_prompt)
        self.encrypt_text.pack()

        # Buttons for encryption
        encrypt_buttons_frame = tk.Frame(self)
        encrypt_buttons_frame.pack()

        self.encrypt_button = tk.Button(encrypt_buttons_frame, text="Encrypt", command=self.encrypt)
        self.encrypt_button.pack(side="left", padx=5)

        self.encrypt_clear_button = tk.Button(encrypt_buttons_frame, text="Clear", command=self.clear_encrypt)
        self.encrypt_clear_button.pack(side="left", padx=5)

        # Output box for encrypted text
        self.encrypt_output = tk.scrolledtext.ScrolledText(self, height=4, width=40)
        self.encrypt_output.pack()

        # Create some spacing
        tk.Label(self, text="").pack()

        # Create the decrypt section
        decrypt_label = tk.Label(self, text="Decrypt")
        decrypt_label.pack()

        # Input box for ciphertext
        self.decrypt_text = tk.scrolledtext.ScrolledText(self, height=4, width=40)
        self.decrypt_text.insert("1.0", "Enter ciphertext...")
        self.decrypt_text.bind("<FocusIn>", self.clear_prompt)
        self.decrypt_text.pack()

        # Buttons for decryption
        decrypt_buttons_frame = tk.Frame(self)
        decrypt_buttons_frame.pack()

        self.decrypt_button = tk.Button(decrypt_buttons_frame, text="Decrypt", command=self.decrypt)
        self.decrypt_button.pack(side="left", padx=5)

        self.decrypt_clear_button = tk.Button(decrypt_buttons_frame, text="Clear", command=self.clear_decrypt)
        self.decrypt_clear_button.pack(side="left", padx=5)

        # Output box for decrypted text
        self.decrypt_output = tk.scrolledtext.ScrolledText(self, height=4, width=40)
        self.decrypt_output.pack()

    def clear_prompt(self, event):
        # Clear the prompt text when the input box is clicked
        event.widget.delete("1.0", "end")

    def encrypt(self):
        # Get the plaintext from the input box
        plaintext = self.encrypt_text.get("1.0", "end-1c")

        if plaintext == "Enter plaintext...":
            # Show an error message if no plaintext is entered
            messagebox.showerror("Error", "Please enter plaintext.")
            return

        # Encrypt the plaintext
        ciphertext = encrypt(plaintext)

        # Clear the output box and display the ciphertext
        self.encrypt_output.delete("1.0", "end")
        self.encrypt_output.insert("end", ciphertext)

    def decrypt(self):
        # Get the ciphertext from the input box
        ciphertext = self.decrypt_text.get("1.0", "end-1c")

        if ciphertext == "Enter ciphertext...":
            # Show an error message if no ciphertext is entered
            messagebox.showerror("Error", "Please enter ciphertext.")
            return

        # Decrypt the ciphertext
        plaintext = decrypt(ciphertext)

        # Clear the output box and display the plaintext
        self.decrypt_output.delete("1.0", "end")
        self.decrypt_output.insert("end", plaintext)

    def clear_encrypt(self):
        # Clear the encrypt input box and output box, and restore the prompt text
        self.encrypt_text.delete("1.0", "end")
        self.encrypt_text.insert("1.0", "Enter plaintext...")
        self.encrypt_output.delete("1.0", "end")

    def clear_decrypt(self):
        # Clear the decrypt input box and output box, and restore the prompt text
        self.decrypt_text.delete("1.0", "end")
        self.decrypt_text.insert("1.0", "Enter ciphertext...")
        self.decrypt_output.delete("1.0", "end")


if __name__ == "__main__":
    app = App()
    app.mainloop()
