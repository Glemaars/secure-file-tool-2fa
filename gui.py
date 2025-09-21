import tkinter as tk
from tkinter import filedialog, messagebox
from src.auth import setup_2fa, verify_2fa
from src.encryption import encrypt_file, decrypt_file

class SecureFileToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Tool 2FA")
        self.root.geometry("600x250")
        self.totp = None
        self.authenticated = False
        self.create_widgets()
        self.root.after(100, self.open_2fa_popup)

    def create_widgets(self):
        self.status_label = tk.Label(self.root, text="Authenticate with 2FA to continue.")
        self.status_label.pack(pady=10)

        self.file_frame = tk.Frame(self.root)
        self.file_frame.pack(pady=10)

        self.file_path_var = tk.StringVar()
        self.file_entry = tk.Entry(self.file_frame, textvariable=self.file_path_var, width=60)
        self.file_entry.pack(side=tk.LEFT, padx=(0,5))
        self.browse_btn = tk.Button(self.file_frame, text="...", command=self.browse_file, width=3)
        self.browse_btn.pack(side=tk.LEFT)

        self.button_frame = tk.Frame(self.root)
        self.button_frame.pack(pady=5)
        self.encrypt_btn = tk.Button(self.button_frame, text="Encrypt File", command=self.encrypt_file, state=tk.DISABLED, width=20)
        self.encrypt_btn.pack(side=tk.LEFT, padx=5)
        self.decrypt_btn = tk.Button(self.button_frame, text="Decrypt File", command=self.decrypt_file, state=tk.DISABLED, width=20)
        self.decrypt_btn.pack(side=tk.LEFT, padx=5)

    def open_2fa_popup(self):
        popup = tk.Toplevel(self.root)
        popup.title("2FA Verification")
        popup.geometry("350x120")
        tk.Label(popup, text="Enter 2FA code:").pack(pady=10)
        code_entry = tk.Entry(popup)
        code_entry.pack(pady=5)
        code_entry.focus()

        def submit_2fa():
            if not self.totp:
                self.totp = setup_2fa()
            code = code_entry.get()
            if self.totp.verify(code):
                self.status_label.config(text="Access granted. Choose an action.")
                self.encrypt_btn.config(state=tk.NORMAL)
                self.decrypt_btn.config(state=tk.NORMAL)
                self.authenticated = True
                popup.destroy()
            else:
                messagebox.showerror("2FA Error", "Invalid 2FA code.")

        tk.Button(popup, text="Submit", command=submit_2fa).pack(pady=5)

    def browse_file(self):
        path = filedialog.askopenfilename(title="Select file")
        if path:
            self.file_path_var.set(path)

    def encrypt_file(self):
        path = self.file_path_var.get()
        if not path:
            messagebox.showerror("Error", "Please enter or select a file path.")
            return
        if messagebox.askyesno("Auth Token", "Generate authorization token for sharing?"):
            self.open_token_popup()
        try:
            encrypt_file(path)
            messagebox.showinfo("Success", f"{path} encrypted.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_file(self):
        path = self.file_path_var.get()
        if not path:
            messagebox.showerror("Error", "Please enter or select a file path.")
            return
        try:
            decrypt_file(path)
            messagebox.showinfo("Success", f"{path} decrypted.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def open_token_popup(self):
        popup = tk.Toplevel(self.root)
        popup.title("Authorization Token")
        popup.geometry("400x150")
        tk.Label(popup, text="Authorization token generated.").pack(pady=10)
        from src.auth import load_device_key, generate_auth_token
        key = load_device_key()
        token = generate_auth_token(key)

        def copy_to_clipboard():
            self.root.clipboard_clear()
            self.root.clipboard_append(token.decode())
            messagebox.showinfo("Copied", "Token copied to clipboard.")
            popup.destroy()

        tk.Button(popup, text="Copy to Clipboard", command=copy_to_clipboard).pack(pady=20)

def main():
    root = tk.Tk()
    app = SecureFileToolGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
