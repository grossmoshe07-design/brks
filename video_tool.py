import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.fernet import Fernet
import os

# -------------------------------------------------
# Configuration and Initialization
# -------------------------------------------------

# Generate / use a valid Fernet key (44 chars, base64)
# In production, load this from a secure environment variable
SECRET_KEY_PLACEHOLDER = Fernet.generate_key()

KEY_FROM_ENV = os.environ.get('PROPRIETARY_SECRET_KEY', '').strip()

if KEY_FROM_ENV:
    try:
        key_clean = KEY_FROM_ENV.strip()
        if len(key_clean) != 44:
            raise ValueError("Invalid key length")
        FERNET_KEY_BYTES = key_clean.encode("utf-8")
        Fernet(FERNET_KEY_BYTES)
        print("✓ Environment key validated successfully.")
    except Exception as e:
        print(f"Invalid environment key, using placeholder: {e}")
        FERNET_KEY_BYTES = SECRET_KEY_PLACEHOLDER
else:
    print("No environment key found. Using placeholder key.")
    FERNET_KEY_BYTES = SECRET_KEY_PLACEHOLDER

FERNET = Fernet(FERNET_KEY_BYTES)

CUSTOM_EXTENSION = ".brks"
CUSTOM_HEADER = b"MY_PROPRIETARY_HEADER_V1_0"
HEADER_LENGTH = len(CUSTOM_HEADER)

# -------------------------------------------------
# Main Application Class
# -------------------------------------------------

class VideoToolApp:
    def __init__(self, master):
        self.master = master
        master.title("Proprietary Video Converter & Player")
        master.geometry("600x450")

        self.selected_file_path = ""
        self.is_converter_logged_in = False

        self.create_main_interface()

    # -------------------------------------------------
    # Main UI
    # -------------------------------------------------

    def create_main_interface(self):
        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(pady=10, padx=10, expand=True, fill="both")

        self.player_tab = ttk.Frame(self.notebook, padding=10)
        self.converter_tab = ttk.Frame(self.notebook, padding=10)

        self.notebook.add(self.player_tab, text="▶ Player (.brks)")
        self.notebook.add(self.converter_tab, text="🎥 Converter (Login)")

        self._setup_player_tab()
        self._setup_converter_tab()

    # -------------------------------------------------
    # Converter Tab
    # -------------------------------------------------

    def _setup_converter_tab(self):
        self.converter_main_frame = ttk.Frame(self.converter_tab, padding=10)
        self.converter_main_frame.pack(expand=True, fill="both")

        self.conv_login_frame = self._create_converter_login_frame(self.converter_main_frame)
        self.conv_login_frame.pack(pady=50)

        self.conv_tools_frame = self._create_converter_tools_frame(self.converter_main_frame)

    def _create_converter_login_frame(self, parent):
        frame = ttk.Frame(parent)

        ttk.Label(frame, text="*** Login Required to Access Converter Tools ***",
                  foreground="red", font=("Arial", 12, "bold")).grid(row=0, column=0, columnspan=2, pady=10)

        ttk.Label(frame, text="Username:").grid(row=1, column=0, sticky="w", pady=5)
        self.user_entry = ttk.Entry(frame)
        self.user_entry.grid(row=1, column=1, pady=5)

        ttk.Label(frame, text="Password:").grid(row=2, column=0, sticky="w", pady=5)
        self.pass_entry = ttk.Entry(frame, show="*")
        self.pass_entry.grid(row=2, column=1, pady=5)

        ttk.Button(frame, text="Login & Enable Converter",
                   command=self._attempt_converter_login).grid(row=3, column=0, columnspan=2, pady=10)

        return frame

    def _create_converter_tools_frame(self, parent):
        frame = ttk.Frame(parent, padding=10)

        ttk.Button(frame, text="1. Select MP4 Video",
                   command=self.select_source_file).pack(pady=10)

        self.conv_file_label = ttk.Label(frame, text="No file selected.", wraplength=400)
        self.conv_file_label.pack(pady=5)

        ttk.Button(frame, text=f"2. Convert & Encrypt to {CUSTOM_EXTENSION}",
                   command=self.convert_file).pack(pady=20)

        self.conv_status_label = ttk.Label(frame, text="Status: Ready.", foreground="blue")
        self.conv_status_label.pack(pady=10)

        return frame

    def _attempt_converter_login(self):
        if self.user_entry.get() == "admin" and self.pass_entry.get() == "secure123":
            self.is_converter_logged_in = True
            self.conv_login_frame.pack_forget()
            self.conv_tools_frame.pack(expand=True, fill="both")
            messagebox.showinfo("Login Success", "Converter tools enabled.")
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")

    def select_source_file(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("MP4 files", "*.mp4"), ("All files", "*.*")]
        )
        if file_path:
            self.selected_file_path = file_path
            self.conv_file_label.config(text=os.path.basename(file_path))
            self.conv_status_label.config(text="Status: Ready to convert.", foreground="blue")

    def convert_file(self):
        if not self.selected_file_path:
            messagebox.showerror("Error", "No source file selected.")
            return

        try:
            self.conv_status_label.config(text="Encrypting...", foreground="orange")
            self.master.update()

            with open(self.selected_file_path, "rb") as f:
                original_data = f.read()

            encrypted_data = FERNET.encrypt(original_data)

            output_path = os.path.splitext(self.selected_file_path)[0] + CUSTOM_EXTENSION

            with open(output_path, "wb") as f:
                f.write(CUSTOM_HEADER)
                f.write(encrypted_data)

            self.conv_status_label.config(text="Conversion successful!", foreground="green")
            messagebox.showinfo("Success", f"Created file:\n{output_path}")

        except Exception as e:
            self.conv_status_label.config(text="Conversion failed", foreground="red")
            messagebox.showerror("Error", str(e))

    # -------------------------------------------------
    # Player Tab
    # -------------------------------------------------

    def _setup_player_tab(self):
        ttk.Button(self.player_tab, text=f"Open {CUSTOM_EXTENSION} File",
                   command=self.open_proprietary_file).pack(pady=10)

        self.player_status_label = ttk.Label(
            self.player_tab,
            text=f"Status: Ready to load {CUSTOM_EXTENSION} file.",
            wraplength=400
        )
        self.player_status_label.pack(pady=10)

        ttk.Label(self.player_tab, text="Video playback placeholder").pack(pady=20)

    def open_proprietary_file(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Proprietary Video", f"*{CUSTOM_EXTENSION}"), ("All files", "*.*")]
        )
        if file_path:
            self.play_proprietary_file(file_path)

    def play_proprietary_file(self, file_path):
        try:
            with open(file_path, "rb") as f:
                header = f.read(HEADER_LENGTH)
                if header != CUSTOM_HEADER:
                    raise ValueError("Invalid file header")
                encrypted_data = f.read()

            FERNET.decrypt(encrypted_data)

            self.player_status_label.config(text="Decryption successful!", foreground="green")
            messagebox.showinfo("Success", "Video decrypted successfully.")

        except Exception as e:
            self.player_status_label.config(text="Playback failed", foreground="red")
            messagebox.showerror("Error", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = VideoToolApp(root)
    root.mainloop()
