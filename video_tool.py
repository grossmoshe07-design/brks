import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.fernet import Fernet
import os
import sys
import base64 # <-- Added for safe key processing

# --- Configuration and Initialization ---
# This is the core logic that retrieves the secret key.

# PLACEHOLDER KEY (44 characters, valid Base64) for local testing.
# This key is only used if the script is NOT run via the PyInstaller executable 
# built with the PROPRIETARY_SECRET_KEY environment variable set.
SECRET_KEY_PLACEHOLDER = b'aGVsbG9fZnJvbV9teV9hdXRvbWF0ZWRfYnVpbGRfc2VjcmV0' 
FERNET_KEY_BYTES = None

# Try to get the key from the environment variable set by GitHub Actions/PyInstaller
KEY_FROM_ENV = os.environ.get('PROPRIETARY_SECRET_KEY')

if KEY_FROM_ENV:
    try:
        # Key comes in as a string. Check length and encode it to bytes.
        if len(KEY_FROM_ENV) != 44:
             raise ValueError(f"Environment key has incorrect length ({len(KEY_FROM_ENV)}). Expected 44 characters.")

        # If the key is present and correct length, use it.
        FERNET_KEY_BYTES = KEY_FROM_ENV.encode('utf-8')
        
    except Exception as e:
        # Fall back to placeholder if the environment key is invalid
        print(f"Error processing environment key: {e}. Falling back to placeholder.")
        FERNET_KEY_BYTES = SECRET_KEY_PLACEHOLDER
else:
    # Use placeholder for local run without env var set
    FERNET_KEY_BYTES = SECRET_KEY_PLACEHOLDER

# Initialize Fernet with the correctly processed key bytes
try:
    FERNET = Fernet(FERNET_KEY_BYTES)
except ValueError as e:
    # This catches the Fernet specific error, providing context.
    print(f"Key loaded: {FERNET_KEY_BYTES}")
    raise ValueError(f"Failed to initialize Fernet. Key length: {len(FERNET_KEY_BYTES)}. Detail: {e}")

CUSTOM_EXTENSION = ".myformat"
CUSTOM_HEADER = b'MY_PROPRIETARY_HEADER_V1_0'
HEADER_LENGTH = len(CUSTOM_HEADER)
# --- End Configuration ---


# --- Main Application Class ---
class VideoToolApp:
    def __init__(self, master):
        self.master = master
        master.title("Proprietary Video Converter & Player")
        master.geometry("500x300")
        
        self.selected_file_path = ""
        
        self.login_frame = self.create_login_frame()
        self.login_frame.pack(expand=True, fill="both")

    # --- Login Screen UI ---
    def create_login_frame(self):
        frame = tk.Frame(self.master)
        
        center_frame = tk.Frame(frame)
        center_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        tk.Label(center_frame, text="Username:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.user_entry = tk.Entry(center_frame)
        self.user_entry.grid(row=0, column=1, padx=10, pady=5)
        
        tk.Label(center_frame, text="Password:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.pass_entry = tk.Entry(center_frame, show="*")
        self.pass_entry.grid(row=1, column=1, padx=10, pady=5)
        
        tk.Button(center_frame, text="Login", command=self.attempt_login).grid(row=2, column=0, columnspan=2, pady=10)
        
        return frame

    def attempt_login(self):
        # NOTE: Simple authentication for demonstration
        if self.user_entry.get() == "admin" and self.pass_entry.get() == "secure123":
            self.login_frame.pack_forget()
            self.master.geometry("600x450") 
            self.create_main_interface()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")

    # --- Main Interface (Notebook UI) ---
    def create_main_interface(self):
        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(pady=10, padx=10, expand=True, fill="both")

        self.converter_tab = tk.Frame(self.notebook, padding="10")
        self.player_tab = tk.Frame(self.notebook, padding="10")

        self.notebook.add(self.converter_tab, text="🎥 Converter (Create .myformat)")
        self.notebook.add(self.player_tab, text="▶️ Player (View .myformat)")

        self._setup_converter_tab()
        self._setup_player_tab()

    # --- CONVERTER TAB LOGIC ---
    def _setup_converter_tab(self):
        tk.Button(self.converter_tab, text="1. Select Standard MP4 Video", command=self.select_source_file).pack(pady=10, padx=10)
        
        self.conv_file_label = tk.Label(self.converter_tab, text="No file selected.", wraplength=400)
        self.conv_file_label.pack(pady=5)
        
        tk.Button(self.converter_tab, text=f"2. CONVERT and Encrypt to {CUSTOM_EXTENSION}", command=self.convert_file).pack(pady=20, padx=10)
        
        self.conv_status_label = tk.Label(self.converter_tab, text="Status: Ready.", fg="blue")
        self.conv_status_label.pack(pady=10)
        
    def select_source_file(self):
        file_path = filedialog.askopenfilename(
            defaultextension=".mp4",
            filetypes=[("MP4 Video files", "*.mp4"), ("All files", "*.*")]
        )
        if file_path:
            self.selected_file_path = file_path
            self.conv_file_label.config(text=f"Selected: {os.path.basename(file_path)}")
            self.conv_status_label.config(text="Status: File selected. Ready to convert.", fg="blue")

    def convert_file(self):
        if not self.selected_file_path:
            messagebox.showerror("Error", "Please select a source file first.")
            return

        try:
            self.conv_status_label.config(text="Status: Reading and encrypting...", fg="orange")
            self.master.update() 
            
            with open(self.selected_file_path, 'rb') as f:
                original_data = f.read()

            encrypted_data = FERNET.encrypt(original_data)

            base_name = os.path.splitext(self.selected_file_path)[0]
            output_path = base_name + CUSTOM_EXTENSION
            
            with open(output_path, 'wb') as f:
                f.write(CUSTOM_HEADER)
                f.write(encrypted_data)
            
            self.conv_status_label.config(text=f"Status: SUCCESS! Output: {os.path.basename(output_path)}", fg="green")
            messagebox.showinfo("Success", f"File successfully converted and encrypted to:\n{output_path}")

        except Exception as e:
            self.conv_status_label.config(text="Status: CONVERSION FAILED.", fg="red")
            messagebox.showerror("Conversion Error", f"An error occurred: {e}")

    # --- PLAYER TAB LOGIC ---
    def _setup_player_tab(self):
        tk.Button(self.player_tab, text=f"1. Open {CUSTOM_EXTENSION} Video File", command=self.open_proprietary_file).pack(pady=10, padx=10)
        
        self.player_status_label = tk.Label(self.player_tab, text="Status: Ready to load proprietary file.", wraplength=400)
        self.player_status_label.pack(pady=10)
        
        tk.Label(self.player_tab, text="Video Display Area (Requires C-based Library Integration)").pack(pady=20)


    def open_proprietary_file(self):
        file_path = filedialog.askopenfilename(
            defaultextension=CUSTOM_EXTENSION,
            filetypes=[(f"Custom Video files", f"*{CUSTOM_EXTENSION}"), ("All files", "*.*")]
        )
        
        if file_path:
            self.player_status_label.config(text=f"Status: Attempting to load and decrypt {os.path.basename(file_path)}...", fg="blue")
            self.master.update() 
            self.play_proprietary_file(file_path)

    def play_proprietary_file(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                header_check = f.read(HEADER_LENGTH)
                if header_check != CUSTOM_HEADER:
                    raise ValueError("File is not a valid proprietary format (Missing Header).")
                
                encrypted_data = f.read()
            
            decrypted_data = FERNET.decrypt(encrypted_data)
            
            # --- REAL-TIME VIDEO PLAYBACK LOGIC GOES HERE ---
            
            self.player_status_label.config(text="Status: Decryption SUCCESS. Video is ready for playback.", fg="green")
            messagebox.showinfo("Playback Success", 
                                f"Video file decrypted successfully. The embedded player would now be rendering the video stream.")

        except Exception as e:
            self.player_status_label.config(text="Status: Playback FAILED.", fg="red")
            messagebox.showerror("Playback Error", f"Cannot play this file. Only authorized files can be viewed. Error: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = VideoToolApp(root)
    root.mainloop()
