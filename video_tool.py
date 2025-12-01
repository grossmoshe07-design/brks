import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.fernet import Fernet
import os
import sys
import base64 

# --- Configuration and Initialization ---

# PLACEHOLDER KEY (44 characters, valid Base64) for local testing.
SECRET_KEY_PLACEHOLDER = b'aGVsbG9fZnJvbV9teV9hdXRvbWF0ZWRfYnVpbGRfc2VjcmV0' 
FERNET_KEY_BYTES = None

KEY_FROM_ENV = os.environ.get('PROPRIETARY_SECRET_KEY')

if KEY_FROM_ENV:
    try:
        if len(KEY_FROM_ENV) != 44:
             # This check validates that the GitHub Action fix worked
             raise ValueError(f"Environment key has incorrect length ({len(KEY_FROM_ENV)}). Expected 44 characters.")
        FERNET_KEY_BYTES = KEY_FROM_ENV.encode('utf-8')
    except Exception as e:
        print(f"Error processing environment key: {e}. Falling back to placeholder.")
        FERNET_KEY_BYTES = SECRET_KEY_PLACEHOLDER
else:
    FERNET_KEY_BYTES = SECRET_KEY_PLACEHOLDER

try:
    FERNET = Fernet(FERNET_KEY_BYTES)
except ValueError as e:
    print(f"Key loaded: {FERNET_KEY_BYTES}")
    raise ValueError(f"Failed to initialize Fernet. Key length: {len(FERNET_KEY_BYTES)}. Detail: {e}")

# Changed extension to .brks
CUSTOM_EXTENSION = ".brks" 
CUSTOM_HEADER = b'MY_PROPRIETARY_HEADER_V1_0'
HEADER_LENGTH = len(CUSTOM_HEADER)
# --- End Configuration ---


# --- Main Application Class ---
class VideoToolApp:
    def __init__(self, master):
        self.master = master
        master.title("Proprietary Video Converter & Player")
        master.geometry("600x450") 
        
        self.selected_file_path = ""
        self.is_converter_logged_in = False 
        
        # Application now starts directly on the main interface (no initial login screen)
        self.create_main_interface() 

    # --- Main Interface (Notebook UI) ---
    def create_main_interface(self):
        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(pady=10, padx=10, expand=True, fill="both")

        self.converter_tab = tk.Frame(self.notebook, padding="10")
        self.player_tab = tk.Frame(self.notebook, padding="10")

        self.notebook.add(self.player_tab, text="▶️ Player (View .brks)")
        self.notebook.add(self.converter_tab, text="🎥 Converter (Login Required)")

        self._setup_player_tab()
        self._setup_converter_tab()

    # --- CONVERTER TAB LOGIC (LOCKED BY DEFAULT) ---
    def _setup_converter_tab(self):
        self.converter_main_frame = tk.Frame(self.converter_tab, padding="10")
        self.converter_main_frame.pack(expand=True, fill="both")

        self.conv_login_frame = self._create_converter_login_frame(self.converter_main_frame)
        self.conv_login_frame.pack(pady=50) 

        self.conv_tools_frame = self._create_converter_tools_frame(self.converter_main_frame)
    
    def _create_converter_login_frame(self, parent):
        frame = tk.Frame(parent)
        tk.Label(frame, text="*** Login Required to Access Converter Tools ***", fg="red", font=('Arial', 12, 'bold')).grid(row=0, column=0, columnspan=2, pady=10)
        
        tk.Label(frame, text="Username:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.user_entry = tk.Entry(frame)
        self.user_entry.grid(row=1, column=1, padx=10, pady=5)
        
        tk.Label(frame, text="Password:").grid(row=2, column=0, padx=10, pady=5, sticky="w")
        self.pass_entry = tk.Entry(frame, show="*")
        self.pass_entry.grid(row=2, column=1, padx=10, pady=5)
        
        tk.Button(frame, text="Login & Enable Converter", command=self._attempt_converter_login).grid(row=3, column=0, columnspan=2, pady=10)
        return frame

    def _create_converter_tools_frame(self, parent):
        frame = tk.Frame(parent, padding="10")
        
        tk.Button(frame, text="1. Select Standard MP4 Video", command=self.select_source_file).pack(pady=10, padx=10)
        
        self.conv_file_label = tk.Label(frame, text="No file selected.", wraplength=400)
        self.conv_file_label.pack(pady=5)
        
        tk.Button(frame, text=f"2. CONVERT and Encrypt to {CUSTOM_EXTENSION}", command=self.convert_file).pack(pady=20, padx=10)
        
        self.conv_status_label = tk.Label(frame, text="Status: Ready.", fg="blue")
        self.conv_status_label.pack(pady=10)
        
        return frame

    def _attempt_converter_login(self):
        if self.user_entry.get() == "admin" and self.pass_entry.get() == "secure123":
            self.is_converter_logged_in = True
            self.conv_login_frame.pack_forget() 
            self.conv_tools_frame.pack(expand=True, fill="both") 
            messagebox.showinfo("Login Success", "Converter Tools are now enabled.")
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")
            
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

    # --- PLAYER TAB LOGIC (UNLOCKED BY DEFAULT) ---
    def _setup_player_tab(self):
        tk.Button(self.player_tab, text=f"1. Open {CUSTOM_EXTENSION} Video File", command=self.open_proprietary_file).pack(pady=10, padx=10)
        
        self.player_status_label = tk.Label(self.player_tab, text=f"Status: Ready to load proprietary {CUSTOM_EXTENSION} file.", wraplength=400)
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
            
            # --- REAL-TIME VIDEO PLAYBACK LOGIC WOULD GO HERE ---
            
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
