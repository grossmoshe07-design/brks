import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.fernet import Fernet
import os
import sys

# --- Configuration ---
# THIS SECRET KEY IS THE FOUNDATION OF YOUR PROPRIETARY SYSTEM
# The script will now check the environment variable 'PROPRIETARY_SECRET_KEY'
# NOTE: This placeholder key MUST be 44 characters long and Base64-encoded to work.
# This placeholder is ONLY used if you run the script locally without setting the environment variable.
SECRET_KEY_PLACEHOLDER = b'aGVsbG9fZnJvbV9teV9hdXRvbWF0ZWRfYnVpbGRfc2VjcmV0' 

# Load the key from the environment variable set by GitHub Actions, 
# or use the placeholder if running locally without the environment variable set.
KEY_FROM_ENV = os.environ.get('PROPRIETARY_SECRET_KEY')

if KEY_FROM_ENV:
    # Key is loaded from the environment set during the CI build
    SECRET_KEY = KEY_FROM_ENV.encode('utf-8')
    # print("Using key from environment variable.") # This line is commented out but would confirm successful injection
else:
    # Key is loaded from the hardcoded placeholder
    SECRET_KEY = SECRET_KEY_PLACEHOLDER
    # print("Using placeholder key (for local testing only).") # For local testing confirmation
    
FERNET = Fernet(SECRET_KEY)
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
        
        # Start with the login frame
        self.login_frame = self.create_login_frame()
        self.login_frame.pack(expand=True, fill="both")

    # --- Login Screen UI ---
    def create_login_frame(self):
        frame = tk.Frame(self.master)
        
        # Centering elements
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
            self.master.geometry("600x450") # Adjust size for main content
            self.create_main_interface()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")

    # --- Main Interface (Notebook UI) ---
    def create_main_interface(self):
        # Create a Notebook (Tabbed Interface)
        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(pady=10, padx=10, expand=True, fill="both")

        # Create the two main tabs
        self.converter_tab = tk.Frame(self.notebook, padding="10")
        self.player_tab = tk.Frame(self.notebook, padding="10")

        self.notebook.add(self.converter_tab, text="🎥 Converter (Create .myformat)")
        self.notebook.add(self.player_tab, text="▶️ Player (View .myformat)")

        self._setup_converter_tab()
        self._setup_player_tab()

    # --- CONVERTER TAB LOGIC ---
    def _setup_converter_tab(self):
        # File Selector Button
        tk.Button(self.converter_tab, text="1. Select Standard MP4 Video", command=self.select_source_file).pack(pady=10, padx=10)
        
        # Display Selected File Path
        self.conv_file_label = tk.Label(self.converter_tab, text="No file selected.", wraplength=400)
        self.conv_file_label.pack(pady=5)
        
        # Conversion Button
        tk.Button(self.converter_tab, text=f"2. CONVERT and Encrypt to {CUSTOM_EXTENSION}", command=self.convert_file).pack(pady=20, padx=10)
        
        # Status
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
            
            # 1. Read the original file
            with open(self.selected_file_path, 'rb') as f:
                original_data = f.read()

            # 2. Encrypt the data
            encrypted_data = FERNET.encrypt(original_data)

            # 3. Create the output path
            base_name = os.path.splitext(self.selected_file_path)[0]
            output_path = base_name + CUSTOM_EXTENSION
            
            # 4. Write the proprietary file (Header + Encrypted Data)
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
        # File Selector Button
        tk.Button(self.player_tab, text=f"1. Open {CUSTOM_EXTENSION} Video File", command=self.open_proprietary_file).pack(pady=10, padx=10)
        
        # Player Placeholder/Status
        self.player_status_label = tk.Label(self.player_tab, text="Status: Ready to load proprietary file.", wraplength=400)
        self.player_status_label.pack(pady=10)
        
        tk.Label(self.player_tab, text="Video Display Area (Requires C-based Library Integration)").pack(pady=20)


    def open_proprietary_file(self):
        # Open file dialog for your proprietary files
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
            # 1. Read the proprietary file
            with open(file_path, 'rb') as f:
                # 2. Check the proprietary header
                header_check = f.read(HEADER_LENGTH)
                if header_check != CUSTOM_HEADER:
                    raise ValueError("File is not a valid proprietary format (Missing Header).")
                
                encrypted_data = f.read()
            
            # 3. Decrypt the data
            decrypted_data = FERNET.decrypt(encrypted_data)
            
            # 4. Player Integration (Concept)
            # --- REAL-TIME VIDEO PLAYBACK LOGIC GOES HERE ---
            # This is where the video playback engine would stream the decrypted_data buffer.
            
            # Success Message:
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
