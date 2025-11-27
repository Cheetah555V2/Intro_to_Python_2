import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import sys
import traceback

# Add the program directory to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'program', 'md'))

# Import your modules
import program.md.console_command as cc
import program.md.decorator as decorator
import program.md.RSAoj as RSAoj
import program.md.RSAmath as RSAmath
import program.md.primitive_test as pt
from program.md.RSAerror import *

class RSAApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA Encryption System")
        self.root.geometry("800x600")
        
        # Define paths
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.unencrypt_dir = os.path.join(self.base_dir, "user_payload", "unencrypt_file")
        self.encrypt_dir = os.path.join(self.base_dir, "user_payload", "encrypt_file")
        self.user_dir = os.path.join(self.base_dir, "user")
        
        # Create directories if they don't exist
        os.makedirs(self.unencrypt_dir, exist_ok=True)
        os.makedirs(self.encrypt_dir, exist_ok=True)
        os.makedirs(self.user_dir, exist_ok=True)
        
        # Current state variables
        self.current_file = None
        self.current_keys = None
        
        # Start with menu screen
        self.show_menu_screen()
    
    def clear_screen(self):
        """Clear all widgets from the screen"""
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def create_back_button(self, command):
        """Create a back button"""
        back_btn = ttk.Button(self.root, text="← Back", command=command)
        back_btn.pack(anchor="nw", padx=10, pady=10)
    
    def show_menu_screen(self):
        """Screen 1: Main menu"""
        self.clear_screen()
        
        # Title
        title_label = ttk.Label(self.root, text="RSA Encryption System", 
                               font=("Arial", 20, "bold"))
        title_label.pack(pady=40)
        
        # Buttons
        encrypt_btn = ttk.Button(self.root, text="Encrypt a File", 
                                command=self.show_encrypt_file_selection,
                                width=30)
        encrypt_btn.pack(pady=15)
        
        decrypt_btn = ttk.Button(self.root, text="Decrypt a File", 
                                command=self.show_decrypt_file_selection,
                                width=30)
        decrypt_btn.pack(pady=15)
        
        quit_btn = ttk.Button(self.root, text="Quit", 
                             command=self.root.quit,
                             width=30)
        quit_btn.pack(pady=15)
    
    def show_encrypt_file_selection(self):
        """Screen 2.1: Encrypt file selection"""
        self.clear_screen()
        self.create_back_button(self.show_menu_screen)
        
        title_label = ttk.Label(self.root, text="Select File to Encrypt", 
                               font=("Arial", 16, "bold"))
        title_label.pack(pady=20)
        
        # Instructions
        instr_label = ttk.Label(self.root, 
                               text="Place your file in: " + self.unencrypt_dir,
                               wraplength=600)
        instr_label.pack(pady=10)
        
        # File list frame
        file_frame = ttk.Frame(self.root)
        file_frame.pack(pady=20, fill="both", expand=True, padx=50)
        
        # Scrollable file list
        file_listbox_frame = ttk.Frame(file_frame)
        file_listbox_frame.pack(fill="both", expand=True)
        
        file_listbox = tk.Listbox(file_listbox_frame, height=10)
        scrollbar = ttk.Scrollbar(file_listbox_frame, orient="vertical", 
                                 command=file_listbox.yview)
        file_listbox.configure(yscrollcommand=scrollbar.set)
        
        file_listbox.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Refresh button
        refresh_btn = ttk.Button(file_frame, text="Refresh", 
                                command=lambda: self.update_file_list(file_listbox, self.unencrypt_dir))
        refresh_btn.pack(pady=10)
        
        # Manual file entry
        manual_frame = ttk.Frame(self.root)
        manual_frame.pack(pady=10)
        
        ttk.Label(manual_frame, text="Or enter filename:").pack(side="left")
        file_entry = ttk.Entry(manual_frame, width=30)
        file_entry.pack(side="left", padx=5)
        
        # Continue button
        continue_btn = ttk.Button(self.root, text="Continue", 
                                 command=lambda: self.select_encrypt_file(file_listbox, file_entry),
                                 state="disabled")
        continue_btn.pack(pady=20)
        
        # Update file list and bind selection
        self.update_file_list(file_listbox, self.unencrypt_dir)
        file_listbox.bind('<<ListboxSelect>>', 
                         lambda e: self.on_file_select(file_listbox, continue_btn))
        file_entry.bind('<KeyRelease>', 
                       lambda e: self.on_file_entry_change(file_entry, continue_btn))
    
    def show_decrypt_file_selection(self):
        """Screen 2.2: Decrypt file selection"""
        self.clear_screen()
        self.create_back_button(self.show_menu_screen)
        
        title_label = ttk.Label(self.root, text="Select File to Decrypt", 
                               font=("Arial", 16, "bold"))
        title_label.pack(pady=20)
        
        # Instructions
        instr_label = ttk.Label(self.root, 
                               text="Place your file in: " + self.encrypt_dir,
                               wraplength=600)
        instr_label.pack(pady=10)
        
        # File list frame
        file_frame = ttk.Frame(self.root)
        file_frame.pack(pady=20, fill="both", expand=True, padx=50)
        
        # Scrollable file list
        file_listbox_frame = ttk.Frame(file_frame)
        file_listbox_frame.pack(fill="both", expand=True)
        
        file_listbox = tk.Listbox(file_listbox_frame, height=10)
        scrollbar = ttk.Scrollbar(file_listbox_frame, orient="vertical", 
                                 command=file_listbox.yview)
        file_listbox.configure(yscrollcommand=scrollbar.set)
        
        file_listbox.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Refresh button
        refresh_btn = ttk.Button(file_frame, text="Refresh", 
                                command=lambda: self.update_file_list(file_listbox, self.encrypt_dir))
        refresh_btn.pack(pady=10)
        
        # Manual file entry
        manual_frame = ttk.Frame(self.root)
        manual_frame.pack(pady=10)
        
        ttk.Label(manual_frame, text="Or enter filename:").pack(side="left")
        file_entry = ttk.Entry(manual_frame, width=30)
        file_entry.pack(side="left", padx=5)
        
        # Continue button
        continue_btn = ttk.Button(self.root, text="Continue", 
                                 command=lambda: self.select_decrypt_file(file_listbox, file_entry),
                                 state="disabled")
        continue_btn.pack(pady=20)
        
        # Update file list and bind selection
        self.update_file_list(file_listbox, self.encrypt_dir)
        file_listbox.bind('<<ListboxSelect>>', 
                         lambda e: self.on_file_select(file_listbox, continue_btn))
        file_entry.bind('<KeyRelease>', 
                       lambda e: self.on_file_entry_change(file_entry, continue_btn))
    
    def show_encrypt_key_choice(self):
        """Screen 3.1: Encrypt key choice"""
        self.clear_screen()
        self.create_back_button(self.show_encrypt_file_selection)
        
        title_label = ttk.Label(self.root, text="Choose RSA Key Source", 
                               font=("Arial", 16, "bold"))
        title_label.pack(pady=30)
        
        # Buttons for different options
        input_btn = ttk.Button(self.root, text="Input My Own RSA Key Pair", 
                              command=self.show_user_key_input,
                              width=30)
        input_btn.pack(pady=15)
        
        existing_btn = ttk.Button(self.root, text="Choose Existing User", 
                                 command=self.show_user_selection,
                                 width=30)
        existing_btn.pack(pady=15)
        
        generate_btn = ttk.Button(self.root, text="Generate New RSA Key Pair", 
                                 command=self.show_key_generation,
                                 width=30)
        generate_btn.pack(pady=15)
    
    def show_decrypt_key_choice(self):
        """Screen 3.2: Decrypt key choice"""
        self.clear_screen()
        self.create_back_button(self.show_decrypt_file_selection)
        
        title_label = ttk.Label(self.root, text="Choose Private Key Source", 
                               font=("Arial", 16, "bold"))
        title_label.pack(pady=30)
        
        # Buttons for different options
        existing_btn = ttk.Button(self.root, text="Choose Existing User", 
                                 command=self.show_decrypt_user_selection,
                                 width=30)
        existing_btn.pack(pady=15)
        
        input_btn = ttk.Button(self.root, text="Input My Own Private Key", 
                              command=self.show_decrypt_key_input,
                              width=30)
        input_btn.pack(pady=15)
    
    def show_decrypt_user_selection(self):
        """Screen for selecting existing user for decryption"""
        self.clear_screen()
        self.create_back_button(self.show_decrypt_key_choice)
        
        title_label = ttk.Label(self.root, text="Select User for Decryption", 
                               font=("Arial", 16, "bold"))
        title_label.pack(pady=20)
        
        # User list frame
        user_frame = ttk.Frame(self.root)
        user_frame.pack(pady=20, fill="both", expand=True, padx=50)
        
        # Scrollable user list
        user_listbox_frame = ttk.Frame(user_frame)
        user_listbox_frame.pack(fill="both", expand=True)
        
        user_listbox = tk.Listbox(user_listbox_frame, height=10)
        scrollbar = ttk.Scrollbar(user_listbox_frame, orient="vertical", 
                                 command=user_listbox.yview)
        user_listbox.configure(yscrollcommand=scrollbar.set)
        
        user_listbox.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Manual user entry
        manual_frame = ttk.Frame(self.root)
        manual_frame.pack(pady=10)
        
        ttk.Label(manual_frame, text="Or enter username:").pack(side="left")
        user_entry = ttk.Entry(manual_frame, width=30)
        user_entry.pack(side="left", padx=5)
        
        # Continue button
        continue_btn = ttk.Button(self.root, text="Continue", 
                                 command=lambda: self.select_user_for_decryption(user_listbox, user_entry),
                                 state="disabled")
        continue_btn.pack(pady=20)
        
        # Update user list and bind selection
        self.update_user_list(user_listbox)
        user_listbox.bind('<<ListboxSelect>>', 
                         lambda e: self.on_user_select(user_listbox, continue_btn))
        user_entry.bind('<KeyRelease>', 
                       lambda e: self.on_user_entry_change(user_entry, continue_btn))
    
    def show_decrypt_key_input(self):
        """Screen for inputting private key manually"""
        self.clear_screen()
        self.create_back_button(self.show_decrypt_key_choice)
        
        title_label = ttk.Label(self.root, text="Enter Private Key", 
                               font=("Arial", 16, "bold"))
        title_label.pack(pady=30)
        
        # Private exponent input
        key_frame = ttk.Frame(self.root)
        key_frame.pack(pady=20)
        
        ttk.Label(key_frame, text="Private Exponent (d):").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        d_entry = ttk.Entry(key_frame, width=50)
        d_entry.grid(row=0, column=1, padx=5, pady=5)
        
        # Continue button
        continue_btn = ttk.Button(self.root, text="Continue", 
                                 command=lambda: self.decrypt_file(d_entry.get()))
        continue_btn.pack(pady=20)
    
    def show_user_key_input(self):
        """Screen 4.1: User's own key input"""
        self.clear_screen()
        self.create_back_button(self.show_encrypt_key_choice)
        
        title_label = ttk.Label(self.root, text="Input Your RSA Keys", 
                               font=("Arial", 16, "bold"))
        title_label.pack(pady=30)
        
        # Key input frame
        key_frame = ttk.Frame(self.root)
        key_frame.pack(pady=20)
        
        ttk.Label(key_frame, text="Public Modulus (n):").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        n_entry = ttk.Entry(key_frame, width=50)
        n_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(key_frame, text="Public Exponent (e):").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        e_entry = ttk.Entry(key_frame, width=50)
        e_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # Continue button
        continue_btn = ttk.Button(self.root, text="Continue", 
                                 command=lambda: self.set_custom_keys(n_entry.get(), e_entry.get()))
        continue_btn.pack(pady=20)
    
    def show_user_selection(self):
        """Screen 4.2: Existing user selection"""
        self.clear_screen()
        self.create_back_button(self.show_encrypt_key_choice)
        
        title_label = ttk.Label(self.root, text="Select Existing User", 
                               font=("Arial", 16, "bold"))
        title_label.pack(pady=20)
        
        # User list frame
        user_frame = ttk.Frame(self.root)
        user_frame.pack(pady=20, fill="both", expand=True, padx=50)
        
        # Scrollable user list
        user_listbox_frame = ttk.Frame(user_frame)
        user_listbox_frame.pack(fill="both", expand=True)
        
        user_listbox = tk.Listbox(user_listbox_frame, height=10)
        scrollbar = ttk.Scrollbar(user_listbox_frame, orient="vertical", 
                                 command=user_listbox.yview)
        user_listbox.configure(yscrollcommand=scrollbar.set)
        
        user_listbox.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Manual user entry
        manual_frame = ttk.Frame(self.root)
        manual_frame.pack(pady=10)
        
        ttk.Label(manual_frame, text="Or enter username:").pack(side="left")
        user_entry = ttk.Entry(manual_frame, width=30)
        user_entry.pack(side="left", padx=5)
        
        # Continue button
        continue_btn = ttk.Button(self.root, text="Continue", 
                                 command=lambda: self.select_user(user_listbox, user_entry),
                                 state="disabled")
        continue_btn.pack(pady=20)
        
        # Update user list and bind selection
        self.update_user_list(user_listbox)
        user_listbox.bind('<<ListboxSelect>>', 
                         lambda e: self.on_user_select(user_listbox, continue_btn))
        user_entry.bind('<KeyRelease>', 
                       lambda e: self.on_user_entry_change(user_entry, continue_btn))
    
    def show_key_generation(self):
        """Screen 4.3: Key generation"""
        self.clear_screen()
        self.create_back_button(self.show_encrypt_key_choice)
        
        title_label = ttk.Label(self.root, text="Generate New RSA Keys", 
                               font=("Arial", 16, "bold"))
        title_label.pack(pady=20)
        
        # Generate button
        generate_btn = ttk.Button(self.root, text="Generate Keys", 
                                 command=self.generate_keys)
        generate_btn.pack(pady=10)
        
        # Results frame (initially empty)
        self.results_frame = ttk.Frame(self.root)
        self.results_frame.pack(pady=20, fill="both", expand=True, padx=50)
    
    def show_save_user_screen(self):
        """Screen 5.1: Save user screen"""
        self.clear_screen()
        self.create_back_button(self.show_key_generation)
        
        title_label = ttk.Label(self.root, text="Save User Profile", 
                               font=("Arial", 16, "bold"))
        title_label.pack(pady=20)
        
        # Display generated keys
        keys_frame = ttk.Frame(self.root)
        keys_frame.pack(pady=10, fill="x", padx=50)
        
        ttk.Label(keys_frame, text="Public Modulus (n):").grid(row=0, column=0, sticky="w")
        ttk.Label(keys_frame, text=str(self.current_keys.n)).grid(row=0, column=1, sticky="w")
        
        ttk.Label(keys_frame, text="Public Exponent (e):").grid(row=1, column=0, sticky="w")
        ttk.Label(keys_frame, text=str(self.current_keys.e)).grid(row=1, column=1, sticky="w")
        
        ttk.Label(keys_frame, text="Private Exponent (d):").grid(row=2, column=0, sticky="w")
        ttk.Label(keys_frame, text=str(self.current_keys._d)).grid(row=2, column=1, sticky="w")
        
        # Username input
        user_frame = ttk.Frame(self.root)
        user_frame.pack(pady=20)
        
        ttk.Label(user_frame, text="Username:").pack(side="left")
        username_entry = ttk.Entry(user_frame, width=20)
        username_entry.pack(side="left", padx=5)
        
        # Buttons
        btn_frame = ttk.Frame(self.root)
        btn_frame.pack(pady=10)
        
        save_btn = ttk.Button(btn_frame, text="Save User", 
                             command=lambda: self.save_user(username_entry.get()))
        save_btn.pack(side="left", padx=5)
        
        skip_btn = ttk.Button(btn_frame, text="Skip Saving", 
                             command=self.encrypt_file)
        skip_btn.pack(side="left", padx=5)
        
        # Status label
        self.status_label = ttk.Label(self.root, text="")
        self.status_label.pack(pady=5)
    
    def show_encrypt_result(self, success, file_path=None):
        """Screen 6.1: Encryption result"""
        self.clear_screen()
        
        if success:
            title_label = ttk.Label(self.root, text="Encryption Successful!", 
                                   font=("Arial", 16, "bold"), foreground="green")
            title_label.pack(pady=20)
            
            ttk.Label(self.root, text=f"Encrypted file saved to:\n{file_path}").pack(pady=10)
        else:
            title_label = ttk.Label(self.root, text="Encryption Failed", 
                                   font=("Arial", 16, "bold"), foreground="red")
            title_label.pack(pady=20)
            
            ttk.Label(self.root, text="Cannot encrypt with the current RSA keys pair").pack(pady=10)
        
        # Back to menu button
        menu_btn = ttk.Button(self.root, text="Back to Menu", 
                             command=self.show_menu_screen)
        menu_btn.pack(pady=20)
    
    def show_decrypt_result(self, success, file_path=None):
        """Screen 4.4: Decryption result"""
        self.clear_screen()
        
        if success:
            title_label = ttk.Label(self.root, text="Decryption Successful!", 
                                   font=("Arial", 16, "bold"), foreground="green")
            title_label.pack(pady=20)
            
            ttk.Label(self.root, text=f"Decrypted file saved to:\n{file_path}").pack(pady=10)
        else:
            title_label = ttk.Label(self.root, text="Decryption Failed", 
                                   font=("Arial", 16, "bold"), foreground="red")
            title_label.pack(pady=20)
            
            ttk.Label(self.root, text="Cannot decrypt with the current private exponent").pack(pady=10)
        
        # Back to menu button
        menu_btn = ttk.Button(self.root, text="Back to Menu", 
                             command=self.show_menu_screen)
        menu_btn.pack(pady=20)
    
    # Helper methods
    def update_file_list(self, listbox, directory):
        """Update file listbox with files from directory"""
        listbox.delete(0, tk.END)
        try:
            files = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
            for file in files:
                listbox.insert(tk.END, file)
        except Exception as e:
            messagebox.showerror("Error", f"Could not read directory: {e}")
    
    def update_user_list(self, listbox):
        """Update user listbox with users from user directory"""
        listbox.delete(0, tk.END)
        try:
            users = [f.replace('.txt', '') for f in os.listdir(self.user_dir) 
                    if f.endswith('.txt') and os.path.isfile(os.path.join(self.user_dir, f))]
            for user in users:
                listbox.insert(tk.END, user)
        except Exception as e:
            messagebox.showerror("Error", f"Could not read user directory: {e}")
    
    def on_file_select(self, listbox, button):
        """Enable continue button when file is selected"""
        if listbox.curselection():
            button.config(state="normal")
    
    def on_file_entry_change(self, entry, button):
        """Enable continue button when file entry has text"""
        if entry.get().strip():
            button.config(state="normal")
        else:
            button.config(state="disabled")
    
    def on_user_select(self, listbox, button):
        """Enable continue button when user is selected"""
        if listbox.curselection():
            button.config(state="normal")
    
    def on_user_entry_change(self, entry, button):
        """Enable continue button when user entry has text"""
        if entry.get().strip():
            button.config(state="normal")
        else:
            button.config(state="disabled")
    
    def select_encrypt_file(self, listbox, entry):
        """Select file for encryption and proceed"""
        filename = ""
        if listbox.curselection():
            filename = listbox.get(listbox.curselection()[0])
        else:
            filename = entry.get().strip()
        
        if filename:
            file_path = os.path.join(self.unencrypt_dir, filename)
            if os.path.exists(file_path):
                self.current_file = file_path
                self.show_encrypt_key_choice()
            else:
                messagebox.showerror("Error", "File does not exist")
        else:
            messagebox.showwarning("Warning", "Please select or enter a filename")
    
    def select_decrypt_file(self, listbox, entry):
        """Select file for decryption and proceed"""
        filename = ""
        if listbox.curselection():
            filename = listbox.get(listbox.curselection()[0])
        else:
            filename = entry.get().strip()
        
        if filename:
            file_path = os.path.join(self.encrypt_dir, filename)
            if os.path.exists(file_path):
                self.current_file = file_path
                # CHANGED: Go to decrypt key choice screen instead of direct key input
                self.show_decrypt_key_choice()
            else:
                messagebox.showerror("Error", "File does not exist")
        else:
            messagebox.showwarning("Warning", "Please select or enter a filename")
    
    def select_user(self, listbox, entry):
        """Select user and load their keys for encryption"""
        username = ""
        if listbox.curselection():
            username = listbox.get(listbox.curselection()[0])
        else:
            username = entry.get().strip()
        
        if username:
            user_file = os.path.join(self.user_dir, username + ".txt")
            if os.path.exists(user_file):
                try:
                    with open(user_file, 'r') as f:
                        content = f.read().split('\n')
                        n = int(content[0].split('=')[1].strip())
                        e = int(content[1].split('=')[1].strip())
                        d = int(content[2].split('=')[1].strip())
                    
                    self.current_keys = RSAoj.RSAKeyPair(n=n, e=e, d=d)
                    self.encrypt_file()
                except Exception as e:
                    messagebox.showerror("Error", f"Could not load user keys: {e}")
            else:
                messagebox.showerror("Error", "User file does not exist")
        else:
            messagebox.showwarning("Warning", "Please select or enter a username")
    
    def select_user_for_decryption(self, listbox, entry):
        """Select user for decryption and extract private key"""
        username = ""
        if listbox.curselection():
            username = listbox.get(listbox.curselection()[0])
        else:
            username = entry.get().strip()
        
        if username:
            user_file = os.path.join(self.user_dir, username + ".txt")
            if os.path.exists(user_file):
                try:
                    with open(user_file, 'r') as f:
                        content = f.read().split('\n')
                        # Extract private key (d) from user file
                        d = int(content[2].split('=')[1].strip())
                    
                    # Use the private key for decryption
                    self.decrypt_file(str(d))
                    
                except Exception as e:
                    messagebox.showerror("Error", f"Could not load user keys: {e}")
            else:
                messagebox.showerror("Error", "User file does not exist")
        else:
            messagebox.showwarning("Warning", "Please select or enter a username")
    
    def set_custom_keys(self, n_str, e_str):
        """Set custom keys from user input"""
        try:
            n = int(n_str)
            e = int(e_str)
            self.current_keys = RSAoj.RSAKeyPair(n=n, e=e)
            self.encrypt_file()
        except ValueError:
            messagebox.showerror("Error", "Please enter valid integers for n and e")
        except Exception as e:
            messagebox.showerror("Error", f"Invalid keys: {e}")
    
    def generate_keys(self):
        """Generate new RSA keys"""
        try:
            # Clear previous results
            for widget in self.results_frame.winfo_children():
                widget.destroy()
            
            # Generate keys
            key_pair = RSAoj.RSAKeyPair()
            key_pair.generate_keys(digits=10)  # Smaller digits for faster generation
            
            self.current_keys = key_pair
            
            # Display results
            ttk.Label(self.results_frame, text="Generated Keys:", 
                     font=("Arial", 12, "bold")).pack(pady=10)
            
            ttk.Label(self.results_frame, text=f"Public Modulus (n): {key_pair.n}").pack(anchor="w")
            ttk.Label(self.results_frame, text=f"Public Exponent (e): {key_pair.e}").pack(anchor="w")
            ttk.Label(self.results_frame, text=f"Private Exponent (d): {key_pair._d}").pack(anchor="w")
            
            # Buttons
            btn_frame = ttk.Frame(self.results_frame)
            btn_frame.pack(pady=20)
            
            save_btn = ttk.Button(btn_frame, text="Save User", 
                                 command=self.show_save_user_screen)
            save_btn.pack(side="left", padx=5)
            
            encrypt_btn = ttk.Button(btn_frame, text="Encrypt Without Saving", 
                                    command=self.encrypt_file)
            encrypt_btn.pack(side="left", padx=5)
            
        except Exception as e:
            messagebox.showerror("Error", f"Key generation failed: {e}")
    
    def save_user(self, username):
        """Save user profile"""
        if not username:
            self.status_label.config(text="Please enter a username", foreground="red")
            return
        
        user_file = os.path.join(self.user_dir, username + ".txt")
        if os.path.exists(user_file):
            self.status_label.config(text="Username already exists", foreground="red")
            return
        
        try:
            with open(user_file, 'w') as f:
                f.write(f"n = {self.current_keys.n}\n")
                f.write(f"e = {self.current_keys.e}\n")
                f.write(f"d = {self.current_keys._d}\n")
            
            self.status_label.config(text="User saved successfully!", foreground="green")
            # Proceed to encryption after a short delay
            self.root.after(1000, self.encrypt_file)
            
        except Exception as e:
            self.status_label.config(text=f"Error saving user: {e}", foreground="red")
    
    @decorator.error_handler
    def encrypt_file(self):
        """Encrypt the current file"""
        if not self.current_file or not self.current_keys:
            messagebox.showerror("Error", "No file or keys selected")
            return
        
        try:
            # Read file content
            with open(self.current_file, 'r', encoding='utf_8') as f:
                content = f.read()
            
            # Encrypt each character
            encrypted_chars = []
            for char in content:
                unicode_val = ord(char)
                encrypted_char = pow(unicode_val, self.current_keys.e, self.current_keys.n)
                encrypted_chars.append(str(encrypted_char))
            
            # Create output filename
            input_filename = os.path.basename(self.current_file)
            output_file = os.path.join(self.encrypt_dir, input_filename)
            
            # Write encrypted file
            with open(output_file, 'w', encoding='utf_8') as f:
                f.write(", ".join(encrypted_chars) + "\n")
                f.write(f"n = {self.current_keys.n}\n")
                f.write(f"e = {self.current_keys.e}\n")
            
            self.show_encrypt_result(True, output_file)
            
        except Exception as e:
            print(f"Encryption error: {e}")
            self.show_encrypt_result(False)
    
    @decorator.error_handler
    def decrypt_file(self, d_str):
        """Decrypt the current file"""
        if not self.current_file or not d_str:
            messagebox.showerror("Error", "No file or private key provided")
            return
        
        try:
            d = int(d_str)
            
            # Read encrypted file
            with open(self.current_file, 'r', encoding='utf_8') as f:
                lines = f.readlines()
            
            # Parse encrypted data and keys
            encrypted_chars = [int(x.strip()) for x in lines[0].split(",")]
            
            # Find n from the file or use the one from user input
            n = None
            for line in lines[1:]:
                if line.startswith("n = "):
                    n = int(line.split("=")[1].strip())
                    break
            
            if not n:
                messagebox.showerror("Error", "Could not find modulus (n) in encrypted file")
                return
            
            # Decrypt each character
            decrypted_chars = []
            for encrypted_char in encrypted_chars:
                decrypted_val = pow(encrypted_char, d, n)
                try:
                    decrypted_chars.append(chr(decrypted_val))
                except ValueError:
                    self.show_decrypt_result(False)
                    return
            
            # Create output filename
            input_filename = os.path.basename(self.current_file)
            output_file = os.path.join(self.unencrypt_dir, input_filename)
            
            # Write decrypted file
            with open(output_file, 'w', encoding='utf_8') as f:
                f.write(''.join(decrypted_chars))
            
            self.show_decrypt_result(True, output_file)
            
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid integer for private exponent")
        except Exception as e:
            print(f"Decryption error: {e}")
            self.show_decrypt_result(False)

@decorator.error_handler
def main():
    root = tk.Tk()
    app = RSAApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()