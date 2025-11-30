#!/usr/bin/env python3
#https://127.0.0.1:8000/ui/
#http://127.0.0.1:8000/ui/
"""
GUI for file_server.py using CustomTkinter.

Provides a modern interface to configure and run the file server with real-time logs.
"""

import json
import os
import queue
import subprocess
import sys
import threading
from pathlib import Path

import customtkinter as ctk
from tkinter import filedialog, messagebox, scrolledtext

# Config file
CONFIG_FILE = Path(__file__).parent / "server_gui_config.json"

class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("File Server GUI")
        self.root.geometry("1200x800")
        self.root.resizable(True, True)

        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        self.server_process = None
        self.log_queue = queue.Queue()
        self.config = self.load_config()

        self.create_widgets()
        self.start_log_thread()

    def create_widgets(self):
        # Main container
        main_frame = ctk.CTkFrame(self.root)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Left panel for settings
        left_panel = ctk.CTkScrollableFrame(main_frame, width=400)
        left_panel.pack(side="left", fill="y", padx=(0,10))

        # Server Settings
        server_frame = ctk.CTkFrame(left_panel)
        server_frame.pack(fill="x", pady=(0,10))

        ctk.CTkLabel(server_frame, text="Server Settings", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)

        # Host
        ctk.CTkLabel(server_frame, text="Host:").pack(anchor="w", padx=10)
        self.host_entry = ctk.CTkEntry(server_frame)
        self.host_entry.pack(fill="x", padx=10, pady=(0,10))
        self.host_entry.insert(0, self.config.get("host", "0.0.0.0"))

        # Port
        ctk.CTkLabel(server_frame, text="Port:").pack(anchor="w", padx=10)
        self.port_entry = ctk.CTkEntry(server_frame)
        self.port_entry.pack(fill="x", padx=10, pady=(0,10))
        self.port_entry.insert(0, str(self.config.get("port", 8080)))

        # Directory
        ctk.CTkLabel(server_frame, text="Directory:").pack(anchor="w", padx=10)
        dir_frame = ctk.CTkFrame(server_frame, fg_color="transparent")
        dir_frame.pack(fill="x", padx=10, pady=(0,10))
        self.dir_entry = ctk.CTkEntry(dir_frame)
        self.dir_entry.pack(side="left", fill="x", expand=True)
        self.dir_entry.insert(0, self.config.get("dir", "data"))
        ctk.CTkButton(dir_frame, text="Browse", width=80, command=self.browse_dir).pack(side="right", padx=(10,0))

        # Protocol
        ctk.CTkLabel(server_frame, text="Protocol:").pack(anchor="w", padx=10)
        self.protocol_combo = ctk.CTkComboBox(server_frame, values=["http", "https", "ftp"])
        self.protocol_combo.pack(fill="x", padx=10, pady=(0,10))
        self.protocol_combo.set(self.config.get("protocol", "http"))

        # Auth Settings
        auth_frame = ctk.CTkFrame(left_panel)
        auth_frame.pack(fill="x", pady=(0,10))

        ctk.CTkLabel(auth_frame, text="Authentication", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)

        # Token
        ctk.CTkLabel(auth_frame, text="Token:").pack(anchor="w", padx=10)
        self.token_entry = ctk.CTkEntry(auth_frame)
        self.token_entry.pack(fill="x", padx=10, pady=(0,10))
        self.token_entry.insert(0, self.config.get("token", ""))

        # Basic Auth
        ctk.CTkLabel(auth_frame, text="Basic User:").pack(anchor="w", padx=10)
        self.basic_user_entry = ctk.CTkEntry(auth_frame)
        self.basic_user_entry.pack(fill="x", padx=10, pady=(0,10))
        self.basic_user_entry.insert(0, self.config.get("basic_user", ""))

        ctk.CTkLabel(auth_frame, text="Basic Pass:").pack(anchor="w", padx=10)
        self.basic_pass_entry = ctk.CTkEntry(auth_frame, show="*")
        self.basic_pass_entry.pack(fill="x", padx=10, pady=(0,10))
        self.basic_pass_entry.insert(0, self.config.get("basic_pass", ""))

        # TLS Settings
        tls_frame = ctk.CTkFrame(left_panel)
        tls_frame.pack(fill="x", pady=(0,10))

        ctk.CTkLabel(tls_frame, text="TLS Settings", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)

        # Cert
        ctk.CTkLabel(tls_frame, text="Cert File:").pack(anchor="w", padx=10)
        cert_frame = ctk.CTkFrame(tls_frame, fg_color="transparent")
        cert_frame.pack(fill="x", padx=10, pady=(0,10))
        self.cert_entry = ctk.CTkEntry(cert_frame)
        self.cert_entry.pack(side="left", fill="x", expand=True)
        self.cert_entry.insert(0, self.config.get("cert", ""))
        ctk.CTkButton(cert_frame, text="Browse", width=80, command=lambda: self.browse_file(self.cert_entry)).pack(side="right", padx=(10,0))

        # Key
        ctk.CTkLabel(tls_frame, text="Key File:").pack(anchor="w", padx=10)
        key_frame = ctk.CTkFrame(tls_frame, fg_color="transparent")
        key_frame.pack(fill="x", padx=10, pady=(0,10))
        self.key_entry = ctk.CTkEntry(key_frame)
        self.key_entry.pack(side="left", fill="x", expand=True)
        self.key_entry.insert(0, self.config.get("key", ""))
        ctk.CTkButton(key_frame, text="Browse", width=80, command=lambda: self.browse_file(self.key_entry)).pack(side="right", padx=(10,0))

        # Generate Self-Signed
        self.gen_self_var = ctk.BooleanVar(value=self.config.get("generate_self_signed", False))
        ctk.CTkCheckBox(tls_frame, text="Generate Self-Signed Cert", variable=self.gen_self_var).pack(anchor="w", padx=10, pady=(0,10))

        # FTP Settings
        ftp_frame = ctk.CTkFrame(left_panel)
        ftp_frame.pack(fill="x", pady=(0,10))

        ctk.CTkLabel(ftp_frame, text="FTP Settings", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)

        # Allow Anonymous
        self.ftp_anon_var = ctk.BooleanVar(value=self.config.get("ftp_allow_anonymous", False))
        ctk.CTkCheckBox(ftp_frame, text="Allow Anonymous", variable=self.ftp_anon_var).pack(anchor="w", padx=10, pady=(0,10))

        # Permissions
        ctk.CTkLabel(ftp_frame, text="Permissions:").pack(anchor="w", padx=10)
        self.ftp_perm_combo = ctk.CTkComboBox(ftp_frame, values=["read", "write", "full"])
        self.ftp_perm_combo.pack(fill="x", padx=10, pady=(0,10))
        self.ftp_perm_combo.set(self.config.get("ftp_permissions", "full"))

        # Actions
        actions_frame = ctk.CTkFrame(left_panel)
        actions_frame.pack(fill="x", pady=(0,10))

        ctk.CTkLabel(actions_frame, text="Actions", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)

        self.start_btn = ctk.CTkButton(actions_frame, text="Start Server", command=self.start_server)
        self.start_btn.pack(fill="x", padx=10, pady=(0,10))

        self.stop_btn = ctk.CTkButton(actions_frame, text="Stop Server", command=self.stop_server, state="disabled")
        self.stop_btn.pack(fill="x", padx=10, pady=(0,10))

        self.save_btn = ctk.CTkButton(actions_frame, text="Save Config", command=self.save_config)
        self.save_btn.pack(fill="x", padx=10, pady=(0,10))

        # Right panel for logs
        right_panel = ctk.CTkFrame(main_frame)
        right_panel.pack(side="right", fill="both", expand=True)

        ctk.CTkLabel(right_panel, text="Server Logs", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)

        self.log_text = scrolledtext.ScrolledText(right_panel, wrap="word", state="disabled", bg="#2b2b2b", fg="white", insertbackground="white")
        self.log_text.pack(fill="both", expand=True, padx=10, pady=(0,10))

        # Status bar
        self.status_label = ctk.CTkLabel(self.root, text="Ready")
        self.status_label.pack(fill="x", padx=10, pady=(0,10))

    def browse_dir(self):
        dir_path = filedialog.askdirectory()
        if dir_path:
            self.dir_entry.delete(0, "end")
            self.dir_entry.insert(0, dir_path)

    def browse_file(self, entry):
        file_path = filedialog.askopenfilename()
        if file_path:
            entry.delete(0, "end")
            entry.insert(0, file_path)

    def load_config(self):
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, "r") as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def save_config(self):
        config = {
            "host": self.host_entry.get(),
            "port": int(self.port_entry.get()),
            "dir": self.dir_entry.get(),
            "token": self.token_entry.get(),
            "basic_user": self.basic_user_entry.get(),
            "basic_pass": self.basic_pass_entry.get(),
            "protocol": self.protocol_combo.get(),
            "cert": self.cert_entry.get(),
            "key": self.key_entry.get(),
            "generate_self_signed": self.gen_self_var.get(),
            "ftp_allow_anonymous": self.ftp_anon_var.get(),
            "ftp_permissions": self.ftp_perm_combo.get(),
        }
        try:
            with open(CONFIG_FILE, "w") as f:
                json.dump(config, f, indent=2)
            self.status_label.configure(text="Config saved")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save config: {e}")

    def start_server(self):
        if self.server_process and self.server_process.poll() is None:
            messagebox.showwarning("Warning", "Server is already running")
            return

        args = [sys.executable, "file_server.py",
                "--host", self.host_entry.get(),
                "--port", self.port_entry.get(),
                "--dir", self.dir_entry.get(),
                "--protocol", self.protocol_combo.get()]

        if self.token_entry.get():
            args.extend(["--token", self.token_entry.get()])
        if self.basic_user_entry.get() and self.basic_pass_entry.get():
            args.extend(["--basic-user", self.basic_user_entry.get(), "--basic-pass", self.basic_pass_entry.get()])
        if self.cert_entry.get():
            args.extend(["--cert", self.cert_entry.get()])
        if self.key_entry.get():
            args.extend(["--key", self.key_entry.get()])
        if self.gen_self_var.get():
            args.append("--generate-self-signed")
        if self.ftp_anon_var.get():
            args.append("--ftp-allow-anonymous")
        args.extend(["--ftp-permissions", self.ftp_perm_combo.get()])

        try:
            self.server_process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            self.start_btn.configure(state="disabled")
            self.stop_btn.configure(state="normal")
            self.status_label.configure(text="Server starting...")
            threading.Thread(target=self.monitor_process, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start server: {e}")

    def stop_server(self):
        if self.server_process and self.server_process.poll() is None:
            self.server_process.terminate()
            self.server_process.wait()
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.status_label.configure(text="Server stopped")

    def monitor_process(self):
        while self.server_process and self.server_process.poll() is None:
            output = self.server_process.stdout.readline()
            if output:
                self.log_queue.put(output.strip())
        self.log_queue.put("Server process ended")

    def start_log_thread(self):
        def update_logs():
            try:
                while True:
                    log = self.log_queue.get_nowait()
                    self.log_text.configure(state="normal")
                    self.log_text.insert("end", log + "\n")
                    self.log_text.see("end")
                    self.log_text.configure(state="disabled")
                    
            except queue.Empty:
                pass
            self.root.after(100, update_logs)
        update_logs()

def main():
    root = ctk.CTk()
    app = ServerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    print('https://127.0.0.1:8000/ui/')
    print('http://127.0.0.1:8000/ui/')
    main()
    