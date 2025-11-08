#!/usr/bin/env python3
"""Client with CLI and simple Tkinter GUI for interacting with file_server.py.

Supports upload and download, token auth and HTTP Basic auth (username/password).
"""
from __future__ import annotations

import argparse
import base64
import os
import queue
import sys
import threading
from pathlib import Path
from typing import Optional
import json
import requests

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox
except Exception:
    tk = None  # GUI not available


def is_safe_remote_path(p: str) -> bool:
    if not p:
        return False
    if p.startswith('/') or p.startswith('\\'):
        return False
    if '\\' in p:
        return False
    parts = [part for part in p.split('/') if part != '']
    if any(part == '..' for part in parts):
        return False
    return True


def _build_headers(token: Optional[str], basic_user: Optional[str], basic_pass: Optional[str]) -> dict:
    headers = {}
    if token:
        headers['X-Auth-Token'] = token
    if basic_user and basic_pass:
        cred = f"{basic_user}:{basic_pass}".encode('utf-8')
        headers['Authorization'] = 'Basic ' + base64.b64encode(cred).decode('ascii')
    return headers


def upload(server: str, filepath: Path, token: Optional[str], remote: Optional[str] = None,
           basic_user: Optional[str] = None, basic_pass: Optional[str] = None,
           verify=True):
    url = f"{server.rstrip('/')}/upload"
    dest_name = remote or filepath.name
    if not is_safe_remote_path(dest_name):
        raise ValueError(f"Invalid remote path: {dest_name}")
    headers = _build_headers(token, basic_user, basic_pass)
    with open(filepath, 'rb') as f:
        files = {'file': (dest_name, f)}
    r = requests.post(url, files=files, headers=headers, verify=verify)
    r.raise_for_status()
    return r.json()


def download(server: str, remote_path: str, out: Path, token: Optional[str],
             basic_user: Optional[str] = None, basic_pass: Optional[str] = None,
             verify=True):
    if not is_safe_remote_path(remote_path):
        raise ValueError(f"Invalid remote path: {remote_path}")
    from urllib.parse import quote

    safe_remote = quote(remote_path, safe="/")
    url = f"{server.rstrip('/')}/download/{safe_remote}"
    headers = _build_headers(token, basic_user, basic_pass)
    with requests.get(url, headers=headers, stream=True, verify=verify) as r:
        r.raise_for_status()
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
    return str(out)


def run_cli():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='cmd')

    up = sub.add_parser('upload')
    up.add_argument('server')
    up.add_argument('file', type=Path)
    up.add_argument('--token')
    up.add_argument('--remote', help='remote path relative to server data dir (no leading /, no ..)')
    up.add_argument('--ca', help='CA bundle path to verify server cert')
    up.add_argument('--insecure', action='store_true', help='Disable TLS certificate verification')
    up.add_argument('--user', help='basic auth user')
    up.add_argument('--pass', dest='passwd', help='basic auth password')

    down = sub.add_parser('download')
    down.add_argument('server')
    down.add_argument('remote_path')
    down.add_argument('out', type=Path)
    down.add_argument('--token')
    down.add_argument('--ca', help='CA bundle path to verify server cert')
    down.add_argument('--insecure', action='store_true', help='Disable TLS certificate verification')
    down.add_argument('--user', help='basic auth user')
    down.add_argument('--pass', dest='passwd', help='basic auth password')

    gui = sub.add_parser('gui')

    args = parser.parse_args()
    if args.cmd == 'upload':
        ca = getattr(args, 'ca', None)
        insecure = getattr(args, 'insecure', False)
        verify_param = False if insecure else (ca if ca else True)
        res = upload(args.server, args.file, getattr(args, 'token', None), getattr(args, 'remote', None), getattr(args, 'user', None), getattr(args, 'passwd', None), verify=verify_param)
        print(res)
    elif args.cmd == 'download':
        ca = getattr(args, 'ca', None)
        insecure = getattr(args, 'insecure', False)
        verify_param = False if insecure else (ca if ca else True)
        out = download(args.server, args.remote_path, args.out, getattr(args, 'token', None), getattr(args, 'user', None), getattr(args, 'passwd', None), verify=verify_param)
        print(f"Saved to {out}")
    elif args.cmd == 'gui':
        if tk is None:
            print('Tkinter not available on this system')
            raise SystemExit(1)
        gui_main()
    else:
        parser.print_help()


def gui_main():
    # queue carries either strings (status messages) or dicts {'type':'files','files':[...]}
    q: 'queue.Queue[object]' = queue.Queue()

    # config file in project root
    CONFIG_PATH = Path.cwd() / 'file_server_client.json'

    def load_config() -> dict:
        if not CONFIG_PATH.exists():
            return {}
        try:
            with open(CONFIG_PATH, 'r', encoding='utf-8') as fh:
                return json.load(fh)
        except Exception:
            return {}

    def save_config(data: dict) -> None:
        try:
            with open(CONFIG_PATH, 'w', encoding='utf-8') as fh:
                json.dump(data, fh, indent=2, ensure_ascii=False)
            q.put('Settings saved to ' + str(CONFIG_PATH))
        except Exception as e:
            q.put('Failed to save settings: ' + str(e))

    def worker_upload(server, filepath, remote, token, user, passwd):
        try:
            res = upload(server, Path(filepath), token, remote, user, passwd)
            q.put(f"Upload success: {res}")
        except Exception as e:
            q.put(f"Upload error: {e}")

    def worker_download(server, remote_path, outpath, token, user, passwd):
        try:
            saved = download(server, remote_path, Path(outpath), token, user, passwd)
            q.put(f"Downloaded to: {saved}")
        except Exception as e:
            q.put(f"Download error: {e}")

    def worker_list_files(server, token, user, passwd, verify=True):
        try:
            url = f"{server.rstrip('/')}/files"
            headers = _build_headers(token, user, passwd)
            r = requests.get(url, headers=headers, timeout=10, verify=verify)
            r.raise_for_status()
            data = r.json()
            # Server may return either a list or a dict {"files": [...]}.
            if isinstance(data, dict):
                files = data.get('files') or data.get('items') or []
            else:
                files = data
            # Expecting a list of file dicts or strings (paths)
            q.put({'type': 'files', 'files': files})
            q.put('Authenticated: file list received')
        except Exception as e:
            q.put(f"List files error: {e}")

    root = tk.Tk()
    root.title('File Server Client')

    # container frames to avoid overlap: left for controls, right for file list
    container = tk.Frame(root)
    container.pack(fill=tk.BOTH, expand=True)

    left = tk.Frame(container, padx=10, pady=10)
    left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    right = tk.Frame(container, padx=10, pady=10)
    right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

    # Left column: server/auth/upload/download
    tk.Label(left, text='Server (http(s)://host:port)').grid(row=0, column=0, sticky='w')
    server_e = tk.Entry(left, width=50)
    server_e.grid(row=0, column=1, columnspan=3, sticky='we')
    _cfg = load_config()
    server_e.insert(0, _cfg.get('server', 'http://localhost:8080'))

    tk.Label(left, text='Token').grid(row=1, column=0, sticky='w')
    token_e = tk.Entry(left, width=30)
    token_e.grid(row=1, column=1, sticky='w')
    token_e.insert(0, _cfg.get('token', ''))

    tk.Label(left, text='Basic user').grid(row=1, column=2, sticky='w')
    user_e = tk.Entry(left, width=15)
    user_e.grid(row=1, column=3, sticky='w')
    user_e.insert(0, _cfg.get('basic_user', ''))

    tk.Label(left, text='Basic pass').grid(row=2, column=2, sticky='w')
    pass_e = tk.Entry(left, width=15, show='*')
    pass_e.grid(row=2, column=3, sticky='w')
    pass_e.insert(0, _cfg.get('basic_pass', ''))

    tk.Label(left, text='CA cert (optional)').grid(row=2, column=0, sticky='w')
    ca_e = tk.Entry(left, width=40)
    ca_e.grid(row=2, column=1, sticky='we')
    ca_e.insert(0, _cfg.get('ca_cert', ''))

    def browse_ca(): # Browse for CA cert file
        p = filedialog.askopenfilename(title='Select CA bundle or rootCA.pem')
        if p:
            ca_e.delete(0, tk.END)
            ca_e.insert(0, p)

    tk.Button(left, text='Browse CA', command=browse_ca).grid(row=2, column=4, sticky='w')
    insecure_var = tk.BooleanVar(value=bool(_cfg.get('insecure', False)))
    tk.Checkbutton(left, text='Insecure (disable TLS verify)', variable=insecure_var).grid(row=3, column=1, sticky='w')

    # Upload
    tk.Label(left, text='Upload file').grid(row=4, column=0, sticky='w')
    file_e = tk.Entry(left, width=40)
    file_e.grid(row=4, column=1, sticky='we')

    def browse_file():
        p = filedialog.askopenfilename()
        if p:
            file_e.delete(0, tk.END)
            file_e.insert(0, p)

    tk.Button(left, text='Browse', command=browse_file).grid(row=4, column=2, sticky='w')
    tk.Label(left, text='Remote path (optional)').grid(row=5, column=0, sticky='w')
    remote_e = tk.Entry(left, width=40)
    remote_e.grid(row=5, column=1, sticky='we')

    def on_upload():
        srv = server_e.get().strip(); fp = file_e.get().strip(); rem = remote_e.get().strip() or None
        tok = token_e.get().strip() or None; u = user_e.get().strip() or None; p = pass_e.get() or None
        if not fp:
            messagebox.showerror('Error', 'Choose a file to upload')
            return
        # If user provided a remote path, ensure it's safe (relative inside data)
        if rem and not is_safe_remote_path(rem):
            messagebox.showerror('Error', 'Remote path is invalid or unsafe')
            return
        ca = ca_e.get().strip()
        insecure = insecure_var.get()
        verify_param = False if insecure else (ca if ca else True)
        threading.Thread(target=worker_upload, args=(srv, fp, rem, tok, u, p, verify_param), daemon=True).start()

    tk.Button(left, text='Upload', command=on_upload).grid(row=4, column=3, sticky='w')

    # Save settings & Refresh
    def on_save_settings():
        data = {
            'server': server_e.get().strip(),
            'token': token_e.get().strip(),
            'basic_user': user_e.get().strip(),
            'basic_pass': pass_e.get(),
            'ca_cert': ca_e.get().strip(),
            'insecure': bool(insecure_var.get()),
        }
        threading.Thread(target=save_config, args=(data,), daemon=True).start()

    tk.Button(left, text='Save settings', command=on_save_settings).grid(row=6, column=1, sticky='w', pady=(8,0))

    def on_refresh():
        """Trigger a refresh/list-files to check authentication and populate file list."""
        srv = server_e.get().strip()
        tok = token_e.get().strip() or None
        u = user_e.get().strip() or None
        p = pass_e.get() or None
        ca = ca_e.get().strip()
        insecure = insecure_var.get()
        verify_param = False if insecure else (ca if ca else True)
        threading.Thread(target=worker_list_files, args=(srv, tok, u, p, verify_param), daemon=True).start()

    tk.Button(left, text='Refresh / Check auth', command=on_refresh).grid(row=6, column=2, sticky='w', pady=(8,0)) # Refresh button

    # Download inputs
    tk.Label(left, text='Download remote path').grid(row=7, column=0, sticky='w')
    dremote_e = tk.Entry(left, width=40)
    dremote_e.grid(row=7, column=1, sticky='we')
    tk.Label(left, text='Save as (local)').grid(row=8, column=0, sticky='w')
    out_e = tk.Entry(left, width=40)
    out_e.grid(row=8, column=1, sticky='we')

    def browse_out():
        p = filedialog.asksaveasfilename()
        if p:
            out_e.delete(0, tk.END); out_e.insert(0, p)

    tk.Button(left, text='Browse', command=browse_out).grid(row=8, column=2, sticky='w')

    def on_download():
        srv = server_e.get().strip(); rem = dremote_e.get().strip(); outp = out_e.get().strip()
        tok = token_e.get().strip() or None; u = user_e.get().strip() or None; p = pass_e.get() or None
        if not rem or not outp:
            messagebox.showerror('Error', 'Specify remote path and local output file')
            return
        # Validate remote path safety (must be relative inside data)
        if not is_safe_remote_path(rem):
            messagebox.showerror('Error', 'Remote path is invalid or unsafe')
            return
        ca = ca_e.get().strip()
        insecure = insecure_var.get()
        verify_param = False if insecure else (ca if ca else True)
        threading.Thread(target=worker_download, args=(srv, rem, outp, tok, u, p, verify_param), daemon=True).start()

    tk.Button(left, text='Download', command=on_download).grid(row=8, column=3, sticky='w')

    # Right column: file list
    tk.Label(right, text='Remote files (data/)').pack(anchor='w') # double-click to download
    listbox = tk.Listbox(right, width=60, height=20)
    listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar = tk.Scrollbar(right, orient=tk.VERTICAL, command=listbox.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    listbox.config(yscrollcommand=scrollbar.set)

    def on_list_double_click(event):
        sel = listbox.curselection()
        if not sel:
            return
        val = listbox.get(sel[0])
        # Ensure selected remote path is safe (relative inside data)
        if not is_safe_remote_path(val):
            messagebox.showerror('Error', 'Selected remote path is invalid or unsafe')
            return
        # Suggest local filename
        default = os.path.basename(val)
        save_path = filedialog.asksaveasfilename(initialfile=default)
        if not save_path:
            return
        srv = server_e.get().strip(); tok = token_e.get().strip() or None; u = user_e.get().strip() or None; p = pass_e.get() or None
        ca = ca_e.get().strip()
        insecure = insecure_var.get()
        verify_param = False if insecure else (ca if ca else True)
        threading.Thread(target=worker_download, args=(srv, val, save_path, tok, u, p, verify_param), daemon=True).start()

    listbox.bind('<Double-1>', on_list_double_click)

    tk.Button(right, text='Clear list', command=lambda: listbox.delete(0, tk.END)).pack(anchor='w', pady=(6,0))

    # Status box
    status = tk.Text(root, height=6)
    status.pack(fill=tk.BOTH, padx=10, pady=(0,10))

    def poll_queue():
        try:
            while True:
                msg = q.get_nowait()
                if isinstance(msg, dict) and msg.get('type') == 'files':
                    files = msg.get('files') or []
                    listbox.delete(0, tk.END)
                    # If server returns objects, try to extract path strings
                    for item in files:
                        if isinstance(item, dict):
                            val = item.get('path') or item.get('name') or str(item)
                        else:
                            val = str(item)
                        # Only show safe remote paths (no leading slash, no ..)
                        if is_safe_remote_path(val):
                            listbox.insert(tk.END, val)
                else:
                    status.insert(tk.END, str(msg) + '\n')
                    status.see(tk.END)
        except queue.Empty:
            pass
        root.after(200, poll_queue)

    poll_queue()
    root.mainloop()


if __name__ == '__main__':
    run_cli()
