#!/usr/bin/env python3
"""

Client with CLI and simple Tkinter GUI for interacting with file_server.py.

This script provides both command-line interface (CLI) and graphical user interface (GUI)
for uploading and downloading files to/from a remote file server. It supports authentication
via token or HTTP Basic auth, and includes TLS certificate verification options.

Features:
- Upload files to server with optional remote path specification
- Download files from server to local directory
- List remote files in the server's data directory
- GUI with modern ttk widgets, organized sections, tooltips, and progress feedback
- Configurable server settings saved to JSON file

Usage:
    python client.py upload <server> <file> [options]
    python client.py download <server> <remote_path> <local_file> [options]
    python client.py gui
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
    from tkinter import filedialog, messagebox, ttk
    import customtkinter as ctk
except Exception:
    tk = None  # GUI not available
    ctk = None


def is_safe_remote_path(p: str) -> bool:
    """
    Проверяет, является ли путь безопасным для удаленного доступа.
    Запрещает абсолютные пути, пути с обратными слешами и пути с '..'
    для предотвращения выхода за пределы директории data на сервере.
    """
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
    """
    Строит заголовки HTTP для аутентификации.
    Поддерживает токен аутентификации и базовую HTTP аутентификацию.
    """
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
    """
    Загружает файл на сервер.
    Проверяет безопасность пути, строит заголовки аутентификации,
    отправляет файл через POST запрос и возвращает ответ сервера.
    """
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
    """
    Скачивает файл с сервера.
    Проверяет безопасность пути, кодирует URL, отправляет GET запрос
    и сохраняет файл локально, возвращая путь к сохраненному файлу.
    """
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
    """
    Обрабатывает аргументы командной строки и выполняет соответствующие действия.
    Поддерживает команды upload, download и gui.
    """
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
        if tk is None or ctk is None:
            print('Tkinter or CustomTkinter not available on this system')
            raise SystemExit(1)
        gui_main()
    else:
        parser.print_help()


class Tooltip:
    """
    Класс для создания всплывающих подсказок (tooltips) для виджетов Tkinter.
    Показывает текст при наведении курсора и скрывает при уходе.
    """
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip = None
        widget.bind("<Enter>", self.show_tooltip)
        widget.bind("<Leave>", self.hide_tooltip)

    def show_tooltip(self, event=None):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        self.tooltip = tk.Toplevel(self.widget)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{x}+{y}")
        label = tk.Label(self.tooltip, text=self.text, background="yellow", relief="solid", borderwidth=1)
        label.pack()

    def hide_tooltip(self, event=None):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None


def gui_main():
    """
    Основная функция GUI. Создает интерфейс с разделами для сервера/аутентификации,
    загрузки, скачивания и списка файлов. Использует очередь для обновления UI из потоков.
    """
    # Set CustomTkinter appearance
    ctk.set_appearance_mode("System")  # Modes: "System" (standard), "Dark", "Light"
    ctk.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"

    # queue carries either strings (status messages) or dicts {'type':'files','files':[...]}
    q: 'queue.Queue[object]' = queue.Queue()

    # config file in project root
    CONFIG_PATH = Path.cwd() / 'file_server_client.json'

    def load_config() -> dict:
        """
        Загружает настройки из JSON файла.
        Возвращает пустой словарь, если файл не существует или поврежден.
        """
        if not CONFIG_PATH.exists():
            return {}
        try:
            with open(CONFIG_PATH, 'r', encoding='utf-8') as fh:
                return json.load(fh)
        except Exception:
            return {}

    def save_config(data: dict) -> None:
        """
        Сохраняет настройки в JSON файл.
        Отправляет сообщение в очередь о результате операции.
        """
        try:
            with open(CONFIG_PATH, 'w', encoding='utf-8') as fh:
                json.dump(data, fh, indent=2, ensure_ascii=False)
            q.put('Settings saved to ' + str(CONFIG_PATH))
        except Exception as e:
            q.put('Failed to save settings: ' + str(e))

    def worker_upload(server, filepath, remote, token, user, passwd, verify=True):
        """
        Функция-работник для загрузки файла в отдельном потоке.
        Запускает прогресс-бар, выполняет загрузку и отправляет результат в очередь.
        """
        progress.start()
        try:
            res = upload(server, Path(filepath), token, remote, user, passwd, verify)
            q.put(f"Upload success: {res}")
        except Exception as e:
            q.put(f"Upload error: {e}")

    def worker_download(server, remote_path, outpath, token, user, passwd, verify=True):
        """
        Функция-работник для скачивания файла в отдельном потоке.
        Запускает прогресс-бар, выполняет скачивание и отправляет результат в очередь.
        """
        progress.start()
        try:
            saved = download(server, remote_path, Path(outpath), token, user, passwd, verify)
            q.put(f"Downloaded to: {saved}")
        except Exception as e:
            q.put(f"Download error: {e}")

    def worker_list_files(server, token, user, passwd, verify=True):
        """
        Функция-работник для получения списка файлов в отдельном потоке.
        Запускает прогресс-бар, запрашивает список файлов и отправляет результат в очередь.
        """
        progress.start()
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

    def worker_list_files_ftp(server, user, passwd):
        """
        Функция-работник для получения списка файлов с FTP сервера в отдельном потоке.
        """
        progress.start()
        try:
            from ftplib import FTP
            from urllib.parse import urlparse

            parsed = urlparse(server)
            host = parsed.hostname
            port = parsed.port or 21

            ftp = FTP()
            ftp.connect(host, port)
            ftp.login(user or 'anonymous', passwd or '')
            files = []
            ftp.retrlines('LIST', lambda x: files.append(x.split()[-1]) if x else None)
            ftp.quit()
            q.put({'type': 'files', 'files': files})
            q.put('FTP: file list received')
        except Exception as e:
            q.put(f"FTP list files error: {e}")

    def worker_upload_ftp(server, filepath, remote, user, passwd):
        """
        Функция-работник для загрузки файла на FTP сервер в отдельном потоке.
        """
        progress.start()
        try:
            from ftplib import FTP
            from urllib.parse import urlparse

            parsed = urlparse(server)
            host = parsed.hostname
            port = parsed.port or 21

            ftp = FTP()
            ftp.connect(host, port)
            ftp.login(user or 'anonymous', passwd or '')

            dest_name = remote or os.path.basename(filepath)
            if not is_safe_remote_path(dest_name):
                raise ValueError(f"Invalid remote path: {dest_name}")

            with open(filepath, 'rb') as f:
                ftp.storbinary(f'STOR {dest_name}', f)
            ftp.quit()
            q.put(f"FTP upload success: {dest_name}")
        except Exception as e:
            q.put(f"FTP upload error: {e}")

    def worker_download_ftp(server, remote_path, outpath, user, passwd):
        """
        Функция-работник для скачивания файла с FTP сервера в отдельном потоке.
        """
        progress.start()
        try:
            from ftplib import FTP
            from urllib.parse import urlparse

            if not is_safe_remote_path(remote_path):
                raise ValueError(f"Invalid remote path: {remote_path}")

            parsed = urlparse(server)
            host = parsed.hostname
            port = parsed.port or 21

            ftp = FTP()
            ftp.connect(host, port)
            ftp.login(user or 'anonymous', passwd or '')

            Path(outpath).parent.mkdir(parents=True, exist_ok=True)
            with open(outpath, 'wb') as f:
                ftp.retrbinary(f'RETR {remote_path}', f.write)
            ftp.quit()
            q.put(f"FTP downloaded to: {outpath}")
        except Exception as e:
            q.put(f"FTP download error: {e}")

    # Создание главного окна
    root = ctk.CTk()
    root.title('File Server Client')
    root.geometry('1000x600')  # Установка начального размера
    root.resizable(True, True)  # Сделать окно изменяемым по размеру

    # Панель меню (using standard tk.Menu for compatibility)
    menubar = tk.Menu(root)
    root.config(menu=menubar)

    help_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Help", menu=help_menu)
    help_menu.add_command(label="About", command=lambda: messagebox.showinfo("About", "File Server Client GUI\nVersion 1.0\nSupports upload/download with auth and FTP."))

    # Appearance mode toggle
    def change_appearance_mode_event(new_appearance_mode: str):
        ctk.set_appearance_mode(new_appearance_mode)

    appearance_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Appearance", menu=appearance_menu)
    appearance_menu.add_command(label="Light", command=lambda: change_appearance_mode_event("Light"))
    appearance_menu.add_command(label="Dark", command=lambda: change_appearance_mode_event("Dark"))
    appearance_menu.add_command(label="System", command=lambda: change_appearance_mode_event("System"))

    # Контейнер для разделения на левую и правую панели
    container = tk.Frame(root)
    container.pack(fill=tk.BOTH, expand=True)

    # Левая панель для элементов управления
    left = tk.Frame(container, padx=10, pady=10)
    left.pack(side=tk.LEFT, fill=tk.Y, expand=False)

    # Правая панель для списка файлов
    right = tk.Frame(container, padx=10, pady=10)
    right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

    # Левая панель: разделы для сервера/аутентификации, загрузки и скачивания
    server_frame = ctk.CTkFrame(left)
    server_frame.pack(fill=tk.X, pady=(0, 10))

    ctk.CTkLabel(server_frame, text="Server & Authentication").pack(anchor="w", padx=10, pady=(10,5))

    # Load config first
    _cfg = load_config()

    # Server type selection
    server_type_var = tk.StringVar(value=_cfg.get('server_type', 'HTTP'))
    ctk.CTkLabel(server_frame, text="Server Type:").pack(anchor="w", padx=10)
    server_type_combo = ctk.CTkComboBox(server_frame, values=["HTTP", "FTP"], variable=server_type_var)
    server_type_combo.pack(fill=tk.X, padx=10, pady=(0,10))

    # Поля для сервера и аутентификации
    ctk.CTkLabel(server_frame, text='Server (http(s)://host:port or ftp://host:port)').pack(anchor="w", padx=10)
    server_e = ctk.CTkEntry(server_frame, width=400)
    server_e.pack(fill=tk.X, padx=10, pady=(0,10))
    server_e.insert(0, _cfg.get('server', 'http://localhost:8080'))

    ctk.CTkLabel(server_frame, text='Token (HTTP only)').pack(anchor="w", padx=10)
    token_e = ctk.CTkEntry(server_frame, width=300)
    token_e.pack(fill=tk.X, padx=10, pady=(0,10))
    token_e.insert(0, _cfg.get('token', ''))

    ctk.CTkLabel(server_frame, text='Username').pack(anchor="w", padx=10)
    user_e = ctk.CTkEntry(server_frame, width=300)
    user_e.pack(fill=tk.X, padx=10, pady=(0,10))
    user_e.insert(0, _cfg.get('basic_user', ''))

    ctk.CTkLabel(server_frame, text='Password').pack(anchor="w", padx=10)
    pass_e = ctk.CTkEntry(server_frame, width=300, show='*')
    pass_e.pack(fill=tk.X, padx=10, pady=(0,10))
    pass_e.insert(0, _cfg.get('basic_pass', ''))

    ctk.CTkLabel(server_frame, text='CA cert (HTTP only, optional)').pack(anchor="w", padx=10)
    ca_frame = ctk.CTkFrame(server_frame, fg_color="transparent")
    ca_frame.pack(fill=tk.X, padx=10, pady=(0,10))
    ca_e = ctk.CTkEntry(ca_frame, width=300)
    ca_e.pack(side=tk.LEFT, fill=tk.X, expand=True)
    ca_e.insert(0, _cfg.get('ca_cert', ''))

    def browse_ca():  # Функция для выбора файла CA сертификата
        p = filedialog.askopenfilename(title='Select CA bundle or rootCA.pem')
        if p:
            ca_e.delete(0, tk.END)
            ca_e.insert(0, p)

    ctk.CTkButton(ca_frame, text='Browse', command=browse_ca, width=80).pack(side=tk.RIGHT, padx=(10,0))

    insecure_var = tk.BooleanVar(value=bool(_cfg.get('insecure', False)))
    insecure_cb = ctk.CTkCheckBox(server_frame, text='Insecure (disable TLS verify)', variable=insecure_var)
    insecure_cb.pack(anchor="w", padx=10, pady=(0,10))

    # Раздел для загрузки файлов
    upload_frame = ctk.CTkFrame(left)
    upload_frame.pack(fill=tk.X, pady=(0, 10))

    ctk.CTkLabel(upload_frame, text="Upload").pack(anchor="w", padx=10, pady=(10,5))

    def on_upload():  # Функция обработки загрузки файла
        # Открываем диалог выбора файла
        fp = filedialog.askopenfilename()
        if not fp:
            return  # Пользователь отменил выбор
        srv = server_e.get().strip(); rem = None
        server_type = server_type_var.get()
        tok = token_e.get().strip() or None; u = user_e.get().strip() or None; p = pass_e.get() or None
        ca = ca_e.get().strip()
        insecure = insecure_var.get()
        verify_param = False if insecure else (ca if ca else True)
        if server_type == 'FTP':
            threading.Thread(target=worker_upload_ftp, args=(srv, fp, rem, u, p), daemon=True).start()
        else:
            threading.Thread(target=worker_upload, args=(srv, fp, rem, tok, u, p, verify_param), daemon=True).start()

    upload_btn = ctk.CTkButton(upload_frame, text='Select & Upload File', command=on_upload)
    upload_btn.pack(fill=tk.X, padx=10, pady=(0,10))

    # Кнопки для сохранения настроек и обновления
    buttons_frame = ctk.CTkFrame(left, fg_color="transparent")
    buttons_frame.pack(fill=tk.X, pady=(0, 10))

    def on_save_settings():  # Функция сохранения настроек
        data = {
            'server_type': server_type_var.get(),
            'server': server_e.get().strip(),
            'token': token_e.get().strip(),
            'basic_user': user_e.get().strip(),
            'basic_pass': pass_e.get(),
            'ca_cert': ca_e.get().strip(),
            'insecure': bool(insecure_var.get()),
        }
        threading.Thread(target=save_config, args=(data,), daemon=True).start()

    save_btn = ctk.CTkButton(buttons_frame, text='Save settings', command=on_save_settings)
    save_btn.pack(side=tk.LEFT, padx=(10,5), pady=10)

    def on_refresh():  # Функция обновления списка файлов и проверки аутентификации
        """Trigger a refresh/list-files to check authentication and populate file list."""
        srv = server_e.get().strip()
        server_type = server_type_var.get()
        tok = token_e.get().strip() or None
        u = user_e.get().strip() or None
        p = pass_e.get() or None
        ca = ca_e.get().strip()
        insecure = insecure_var.get()
        verify_param = False if insecure else (ca if ca else True)
        if server_type == 'FTP':
            threading.Thread(target=worker_list_files_ftp, args=(srv, u, p), daemon=True).start()
        else:
            threading.Thread(target=worker_list_files, args=(srv, tok, u, p, verify_param), daemon=True).start()

    refresh_btn = ctk.CTkButton(buttons_frame, text='Refresh / Check auth', command=on_refresh)
    refresh_btn.pack(side=tk.LEFT, padx=(0,10), pady=10)

    # Раздел для скачивания файлов
    download_frame = ctk.CTkFrame(left)
    download_frame.pack(fill=tk.X, pady=(0, 10))

    ctk.CTkLabel(download_frame, text="Download").pack(anchor="w", padx=10, pady=(10,5))

    ctk.CTkLabel(download_frame, text='Download remote path').pack(anchor="w", padx=10)
    dremote_e = ctk.CTkEntry(download_frame, width=400)
    dremote_e.pack(fill=tk.X, padx=10, pady=(0,10))

    ctk.CTkLabel(download_frame, text='Save as (local)').pack(anchor="w", padx=10)
    out_frame = ctk.CTkFrame(download_frame, fg_color="transparent")
    out_frame.pack(fill=tk.X, padx=10, pady=(0,10))
    out_e = ctk.CTkEntry(out_frame, width=300)
    out_e.pack(side=tk.LEFT, fill=tk.X, expand=True)

    def browse_out():  # Функция для выбора места сохранения файла
        p = filedialog.asksaveasfilename()
        if p:
            out_e.delete(0, tk.END); out_e.insert(0, p)

    ctk.CTkButton(out_frame, text='Browse', command=browse_out, width=80).pack(side=tk.RIGHT, padx=(10,0))

    def on_download():  # Функция обработки скачивания файла
        srv = server_e.get().strip(); rem = dremote_e.get().strip(); outp = out_e.get().strip()
        server_type = server_type_var.get()
        tok = token_e.get().strip() or None; u = user_e.get().strip() or None; p = pass_e.get() or None
        if not rem or not outp:
            messagebox.showerror('Error', 'Specify remote path and local output file')
            return
        # Проверяем безопасность удаленного пути
        if not is_safe_remote_path(rem):
            messagebox.showerror('Error', 'Remote path is invalid or unsafe')
            return
        ca = ca_e.get().strip()
        insecure = insecure_var.get()
        verify_param = False if insecure else (ca if ca else True)
        if server_type == 'FTP':
            threading.Thread(target=worker_download_ftp, args=(srv, rem, outp, u, p), daemon=True).start()
        else:
            threading.Thread(target=worker_download, args=(srv, rem, outp, tok, u, p, verify_param), daemon=True).start()

    download_btn = ctk.CTkButton(download_frame, text='Download', command=on_download)
    download_btn.pack(fill=tk.X, padx=10, pady=(0,10))

    # Правая панель: список удаленных файлов
    ctk.CTkLabel(right, text='Remote files - double-click to download', text_color='black').pack(anchor='w', padx=10, pady=(10,5))
    listbox_frame = ctk.CTkFrame(right)
    listbox_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0,10))
    listbox = tk.Listbox(listbox_frame, width=60, height=20, bg=ctk.ThemeManager.theme["CTkFrame"]["fg_color"][1], fg="white", selectbackground=ctk.ThemeManager.theme["CTkButton"]["fg_color"][1])
    listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar = ctk.CTkScrollbar(listbox_frame, orientation="vertical", command=listbox.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    listbox.config(yscrollcommand=scrollbar.set)

    def on_list_double_click(event):  # Функция обработки двойного клика по файлу в списке
        sel = listbox.curselection()
        if not sel:
            return
        val = listbox.get(sel[0])
        # Проверяем безопасность выбранного пути
        if not is_safe_remote_path(val):
            messagebox.showerror('Error', 'Selected remote path is invalid or unsafe')
            return
        # Предлагаем имя файла по умолчанию
        default = os.path.basename(val)
        save_path = filedialog.asksaveasfilename(initialfile=default)
        if not save_path:
            return
        srv = server_e.get().strip(); server_type = server_type_var.get()
        tok = token_e.get().strip() or None; u = user_e.get().strip() or None; p = pass_e.get() or None
        ca = ca_e.get().strip()
        insecure = insecure_var.get()
        verify_param = False if insecure else (ca if ca else True)
        if server_type == 'FTP':
            threading.Thread(target=worker_download_ftp, args=(srv, val, save_path, u, p), daemon=True).start()
        else:
            threading.Thread(target=worker_download, args=(srv, val, save_path, tok, u, p, verify_param), daemon=True).start()

    listbox.bind('<Double-1>', on_list_double_click)

    # Кнопки для управления списком файлов
    buttons_right = ctk.CTkFrame(right, fg_color="transparent")
    buttons_right.pack(fill=tk.X, padx=10, pady=(0,10))
    ctk.CTkButton(buttons_right, text='Refresh List', command=on_refresh).pack(side=tk.LEFT, padx=(0,5))
    ctk.CTkButton(buttons_right, text='Clear list', command=lambda: listbox.delete(0, tk.END)).pack(side=tk.LEFT)

    # Нижняя панель: статус и прогресс-бар
    status_frame = ctk.CTkFrame(root)
    status_frame.pack(fill=tk.BOTH, padx=10, pady=(0,10))

    ctk.CTkLabel(status_frame, text='Status:').pack(anchor='w', padx=10, pady=(10,5))
    status = ctk.CTkTextbox(status_frame, height=80)
    status.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0,10))

    progress = ctk.CTkProgressBar(status_frame, orientation='horizontal', mode='indeterminate')
    progress.pack(fill=tk.X, padx=10, pady=(0,10))

    def poll_queue():  # Функция опроса очереди сообщений из потоков
        try:
            while True:
                msg = q.get_nowait()
                if isinstance(msg, dict) and msg.get('type') == 'files':
                    files = msg.get('files') or []
                    listbox.delete(0, tk.END)
                    # Если сервер возвращает объекты, извлекаем строки путей
                    for item in files:
                        if isinstance(item, dict):
                            val = item.get('path') or item.get('name') or str(item)
                        else:
                            val = str(item)
                        # Показываем только безопасные пути
                        if is_safe_remote_path(val):
                            listbox.insert(tk.END, val)
                    progress.stop()
                else:
                    # Раскрашиваем сообщения по цветам
                    if 'error' in str(msg).lower() or 'failed' in str(msg).lower():
                        status.insert("end", str(msg) + '\n', "error")
                    elif 'success' in str(msg).lower():
                        status.insert("end", str(msg) + '\n', "success")
                    else:
                        status.insert("end", str(msg) + '\n')
                    status.see("end")
                    progress.stop()
        except queue.Empty:
            pass
        root.after(200, poll_queue)

    # Настройка тегов для раскраски статуса
    status.tag_config('error', foreground='red')
    status.tag_config('success', foreground='green')

    # Автосохранение настроек при закрытии окна
    def on_closing():  # Функция обработки закрытия окна
        data = {
            'server_type': server_type_var.get(),
            'server': server_e.get().strip(),
            'token': token_e.get().strip(),
            'basic_user': user_e.get().strip(),
            'basic_pass': pass_e.get(),
            'ca_cert': ca_e.get().strip(),
            'insecure': bool(insecure_var.get()),
        }
        save_config(data)
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_closing)

    poll_queue()
    root.mainloop()


if __name__ == '__main__':
    run_cli()
