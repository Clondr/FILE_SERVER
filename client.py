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
except Exception:
    tk = None  # GUI not available


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
        if tk is None:
            print('Tkinter not available on this system')
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

    # Создание главного окна
    root = tk.Tk()
    root.title('File Server Client')
    root.geometry('1000x600')  # Установка начального размера
    root.resizable(True, True)  # Сделать окно изменяемым по размеру

    # Панель меню
    menubar = tk.Menu(root)
    root.config(menu=menubar)

    help_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Help", menu=help_menu)
    help_menu.add_command(label="About", command=lambda: messagebox.showinfo("About", "File Server Client GUI\nVersion 1.0\nSupports upload/download with auth."))

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
    server_frame = ttk.LabelFrame(left, text="Server & Authentication", padding=(10, 5))
    server_frame.pack(fill=tk.X, pady=(0, 10))

    # Поля для сервера и аутентификации
    ttk.Label(server_frame, text='Server (http(s)://host:port)').grid(row=0, column=0, sticky='w')
    server_e = ttk.Entry(server_frame, width=50)
    server_e.grid(row=0, column=1, columnspan=3, sticky='we', padx=(5,0))
    Tooltip(server_e, "Enter the server URL, e.g., http://localhost:8080")
    _cfg = load_config()
    server_e.insert(0, _cfg.get('server', 'http://localhost:8080'))

    ttk.Label(server_frame, text='Token').grid(row=1, column=0, sticky='w')
    token_e = ttk.Entry(server_frame, width=30)
    token_e.grid(row=1, column=1, sticky='w', padx=(5,0))
    Tooltip(token_e, "Optional auth token for server access")
    token_e.insert(0, _cfg.get('token', ''))

    ttk.Label(server_frame, text='Basic user').grid(row=1, column=2, sticky='w')
    user_e = ttk.Entry(server_frame, width=15)
    user_e.grid(row=1, column=3, sticky='w', padx=(5,0))
    Tooltip(user_e, "Username for basic authentication")
    user_e.insert(0, _cfg.get('basic_user', ''))

    ttk.Label(server_frame, text='Basic pass').grid(row=2, column=2, sticky='w')
    pass_e = ttk.Entry(server_frame, width=15, show='*')
    pass_e.grid(row=2, column=3, sticky='w', padx=(5,0))
    Tooltip(pass_e, "Password for basic authentication")
    pass_e.insert(0, _cfg.get('basic_pass', ''))

    ttk.Label(server_frame, text='CA cert (optional)').grid(row=2, column=0, sticky='w')
    ca_e = ttk.Entry(server_frame, width=40)
    ca_e.grid(row=2, column=1, sticky='we', padx=(5,0))
    Tooltip(ca_e, "Path to CA certificate bundle for TLS verification")
    ca_e.insert(0, _cfg.get('ca_cert', ''))

    def browse_ca():  # Функция для выбора файла CA сертификата
        p = filedialog.askopenfilename(title='Select CA bundle or rootCA.pem')
        if p:
            ca_e.delete(0, tk.END)
            ca_e.insert(0, p)

    ttk.Button(server_frame, text='Browse CA', command=browse_ca).grid(row=2, column=4, sticky='w', padx=(5,0))
    insecure_var = tk.BooleanVar(value=bool(_cfg.get('insecure', False)))
    insecure_cb = ttk.Checkbutton(server_frame, text='Insecure (disable TLS verify)', variable=insecure_var)
    insecure_cb.grid(row=3, column=1, sticky='w', pady=(5,0))
    Tooltip(insecure_cb, "Disable TLS certificate verification (not recommended)")

    # Раздел для загрузки файлов
    upload_frame = ttk.LabelFrame(left, text="Upload", padding=(10, 5))
    upload_frame.pack(fill=tk.X, pady=(0, 10))

    ttk.Label(upload_frame, text='Remote path (optional)').grid(row=0, column=0, sticky='w')
    remote_e = ttk.Entry(upload_frame, width=40)
    remote_e.grid(row=0, column=1, sticky='we', padx=(5,0))
    Tooltip(remote_e, "Optional remote path relative to server data dir (e.g., subdir/file.txt)")

    def on_upload():  # Функция обработки загрузки файла
        # Открываем диалог выбора файла
        fp = filedialog.askopenfilename()
        if not fp:
            return  # Пользователь отменил выбор
        srv = server_e.get().strip(); rem = remote_e.get().strip() or None
        tok = token_e.get().strip() or None; u = user_e.get().strip() or None; p = pass_e.get() or None
        # Если указан удаленный путь, проверяем его безопасность
        if rem and not is_safe_remote_path(rem):
            messagebox.showerror('Error', 'Remote path is invalid or unsafe')
            return
        ca = ca_e.get().strip()
        insecure = insecure_var.get()
        verify_param = False if insecure else (ca if ca else True)
        threading.Thread(target=worker_upload, args=(srv, fp, rem, tok, u, p, verify_param), daemon=True).start()

    upload_btn = ttk.Button(upload_frame, text='Select & Upload File', command=on_upload)
    upload_btn.grid(row=0, column=2, sticky='w', padx=(5,0))
    Tooltip(upload_btn, "Select a local file and upload it to the server")

    # Кнопки для сохранения настроек и обновления
    buttons_frame = ttk.Frame(left)
    buttons_frame.pack(fill=tk.X, pady=(0, 10))

    def on_save_settings():  # Функция сохранения настроек
        data = {
            'server': server_e.get().strip(),
            'token': token_e.get().strip(),
            'basic_user': user_e.get().strip(),
            'basic_pass': pass_e.get(),
            'ca_cert': ca_e.get().strip(),
            'insecure': bool(insecure_var.get()),
        }
        threading.Thread(target=save_config, args=(data,), daemon=True).start()

    save_btn = ttk.Button(buttons_frame, text='Save settings', command=on_save_settings)
    save_btn.grid(row=0, column=0, sticky='w', padx=(0,5))
    Tooltip(save_btn, "Save current settings to config file")

    def on_refresh():  # Функция обновления списка файлов и проверки аутентификации
        """Trigger a refresh/list-files to check authentication and populate file list."""
        srv = server_e.get().strip()
        tok = token_e.get().strip() or None
        u = user_e.get().strip() or None
        p = pass_e.get() or None
        ca = ca_e.get().strip()
        insecure = insecure_var.get()
        verify_param = False if insecure else (ca if ca else True)
        threading.Thread(target=worker_list_files, args=(srv, tok, u, p, verify_param), daemon=True).start()

    refresh_btn = ttk.Button(buttons_frame, text='Refresh / Check auth', command=on_refresh)
    refresh_btn.grid(row=0, column=1, sticky='w')
    Tooltip(refresh_btn, "Refresh the file list and check authentication")

    # Раздел для скачивания файлов
    download_frame = ttk.LabelFrame(left, text="Download", padding=(10, 5))
    download_frame.pack(fill=tk.X, pady=(0, 10))

    ttk.Label(download_frame, text='Download remote path').grid(row=0, column=0, sticky='w')
    dremote_e = ttk.Entry(download_frame, width=40)
    dremote_e.grid(row=0, column=1, sticky='we', padx=(5,0))
    Tooltip(dremote_e, "Remote path to download, e.g., file.txt or subdir/file.txt")

    ttk.Label(download_frame, text='Save as (local)').grid(row=1, column=0, sticky='w')
    out_e = ttk.Entry(download_frame, width=40)
    out_e.grid(row=1, column=1, sticky='we', padx=(5,0))
    Tooltip(out_e, "Local path to save the downloaded file")

    def browse_out():  # Функция для выбора места сохранения файла
        p = filedialog.asksaveasfilename()
        if p:
            out_e.delete(0, tk.END); out_e.insert(0, p)

    ttk.Button(download_frame, text='Browse', command=browse_out).grid(row=1, column=2, sticky='w', padx=(5,0))

    def on_download():  # Функция обработки скачивания файла
        srv = server_e.get().strip(); rem = dremote_e.get().strip(); outp = out_e.get().strip()
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
        threading.Thread(target=worker_download, args=(srv, rem, outp, tok, u, p, verify_param), daemon=True).start()

    download_btn = ttk.Button(download_frame, text='Download', command=on_download)
    download_btn.grid(row=0, column=3, sticky='w', padx=(5,0))
    Tooltip(download_btn, "Download the specified remote file to local path")

    # Правая панель: список удаленных файлов
    ttk.Label(right, text='Remote files (data/) - double-click to download').pack(anchor='w')
    listbox_frame = ttk.Frame(right)
    listbox_frame.pack(fill=tk.BOTH, expand=True)
    listbox = tk.Listbox(listbox_frame, width=60, height=20)
    listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar = ttk.Scrollbar(listbox_frame, orient=tk.VERTICAL, command=listbox.yview)
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
        srv = server_e.get().strip(); tok = token_e.get().strip() or None; u = user_e.get().strip() or None; p = pass_e.get() or None
        ca = ca_e.get().strip()
        insecure = insecure_var.get()
        verify_param = False if insecure else (ca if ca else True)
        threading.Thread(target=worker_download, args=(srv, val, save_path, tok, u, p, verify_param), daemon=True).start()

    listbox.bind('<Double-1>', on_list_double_click)

    # Кнопки для управления списком файлов
    buttons_right = ttk.Frame(right)
    buttons_right.pack(fill=tk.X, pady=(6,0))
    ttk.Button(buttons_right, text='Refresh List', command=on_refresh).pack(side=tk.LEFT, padx=(0,5))
    ttk.Button(buttons_right, text='Clear list', command=lambda: listbox.delete(0, tk.END)).pack(side=tk.LEFT)

    # Нижняя панель: статус и прогресс-бар
    status_frame = ttk.Frame(root)
    status_frame.pack(fill=tk.BOTH, padx=10, pady=(0,10))

    ttk.Label(status_frame, text='Status:').pack(anchor='w')
    status = tk.Text(status_frame, height=4)
    status.pack(fill=tk.BOTH, expand=True)

    progress = ttk.Progressbar(status_frame, orient='horizontal', mode='indeterminate')
    progress.pack(fill=tk.X, pady=(5,0))

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
                        status.insert(tk.END, str(msg) + '\n', 'error')
                    elif 'success' in str(msg).lower():
                        status.insert(tk.END, str(msg) + '\n', 'success')
                    else:
                        status.insert(tk.END, str(msg) + '\n')
                    status.see(tk.END)
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
