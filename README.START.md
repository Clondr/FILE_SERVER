# Как включать (запуск и автозапуск)

Этот файл содержит краткие, практичные инструкции "как включать" (запускать и автозапускать) сервер и клиент в самых типичных сценариях.

1) Быстрый запуск по HTTP (локальная сеть, без шифрования)

```bash
python3 file_server.py --protocol http --host 0.0.0.0 --port 8080
```

2) HTTP + токен (рекомендуется для базовой защиты в LAN)

```bash
python3 file_server.py --protocol http --host 0.0.0.0 --port 8080 --token mysecret
```

3) HTTP + Basic auth (альтернатива токену)

```bash
python3 file_server.py --protocol http --host 0.0.0.0 --port 8080 --basic-user alice --basic-pass s3cr3t
```

4) HTTPS (самоподписанный, быстрый тест)

```bash
python3 file_server.py --protocol https --generate-self-signed --host 0.0.0.0 --port 8443 --token mysecret
```

5) HTTPS (LAN, без предупреждений) с mkcert (рекомендуется для разработки в LAN)

Генерация и запуск:

```bash
mkcert -install
mkdir -p certs
mkcert -cert-file certs/server.crt -key-file certs/server.key "file-server.local" "192.168.1.42"

python3 file_server.py --protocol https --cert ./certs/server.crt --key ./certs/server.key --host 0.0.0.0 --port 443 --token mysecret
```

6) HTTPS (публичный домен) — Let's Encrypt

Получить сертификат (см. `obtain_cert_lets_encrypt.sh`) и запустить сервер:

```bash
python3 file_server.py --protocol https --cert ./certs/your.domain/fullchain.pem --key ./certs/your.domain/privkey.pem --host 0.0.0.0 --port 443 --token mysecret
```

7) Systemd unit (пример) — автозапуск

Пример файла `/etc/systemd/system/file-server.service`:

```ini
[Unit]
Description=Local File Server
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/home/kirill/Dropbox/Spravka/Project/python/FILE_SERVER
ExecStart=/usr/bin/env python3 /home/kirill/Dropbox/Spravka/Project/python/FILE_SERVER/file_server.py --protocol https --cert ./certs/server.crt --key ./certs/server.key --host 0.0.0.0 --port 443 --token mysecret
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Включение и запуск:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now file-server.service
sudo systemctl status file-server.service
```

8) GUI клиент (Tkinter)

Запуск GUI-клиента:

```bash
python3 client.py gui
```

Установка tkinter (Linux):

Debian/Ubuntu:

```bash
sudo apt install python3-tk
```

Fedora:

```bash
sudo dnf install python3-tkinter
```

На Windows/macOS tkinter обычно включается вместе с официальным Python.

9) GUI для сервера (CustomTkinter)

Запуск GUI для управления сервером:

```bash
python3 server_gui.py
```

Установка зависимостей:

```bash
pip install customtkinter
```

На Linux также tkinter:

Debian/Ubuntu:

```bash
sudo apt install python3-tk
```

Fedora:

```bash
sudo dnf install python3-tkinter
```

GUI позволяет конфигурировать сервер (хост, порт, директория, протокол, аутентификация, TLS, FTP) и запускать его с логами в реальном времени. Конфигурация сохраняется в `server_gui_config.json`.

---

