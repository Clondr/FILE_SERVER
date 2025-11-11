# How to enable (run and autostart)

Quick, practical instructions for starting and enabling the server and client in common scenarios.

1) Quick HTTP (LAN, no encryption)

```bash
python3 file_server.py --protocol http --host 0.0.0.0 --port 8080
```

2) HTTP + token (recommended for simple LAN protection)

```bash
python3 file_server.py --protocol http --host 0.0.0.0 --port 8080 --token mysecret
```

3) HTTP + Basic auth (alternative to token)

```bash
python3 file_server.py --protocol http --host 0.0.0.0 --port 8080 --basic-user alice --basic-pass s3cr3t
```

4) HTTPS (self-signed, quick test)

```bash
python3 file_server.py --protocol https --generate-self-signed --host 0.0.0.0 --port 8443 --token mysecret
```

5) HTTPS (LAN, no browser warnings) with mkcert (recommended for dev in LAN)

Generate certs and run:

```bash
mkcert -install
mkdir -p certs
mkcert -cert-file certs/server.crt -key-file certs/server.key "file-server.local" "192.168.1.42"

python3 file_server.py --protocol https --cert ./certs/server.crt --key ./certs/server.key --host 0.0.0.0 --port 443 --token mysecret
```

6) HTTPS (public) — Let's Encrypt

Obtain cert (see `obtain_cert_lets_encrypt.sh`) and run:

```bash
python3 file_server.py --protocol https --cert ./certs/your.domain/fullchain.pem --key ./certs/your.domain/privkey.pem --host 0.0.0.0 --port 443 --token mysecret
```

7) Systemd unit (example)

Create `/etc/systemd/system/file-server.service` with:

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

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now file-server.service
sudo systemctl status file-server.service
```

8) GUI client (Tkinter)

Run GUI:

```bash
python3 client.py gui
```

Install tkinter on Linux:

Debian/Ubuntu:

```bash
sudo apt install python3-tk
```

Fedora:

```bash
sudo dnf install python3-tkinter
```

On Windows/macOS tkinter is usually bundled with Python from python.org.

9) Server GUI (CustomTkinter)

Run GUI for server management:

```bash
python3 server_gui.py
```

Install dependencies:

```bash
pip install customtkinter
```

On Linux also tkinter:

Debian/Ubuntu:

```bash
sudo apt install python3-tk
```

Fedora:

```bash
sudo dnf install python3-tkinter
```

The GUI allows configuring the server (host, port, directory, protocol, authentication, TLS, FTP) and launching it with real-time logs. Configuration is saved in `server_gui_config.json`.

---