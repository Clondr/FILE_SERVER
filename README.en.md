# File server (local network)

A small HTTP/HTTPS/FTP file server for local networks with a simple client, optional web UI, and GUI for management.

Features
- Listing, upload (multipart/form-data), download (Range support), delete files
- Simple token authentication (X-Auth-Token or ?token=)
- Restricts access to a `data` folder next to the script
- HTTPS support (local certificates or real CA)
- FTP protocol support for compatibility with FTP clients
- GUI for easy server configuration and launch with real-time logs

Requirements
- Python 3.8+

Install dependencies:

```bash
pip install -r requirements.txt
```

Default behavior
- The server serves the `data` directory located next to `file_server.py`. The directory will be created automatically if missing.
- Access is restricted to this folder — attempts to use `--dir` outside `./data` will be ignored and the server will use `./data` instead.

Run the server

```bash
python3 file_server.py --host 0.0.0.0 --port 8080 --token mysecret
```

Important CLI options
- --host — bind address (default: 0.0.0.0)
- --port — port (default: 8080)
- --dir — directory to serve (default: `data` next to the script). Relative paths are resolved relative to the script directory.
- --token — simple authentication token (optional)
- --tls — (legacy) enable HTTPS (kept for compatibility)
- --protocol — new argument: `http`, `https` or `ftp`. If provided, it overrides `--tls`.
- --cert/--key — paths to TLS certificate and private key (PEM)
- --generate-self-signed — generate a temporary self-signed certificate (requires openssl)

API
- GET /files — returns JSON list of files
- GET /download/{path} — download file
- POST /upload — multipart/form-data (field `file`)
- DELETE /delete/{path} — delete file

Client examples

Upload a file:

```bash
python3 client.py upload http://localhost:8080 ./myfile.txt --token mysecret
```

Download a file:

```bash
python3 client.py download http://localhost:8080 some/path.txt ./out.txt --token mysecret
```

HTTPS (short)

You can run the server over HTTPS. TLS decision priority:
1. If `--protocol https` is provided — server will run over HTTPS.
2. If `--protocol` is not provided but `--tls` is set — HTTPS is enabled (legacy behavior).

Examples:

```bash
# Use existing cert/key
python3 file_server.py --protocol https --cert ./certs/server.crt --key ./certs/server.key --host 0.0.0.0 --port 8443 --token mysecret

# Generate a temporary self-signed cert
python3 file_server.py --protocol https --generate-self-signed --host 0.0.0.0 --port 8443 --token mysecret

# Legacy style (if --protocol not provided)
python3 file_server.py --tls --cert ./certs/server.crt --key ./certs/server.key
```

Avoiding browser warnings (trusted certificates)

1) Let's Encrypt (public domain)
   - Requirements: a public domain pointing to your server and port 80 reachable (or DNS-01 challenge).
   - Use the provided `obtain_cert_lets_encrypt.sh` helper to obtain certbot certificates and copy them to `./certs/<domain>/`.

2) mkcert (best for LAN / development)
   - Install `mkcert`: https://github.com/FiloSottile/mkcert
   - Run `mkcert -install` to create and install the local CA in the system trust store.
   - Generate a certificate for your hostnames/IPs:

```bash
mkdir -p certs
mkcert -cert-file certs/server.crt -key-file certs/server.key "file-server.local" "192.168.1.42"
```

   - Either run `mkcert -install` on each client machine or copy/import the `rootCA.pem` to the client trust store.

3) Self-managed local CA (openssl)
   - Create your own root CA and sign server CSR manually. You must install the root CA on each client.

Testing and verification
- Open https://<host>:<port>/ui/ in the browser. If the certificate is trusted, there will be no warnings.
- For curl testing with a custom CA file:

```bash
curl --cacert ./path/to/rootCA.pem https://file-server.local:8443/
```

Notes
- For LAN development mkcert is the fastest option: generate trusted certs quickly and install the CA on clients.
- For public servers use Let's Encrypt and automate renewal with `certbot renew`.

If you want, I can update `generate_mkcert.sh` to store certs in `./certs` by default and show exact commands for installing `mkcert` on your system.
 
Examples and parameters (hands-on)
================================

Below are common scenarios with copy-paste commands and explanations.

1) Quick HTTP (LAN, no encryption)

```bash
python3 file_server.py --protocol http --host 0.0.0.0 --port 8080 --token mysecret
```

Notes:
- `--protocol http` forces HTTP. If neither `--protocol` nor `--tls` are set, server runs HTTP.
- `--host 0.0.0.0` binds to all interfaces (LAN accessible).
- `--token mysecret` sets a simple auth token — include `X-Auth-Token: mysecret` in requests.

2) HTTPS with temporary self-signed certificate (fast, for testing)

```bash
python3 file_server.py --protocol https --generate-self-signed --host 0.0.0.0 --port 8443 --token mysecret
```

Notes:
- `--generate-self-signed` creates a temporary cert using `openssl` — browsers will warn about it.

3) HTTPS in LAN without warnings — mkcert (recommended for dev in LAN)

Generate certs (on the machine used to create them):

```bash
# install mkcert and run mkcert -install
mkdir -p certs
mkcert -cert-file certs/server.crt -key-file certs/server.key "file-server.local" "192.168.1.42"
```

Run server:

```bash
python3 file_server.py --protocol https --cert ./certs/server.crt --key ./certs/server.key --host 0.0.0.0 --port 443 --token mysecret
```

Notes:
- `mkcert -install` creates a local CA and installs it into the system/browser trust store on the machine where it is run. For other client machines, either run `mkcert -install` there too, or export/import the `rootCA.pem` to their trust stores.

4) Public HTTPS — Let's Encrypt

```bash
./obtain_cert_lets_encrypt.sh -d your.domain.tld -m admin@your.domain -w ./static
# then
python3 file_server.py --protocol https --cert ./certs/your.domain.tld/fullchain.pem --key ./certs/your.domain.tld/privkey.pem --host 0.0.0.0 --port 443 --token mysecret
```

Notes:
- Let's Encrypt issues certificates trusted by browsers. Requires a publicly routable domain and ACME challenge (HTTP or DNS).

5) curl client examples

List files:

```bash
curl -H "X-Auth-Token: mysecret" http://localhost:8080/files
```

Upload file (multipart):

```bash
curl -H "X-Auth-Token: mysecret" -F "file=@./localfile.txt" http://localhost:8080/upload
```

Download file:

```bash
curl -H "X-Auth-Token: mysecret" -o out.txt "http://localhost:8080/download/subdir/file.txt"
```

Delete file:

```bash
curl -X DELETE -H "X-Auth-Token: mysecret" "http://localhost:8080/delete/subdir/file.txt"
```

6) CLI parameter explanations

- `--protocol` — selects `http`, `https` or `ftp`. Overrides legacy `--tls` if provided.
- `--tls` — legacy flag to enable HTTPS (kept for backward compatibility).
- `--cert` / `--key` — TLS certificate and private key (PEM format).
- `--generate-self-signed` — generate a temporary self-signed certificate.
- `--token` — simple authentication token; server requires `X-Auth-Token` header or `?token=` if provided.
- `--dir` — storage directory (default: `./data` next to script); absolute paths outside `./data` are ignored for safety.
- `--host` / `--port` — bind address and port.
 
Basic auth — examples

Start server with HTTP Basic (alternative to token):
```bash
python3 file_server.py --protocol http --host 0.0.0.0 --port 8080 --basic-user alice --basic-pass s3cr3t
```

curl examples with Basic Authorization:
```bash
# list files
curl -H "Authorization: Basic $(echo -n 'alice:s3cr3t' | base64)" http://localhost:8080/files

# upload
curl -H "Authorization: Basic $(echo -n 'alice:s3cr3t' | base64)" -F "file=@./localfile.txt" http://localhost:8080/upload
```

Combining token and Basic
- The server accepts either a valid token (X-Auth-Token / ?token=) or correct Basic credentials. You can configure both and clients send the header they have.

Ready-to-run server examples
----------------------------

- HTTP without auth (quick test):
```bash
python3 file_server.py --protocol http --host 0.0.0.0 --port 8080
```

- HTTP + token:
```bash
python3 file_server.py --protocol http --host 0.0.0.0 --port 8080 --token mysecret
```

- HTTP + Basic auth:
```bash
python3 file_server.py --protocol http --host 0.0.0.0 --port 8080 --basic-user alice --basic-pass s3cr3t
```

- HTTPS (self-signed) + token:
```bash
python3 file_server.py --protocol https --generate-self-signed --host 0.0.0.0 --port 8443 --token mysecret
```

- HTTPS (mkcert) + Basic auth:
```bash
# generate certs/server.crt and certs/server.key via mkcert
python3 file_server.py --protocol https --cert ./certs/server.crt --key ./certs/server.key --host 0.0.0.0 --port 443 --basic-user alice --basic-pass s3cr3t
```

- FTP + token:
```bash
python3 file_server.py --protocol ftp --host 0.0.0.0 --port 21 --token mysecret
```

- FTP + Basic auth:
```bash
python3 file_server.py --protocol ftp --host 0.0.0.0 --port 21 --basic-user alice --basic-pass s3cr3t
```

- FTP without auth (anonymous):
```bash
python3 file_server.py --protocol ftp --host 0.0.0.0 --port 21
```

Checklist to avoid browser warnings (trusted certificates)
--------------------------------------------------------
1) Choose how to obtain a trusted certificate:
   - Let's Encrypt for public domains (browsers trust it automatically).
   - mkcert for LAN/dev (creates local CA and signs certs).

2) Obtain certificate and key and place them under `./certs` or any path you choose.

3) Make sure clients trust the CA:
   - For Let's Encrypt nothing to do.
   - For mkcert: run `mkcert -install` on each client machine or import `rootCA.pem` into the system trust store.

4) Ensure the URL you open matches the certificate SANs (hostname or IP).

5) Check networking: port 443 (or your chosen port) must be reachable for clients.

6) Test from a client:
```bash
curl -v --cacert ./path/to/rootCA.pem https://file-server.local:443/ui/
```
Example:

with https

python3 file_server.py \
  --protocol https \
  --cert ./certs/server.crt \
  --key ./certs/server.key \
  --host 0.0.0.0 \
  --port 443 \
  --basic-user alice \
  --basic-pass s3cr3t \
  --token mytoken123

with http

python3 file_server.py \
  --protocol http \
  --host 0.0.0.0 \
  --port 8080 \
  --basic-user alice \
  --basic-pass s3cr3t \
  --token mytoken123


# FTP with token
python3 file_server.py --protocol ftp --host 0.0.0.0 --port 21 --token mysecret

# FTP with basic auth
python3 file_server.py --protocol ftp --host 0.0.0.0 --port 21 --basic-user alice --basic-pass s3cr3t

# FTP anonymous(Purely for testing, do not use for serious tasks!!)
python3 file_server.py --protocol ftp --host 0.0.0.0 --port 21

## Server GUI

A graphical interface for managing the server based on CustomTkinter is now available. The GUI allows easy configuration and launching of the server without the command line, with real-time log display.

### Running the GUI

```bash
python3 server_gui.py
```
### Running the GUI for client

```bash
python3 client.py gui 
```

### Installing Dependencies

The GUI uses CustomTkinter. Install it:

```bash
pip install customtkinter
```

On Linux, tkinter may also be required:

Debian/Ubuntu:
```bash
sudo apt install python3-tk
```

Fedora:
```bash
sudo dnf install python3-tkinter
```

On Windows/macOS, tkinter is usually included with Python.

### GUI Features

- **Server Settings**: Host, port, directory, protocol (http/https/ftp).
- **Authentication**: Token, Basic auth (username/password).
- **TLS Settings**: Certificate and key paths, self-signed certificate generation.
- **FTP Settings**: Allow anonymous access, permissions (read/write/full).
- **Actions**: Start/stop server, save configuration.
- **Logs**: Real-time display of server output.

Configuration is saved in `server_gui_config.json` for convenience.
And before you start the server, make sure that you have the port that is in use open, otherwise it will not work.
