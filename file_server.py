"""Простой HTTP-файловый сервер для локальной сети.

Поддерживает:
- листинг файлов в каталоге
- загрузку (multipart/form-data)
- скачивание (передача файла, поддержка Range через FileResponse)
- удаление файлов
- простая аутентификация по токену (заголовок X-Auth-Token)
    Stable version 3.0
Зависимости: aiohttp, aiofiles (опционально). См. requirements.txt
"""

import argparse
import asyncio
import json
import logging
import os
import ssl
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional
from atexit import register
import base64

import aiofiles

from aiohttp import web

try:
    from pyftpdlib.authorizers import DummyAuthorizer
    from pyftpdlib.handlers import FTPHandler
    from pyftpdlib.servers import FTPServer
    FTP_AVAILABLE = True
except ImportError:
    FTP_AVAILABLE = False

ROOT_VAR = "FILES_ROOT"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("file_server")


def secure_path(root: Path, rel_path: str) -> Path: # Проверяет и возвращает безопасный путь внутри root
	"""Проверяет и возвращает безопасный путь внутри root.

	Бросает HTTPBadRequest, если путь выходит за пределы корня.
	"""
	# Отрезаем ведущие / и разрешаем ..
	candidate = (root / rel_path).resolve()
	try:
		root_resolved = root.resolve()
	except Exception:
		root_resolved = root
	if not str(candidate).startswith(str(root_resolved)):
		raise web.HTTPBadRequest(text="Invalid path")
	# Additional check: ensure no symlinks point outside root
	if candidate.is_symlink():
		target = candidate.readlink()
		if target.is_absolute():
			target_resolved = target.resolve()
		else:
			target_resolved = (candidate.parent / target).resolve()
		if not str(target_resolved).startswith(str(root_resolved)):
			raise web.HTTPBadRequest(text="Invalid path")
	return candidate


async def list_files(request: web.Request) -> web.Response: # """Возвращает список файлов в корневом каталоге."""

	root = Path(request.app["root"]).resolve()
	items = []
	# Limit to top-level directory only for security
	for f in os.listdir(root):
		full = root / f
		if full.is_file():
			stat = full.stat()
			items.append({
				"path": f,
				"size": stat.st_size,
				"mtime": int(stat.st_mtime),
			})
	return web.json_response({"files": items})


async def download_file(request: web.Request) -> web.StreamResponse: # """Отдает файл с поддержкой Range-запросов."""

	rel_path = request.match_info.get("path", "")
	file_path = secure_path(Path(request.app["root"]), rel_path)
	if not file_path.exists() or not file_path.is_file():
		logger.warning("File not found: %s", rel_path)
		raise web.HTTPNotFound(text="File not found")
	
	# Get file size
	file_size = file_path.stat().st_size
	
	# Check for Range header (for partial content requests - streaming support)
	range_header = request.headers.get("Range")
	
	if range_header:
		# Parse Range header: "bytes=start-end"
		try:
			range_spec = range_header.replace("bytes=", "")
			start_str, end_str = range_spec.split("-")
			start = int(start_str) if start_str else 0
			end = int(end_str) if end_str else file_size - 1
			
			# Validate range
			if start >= file_size or end < start:
				raise web.HTTPRangeNotSatisfiable(text="Range not satisfiable")
			
			# Clamp end to file size
			if end >= file_size:
				end = file_size - 1
			
			content_length = end - start + 1
			
			logger.info("Range request for %s: bytes %d-%d/%d", file_path, start, end, file_size)
			
			# Create response with proper headers for partial content
			response = web.StreamResponse(
				status=206,  # Partial Content
				headers={
					"Content-Type": "application/octet-stream",
					"Content-Length": str(content_length),
					"Content-Range": f"bytes {start}-{end}/{file_size}",
					"Accept-Ranges": "bytes",
					"Cache-Control": "no-cache",
				}
			)
			
			# Open file and seek to start position
			f = await aiofiles.open(file_path, "rb")
			await f.seek(start)
			
			async def file_sender():
				chunk_size = 64 * 1024  # 64KB chunks
				remaining = content_length
				while remaining > 0:
					to_read = min(chunk_size, remaining)
					chunk = await f.read(to_read)
					if not chunk:
						break
					yield chunk
					remaining -= len(chunk)
				await f.close()
			
			response.enable_chunked_encoding()
			response.disable_compression()
			return response
			
		except (ValueError, Exception) as e:
			logger.warning("Invalid Range header %s: %s", range_header, e)
			# Fall back to full file download
			pass
	
	# No Range header or invalid - return full file with streaming support
	logger.info("Downloaded %s", file_path)
	response = web.FileResponse(
		path=str(file_path),
		status=200,
		headers={
			"Content-Type": "application/octet-stream",
			"Content-Length": str(file_size),
			"Accept-Ranges": "bytes",
			"Cache-Control": "no-cache",
			# Connection timeout handling for large files on mobile
			"Keep-Alive": "timeout=300, max=100",
		}
	)
	return response


def secure_filename(filename: str) -> str: # """Sanitize filename to prevent path traversal and other issues."""

	"""Sanitize filename to prevent path traversal and other issues."""
	import re
	# Remove any path separators
	filename = re.sub(r'[\/\\]', '', filename)
	# Remove control characters
	filename = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', filename) # 
	# Remove reserved characters on Windows
	filename = re.sub(r'[<>:"|?*\x00-\x1f]', '_', filename) # 

	# Limit length
	filename = filename[:255]
	return filename or "unnamed"



async def upload(request: web.Request) -> web.Response: # """Принимает multipart/form-data и сохраняет файлы в корневой каталог."""

	# Use max_file_size from env or default 30GB
	max_file_size = int(os.environ.get("FILE_SERVER_MAX_FILE_SIZE", 30 * 1024 * 1024 * 1024))

	reader = await request.multipart()
	root = Path(request.app["root"])
	saved = []

	async for part in reader:
		# Ожидаем поле 'file' в multipart
		if part.name != "file":
			# можно поддерживать другие поля (например, path)
			continue
		filename = part.filename
		if not filename:
			continue
		filename = secure_filename(filename)
		if not filename:
			continue

		dest = secure_path(root, filename)
		dest.parent.mkdir(parents=True, exist_ok=True)

		# Async write using aiofiles
		size = 0
		async with aiofiles.open(dest, "wb") as f:
			while True: # Цикл чтения чанков
				chunk = await part.read_chunk()  # type: ignore
				if not chunk:
					break
				size += len(chunk)
				if size > max_file_size:
					await f.close()
					if dest.exists():
						dest.unlink()
					raise web.HTTPRequestEntityTooLarge(text="File too large")
				await f.write(chunk)

		saved.append({"path": str(dest.relative_to(root)), "size": dest.stat().st_size})
		logger.info("Saved %s", dest)
	return web.json_response({"saved": saved})


async def delete_file(request: web.Request) -> web.Response: # """Удаляет файл по указанному пути."""

	rel_path = request.match_info.get("path", "") # 
	if not rel_path:
		raise web.HTTPBadRequest(text="Missing path")

	file_path = secure_path(Path(request.app["root"]), rel_path)
	if not file_path.exists():
		logger.warning("File not found for deletion: %s", rel_path)
		raise web.HTTPNotFound(text="File not found")
	if file_path.is_dir():
		logger.warning("Attempted to delete directory: %s", rel_path)
		raise web.HTTPBadRequest(text="Path is a directory")
	file_path.unlink()
	logger.info("Deleted %s", file_path)
	return web.json_response({"deleted": str(file_path.relative_to(Path(request.app["root"])))})


# Simple rate limiter
rate_limits = {}

@web.middleware
async def auth_middleware(request: web.Request, handler): # """Проверяет токен авторизации, если он задан."""

	token = request.app.get("token") # 
	basic = request.app.get("basic_auth") # 

	# Rate limiting: 100 requests per minute per IP
	client_ip = request.remote or "unknown"
	now = time.time()
	if client_ip not in rate_limits:
		rate_limits[client_ip] = []
	rate_limits[client_ip] = [t for t in rate_limits[client_ip] if now - t < 60] # 
	if len(rate_limits[client_ip]) >= 100:
		logger.warning("Rate limit exceeded for %s", client_ip) # 
		raise web.HTTPTooManyRequests(text="Rate limit exceeded") # 
	rate_limits[client_ip].append(now) # 

	# If no authentication is configured, allow all requests
	if not token and not basic:
		return await handler(request)

	# публичные пути: UI should be reachable without credentials so user can input them
	if request.method == "GET" and (request.path == "/" or request.path.startswith("/static")):
		return await handler(request)

	# Check authentication based on configuration
	token_valid = False
	basic_valid = False

	# Get query params for auth (supports download via URL with auth params)
	query_params = request.query

	# Check token if configured - support both header and query param
	if token:
		req_token = request.headers.get("X-Auth-Token") or query_params.get("token")
		if req_token and req_token == token:
			token_valid = True

	# Check basic auth if configured - support both header and query params
	if basic:
		# Try header first
		auth_hdr = request.headers.get("Authorization", "")
		if auth_hdr.startswith("Basic "):
			try:
				b64 = auth_hdr.split(None, 1)[1].strip()
				decoded = base64.b64decode(b64).decode("utf-8")
				user, passwd = decoded.split(":", 1)
				if user == basic[0] and passwd == basic[1]:
					basic_valid = True
			except Exception:
				pass
		
		# Also support query params for direct downloads (user=xxx&pass=xxx)
		if not basic_valid:
			req_user = query_params.get("user")
			req_pass = query_params.get("pass")
			if req_user and req_pass and req_user == basic[0] and req_pass == basic[1]:
				basic_valid = True

	# Authentication logic:
	# - If only token configured: require token
	# - If only basic configured: require basic
	# - If both configured: require both
	if token and basic: # Если токен и basic настроены

		# Both must be valid
		if not (token_valid and basic_valid):
			logger.warning("Authentication failed for %s from %s (both token and basic required)", request.path, client_ip)
			raise web.HTTPUnauthorized(text="Missing or invalid credentials")
	elif token:
		# Only token required
		if not token_valid:
			logger.warning("Authentication failed for %s from %s (token required)", request.path, client_ip)
			raise web.HTTPUnauthorized(text="Missing or invalid credentials")
	elif basic:
		# Only basic required
		if not basic_valid:
			logger.warning("Authentication failed for %s from %s (basic auth required)", request.path, client_ip)
			raise web.HTTPUnauthorized(text="Missing or invalid credentials")

	return await handler(request) # # Вызов следующего обработчика в цепочке


async def index(request: web.Request) -> web.Response: # """Обработчик главной страницы."""
	# Serve index.html from static directory
	static_dir = Path(__file__).parent / "static"
	return web.FileResponse(path=str(static_dir / 'index.html'))


def create_app(root: str, token: Optional[str] = None) -> web.Application: # """Создаёт aiohttp приложение."""

	app = web.Application(middlewares=[auth_middleware]) #
	
	# Set max request size to 50GB (beyond which aiohttp would reject)
	app._client_max_size = 50 * 1024 * 1024 * 1024  # 50 GB

	logger.info("Serving directory: %s", root)

	app["root"] = str(Path(root)) #
	logger.info("Serving directory: %s", app["root"])

	app["token"] = token
	logger.info("Token auth enabled: %s", token is not None)

	app["basic_auth"] = None
	logger.info("Basic auth enabled: %s", app["basic_auth"] is not None)

	app.add_routes([
		web.get("/", index),
		web.get("/files", list_files),
		web.get(r"/download/{path:.*}", download_file),
		web.post("/upload", upload),
		web.delete(r"/delete/{path:.*}", delete_file),
	])

	# Serve web UI static files from ./static relative to this script
	static_dir = Path(__file__).parent / "static"
	if static_dir.exists():
		# Serve static files under /static/ prefix (index.html handled at root)
		app.router.add_static('/static/', path=str(static_dir), show_index=False)

	return app


def main(): # """Главная функция для запуска сервера."""

	parser = argparse.ArgumentParser(description="Simple file server for local network") # Подсказки
	parser.add_argument("--host", default="0.0.0.0", help="Host to bind (default: 0.0.0.0)")
	parser.add_argument("--port", type=int, default=8080, help="Port to bind (default: 8080)")
	parser.add_argument("--dir", default=os.environ.get(ROOT_VAR, "data"), help="Directory to serve (default: data under the script dir or $FILES_ROOT)")
	parser.add_argument("--token", default=os.environ.get("FILE_SERVER_TOKEN"), help="Simple auth token (optional). Also via FILE_SERVER_TOKEN env var")
	parser.add_argument("--basic-user", default=os.environ.get("FILE_SERVER_USER"), help="Username for HTTP Basic auth (optional)")
	parser.add_argument("--basic-pass", default=os.environ.get("FILE_SERVER_PASS"), help="Password for HTTP Basic auth (optional)")
	parser.add_argument("--tls", action="store_true", help="(legacy) Enable HTTPS (requires --cert and --key or use --generate-self-signed)")
	parser.add_argument("--protocol", choices=("http", "https", "ftp"), default=None,
						help="Protocol to run the server with. Overrides --tls when provided. Choices: http, https, ftp")
	parser.add_argument("--cert", help="Path to TLS certificate (PEM)")
	parser.add_argument("--key", help="Path to TLS private key (PEM)")
	parser.add_argument("--generate-self-signed", action="store_true", help="Generate a temporary self-signed cert (requires openssl) and use it for TLS")
	parser.add_argument("--ftp-allow-anonymous", action="store_true", help="Allow anonymous FTP access (default: False)")
	parser.add_argument("--ftp-permissions", choices=["read", "write", "full"], default="full", help="FTP permissions: read, write, or full (default: full)")
	args = parser.parse_args()

	# Принудительно ограничиваем доступ папкой `data` рядом со скриптом.
	# Если пользователь передал относительный путь — он трактуется относительно каталога скрипта.
	script_dir = Path(__file__).parent.resolve() # 
	# Принудительно ограничиваем доступ папкой `data` рядом со скриптом.

	allowed_root = script_dir / "data" # 
	logger.info("Allowed root directory: %s", allowed_root)


	# Если задан переменной окружения полный путь, используем его только если он внутри allowed_root.
	requested = Path(args.dir) # 
	# Преобразуем в абсолютный путь, если он относительный

	if not requested.is_absolute(): # 
		# Если передан относительный путь, преобразуем его в абсолютный относительно script_dir

		root = (script_dir / requested).resolve()
	else:
		root = requested.resolve()

	# Если полученный root не находится внутри allowed_root, принудительно использовать allowed_root.
	try:
		allowed_root_resolved = allowed_root.resolve()
	except Exception:
		allowed_root_resolved = allowed_root
		print('Используй нормальные пути!')

	if not str(root).startswith(str(allowed_root_resolved)): # 
		# Если root не находится внутри allowed_root, выводим предупреждение и используем allowed_root вместо этого.

		logger.warning("Requested dir %s is outside allowed data directory; using %s instead", root, allowed_root_resolved)
		root = allowed_root_resolved # 
		logger.info("Forced root to allowed directory: %s", root)


	if not root.exists(): # 
		# Если корневая директория не существует, создаем её.


		logger.info("Creating root directory %s", root)
		root.mkdir(parents=True, exist_ok=True)

	app = create_app(str(root), token=args.token) # 
	logger.info("Application created with root: %s", app["root"])

	# configure basic auth if provided
	if args.basic_user and args.basic_pass:
		app["basic_auth"] = (args.basic_user, args.basic_pass)

	ssl_context = None
	# Determine protocol and TLS:
	protocol = args.protocol or ("https" if args.tls else "http")
	if protocol not in ("http", "https", "ftp"):
		logger.error("Invalid protocol: %s", protocol)
		return
	use_tls = (protocol == "https")
	is_ftp = (protocol == "ftp")

	if is_ftp:
		if not FTP_AVAILABLE: # 
		# FTP server requested but pyftpdlib not installed

			logger.error("FTP protocol requested but pyftpdlib is not installed. Install with: pip install pyftpdlib")
			return
		# Start FTP server
		authorizer = DummyAuthorizer()

		# Determine permissions based on --ftp-permissions
		perm_map = {
			"read": "elr",  # list, enter, read
			"write": "adfmw",  # append, delete, file rename, make dir, write
			"full": "elradfmw"  # all permissions
		}
		permissions = perm_map[args.ftp_permissions] # 
		logger.info("FTP: Using permissions: %s", permissions)


		# Authentication logic for FTP:
		# - If --ftp-allow-anonymous is set: allow anonymous access with specified permissions
		# - Else if no auth configured: no anonymous, require auth
		# - If only token configured: use token as password for user "user"
		# - If only basic configured: use basic user/pass
		# - If both configured: use basic user/pass (FTP limitation)

		if args.ftp_allow_anonymous: # 
			# Anonymous access allowed
			authorizer.add_anonymous(str(root), perm=permissions)
			logger.info("FTP: Anonymous access enabled with permissions: %s", permissions)
		else:
			# Require authentication
			if not args.token and not (args.basic_user and args.basic_pass):
				logger.error("FTP: Authentication required but no credentials provided. Use --ftp-allow-anonymous or provide --token or --basic-user/--basic-pass")
				return
			if args.basic_user and args.basic_pass:
				# Use basic auth credentials
				user = args.basic_user
				passwd = args.basic_pass
			else:
				# Use token as password
				user = "user"
				passwd = args.token
			authorizer.add_user(user, passwd, str(root), perm=permissions)
			logger.info("FTP: Authenticated access with user '%s' and permissions: %s", user, permissions)

		# Custom handler to log actions
		class LoggingFTPHandler(FTPHandler):
			def on_file_received(self, file):
				logger.info("FTP: File uploaded: %s", file)
			def on_file_sent(self, file):
				logger.info("FTP: File downloaded: %s", file)
			def on_delete(self, file):
				logger.info("FTP: File deleted: %s", file)

		handler = LoggingFTPHandler
		handler.authorizer = authorizer

		server = FTPServer((args.host, args.port), handler)
		logger.info("Starting FTP server at ftp://%s:%s serving %s", args.host, args.port, root)
		try:
			server.serve_forever()
		except KeyboardInterrupt:
			logger.info("FTP server stopped")
	elif use_tls:
		# Determine cert/key
		cert_path = args.cert
		key_path = args.key
		if args.generate_self_signed:
			# create temp cert/key inside data dir or tmp
			tmpdir = Path(tempfile.mkdtemp(prefix='file_server_tls_'))
			cert_path = str(tmpdir / 'cert.pem')
			key_path = str(tmpdir / 'key.pem')
			logger.info("Generating self-signed certificate to %s (requires openssl)", tmpdir)
			try:
				subprocess.run([
					'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes',
					'-keyout', key_path, '-out', cert_path, '-days', '365',
					'-subj', '/CN=localhost'
				], check=True)
			except Exception as e:
				logger.error("Failed to generate self-signed certificate: %s", e)
				raise

		if not cert_path or not key_path: #
			raise SystemExit("TLS enabled but --cert/--key not provided (or use --generate-self-signed)")

		ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
		ssl_context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

		logger.info("Starting file server at https://%s:%s serving %s", args.host, args.port, root)
		web.run_app(app, host=args.host, port=args.port, ssl_context=ssl_context)
	else:
		logger.warning("Starting server without TLS. For production, use HTTPS to protect data in transit.")
		logger.info("Starting file server at http://%s:%s serving %s", args.host, args.port, root)
		web.run_app(app, host=args.host, port=args.port, ssl_context=ssl_context)


if __name__ == "__main__":
	print('https://127.0.0.1:8000/')
	print('http://127.0.0.1:8000/')
	main()
	


@register # register the goodbye function to be called at exit
def goodbye():
	print("Thank you for using FILE_SERVER!")
	print("Goodbye!")
