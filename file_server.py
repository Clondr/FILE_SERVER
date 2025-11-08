"""Простой HTTP-файловый сервер для локальной сети.

Поддерживает:
- листинг файлов в каталоге
- загрузку (multipart/form-data)
- скачивание (передача файла, поддержка Range через FileResponse)
- удаление файлов
- простая аутентификация по токену (заголовок X-Auth-Token)

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
from pathlib import Path
from typing import Optional

import base64

from aiohttp import web

ROOT_VAR = "FILES_ROOT"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("file_server")


def secure_path(root: Path, rel_path: str) -> Path:
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
	return candidate


async def list_files(request: web.Request) -> web.Response:
	root = Path(request.app["root"]).resolve()
	items = []
	for dirpath, dirnames, filenames in os.walk(root):
		for f in filenames:
			full = Path(dirpath) / f
			rel = full.relative_to(root)
			stat = full.stat()
			items.append({
				"path": str(rel).replace("\\", "/"),
				"size": stat.st_size,
				"mtime": int(stat.st_mtime),
			})
	return web.json_response({"files": items})


async def download_file(request: web.Request) -> web.StreamResponse:
	rel_path = request.match_info.get("path", "")
	file_path = secure_path(Path(request.app["root"]), rel_path)
	if not file_path.exists() or not file_path.is_file():
		raise web.HTTPNotFound(text="File not found")
	# aiohttp.web.FileResponse поддерживает range-запросы
	return web.FileResponse(path=str(file_path))


async def upload(request: web.Request) -> web.Response:
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
		dest = secure_path(root, filename)
		dest.parent.mkdir(parents=True, exist_ok=True)
		# Записываем по частям
		with open(dest, "wb") as f:
			while True:
				chunk = await part.read_chunk()  # type: ignore
				if not chunk:
					break
				f.write(chunk)
		saved.append({"path": str(dest.relative_to(root)), "size": dest.stat().st_size})
		logger.info("Saved %s", dest)
	return web.json_response({"saved": saved})


async def delete_file(request: web.Request) -> web.Response:
	rel_path = request.match_info.get("path", "")
	file_path = secure_path(Path(request.app["root"]), rel_path)
	if not file_path.exists():
		raise web.HTTPNotFound(text="File not found")
	if file_path.is_dir():
		raise web.HTTPBadRequest(text="Path is a directory")
	file_path.unlink()
	logger.info("Deleted %s", file_path)
	return web.json_response({"deleted": str(file_path.relative_to(Path(request.app["root"])) )})


@web.middleware
async def auth_middleware(request: web.Request, handler):
	token = request.app.get("token")
	basic = request.app.get("basic_auth")

	# If no authentication is configured, allow all requests
	if not token and not basic:
		return await handler(request)

	# публичные пути: UI should be reachable without credentials so user can input them
	if request.method == "GET" and (request.path == "/" or request.path.startswith("/ui")):
		return await handler(request)

	# Try token authentication first (header or query)
	req_token = request.headers.get("X-Auth-Token") or request.query.get("token")
	if token and req_token and req_token == token:
		return await handler(request)

	# Try HTTP Basic authentication if configured
	if basic:
		auth_hdr = request.headers.get("Authorization", "")
		if auth_hdr.startswith("Basic "):
			try:
				b64 = auth_hdr.split(None, 1)[1].strip()
				decoded = base64.b64decode(b64).decode("utf-8")
				user, passwd = decoded.split(":", 1)
				if user == basic[0] and passwd == basic[1]:
					return await handler(request)
			except Exception:
				# fall through to unauthorized
				pass

	# If we reach here, authentication failed
	raise web.HTTPUnauthorized(text="Missing or invalid credentials")


async def index(request: web.Request) -> web.Response:
		# Перенаправление на веб-интерфейс
		raise web.HTTPFound(location='/ui/')


def create_app(root: str, token: Optional[str] = None) -> web.Application:
	app = web.Application(middlewares=[auth_middleware])
	app["root"] = str(Path(root))
	app["token"] = token
	app["basic_auth"] = None
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
		# Serve index.html at /ui/ first, then serve other static files under /ui/
		async def serve_ui_index(request):
			return web.FileResponse(path=static_dir / 'index.html')
		app.add_routes([web.get('/ui/', serve_ui_index)])
		app.router.add_static('/ui/', path=str(static_dir), show_index=False)

	return app


def main():
	parser = argparse.ArgumentParser(description="Simple file server for local network")
	parser.add_argument("--host", default="0.0.0.0", help="Host to bind (default: 0.0.0.0)")
	parser.add_argument("--port", type=int, default=8080, help="Port to bind (default: 8080)")
	parser.add_argument("--dir", default=os.environ.get(ROOT_VAR, "data"), help="Directory to serve (default: data under the script dir or $FILES_ROOT)")
	parser.add_argument("--token", default=os.environ.get("FILE_SERVER_TOKEN"), help="Simple auth token (optional). Also via FILE_SERVER_TOKEN env var")
	parser.add_argument("--basic-user", default=os.environ.get("FILE_SERVER_USER"), help="Username for HTTP Basic auth (optional)")
	parser.add_argument("--basic-pass", default=os.environ.get("FILE_SERVER_PASS"), help="Password for HTTP Basic auth (optional)")
	parser.add_argument("--tls", action="store_true", help="(legacy) Enable HTTPS (requires --cert and --key or use --generate-self-signed)")
	parser.add_argument("--protocol", choices=("http", "https"), default=None,
						help="Protocol to run the server with. Overrides --tls when provided. Choices: http, https")
	parser.add_argument("--cert", help="Path to TLS certificate (PEM)")
	parser.add_argument("--key", help="Path to TLS private key (PEM)")
	parser.add_argument("--generate-self-signed", action="store_true", help="Generate a temporary self-signed cert (requires openssl) and use it for TLS")
	args = parser.parse_args()

	# Принудительно ограничиваем доступ папкой `data` рядом со скриптом.
	# Если пользователь передал относительный путь — он трактуется относительно каталога скрипта.
	script_dir = Path(__file__).parent.resolve()
	allowed_root = script_dir / "data"

	# Если задан переменной окружения полный путь, используем его только если он внутри allowed_root.
	requested = Path(args.dir)
	if not requested.is_absolute():
		root = (script_dir / requested).resolve()
	else:
		root = requested.resolve()

	# Если полученный root не находится внутри allowed_root, принудительно использовать allowed_root.
	try:
		allowed_root_resolved = allowed_root.resolve()
	except Exception:
		allowed_root_resolved = allowed_root

	if not str(root).startswith(str(allowed_root_resolved)):
		logger.warning("Requested dir %s is outside allowed data directory; using %s instead", root, allowed_root_resolved)
		root = allowed_root_resolved

	if not root.exists():
		logger.info("Creating root directory %s", root)
		root.mkdir(parents=True, exist_ok=True)

	app = create_app(str(root), token=args.token)
	# configure basic auth if provided
	if args.basic_user and args.basic_pass:
		app["basic_auth"] = (args.basic_user, args.basic_pass)

	ssl_context = None
	# Determine whether to run with TLS:
	# Priority: --protocol if provided, otherwise legacy --tls flag.
	if args.protocol is not None:
		use_tls = (args.protocol == "https")
	else:
		use_tls = bool(args.tls)

	if use_tls:
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
	else:
		logger.info("Starting file server at http://%s:%s serving %s", args.host, args.port, root)

	web.run_app(app, host=args.host, port=args.port, ssl_context=ssl_context)


if __name__ == "__main__":
	main()
