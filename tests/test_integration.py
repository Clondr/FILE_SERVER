import subprocess
import sys
import time
import socket
import requests
import os
import tempfile
from pathlib import Path


def _find_free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def start_server(port: int, data_dir: Path, token: str):
    cmd = [sys.executable, str(Path(__file__).parents[1] / 'file_server.py'),
           '--host', '127.0.0.1', '--port', str(port), '--dir', str(data_dir), '--token', token]
    # Start server in background
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return proc


def wait_for_server(port: int, token: str, timeout=5.0):
    url = f'http://127.0.0.1:{port}/files'
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(url, headers={'X-Auth-Token': token}, timeout=0.5)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.1)
    return False


def stop_server(proc: subprocess.Popen):
    proc.terminate()
    try:
        proc.wait(timeout=2.0)
    except Exception:
        proc.kill()


def test_upload_download_and_list(tmp_path):
    port = _find_free_port()
    token = 'testtoken'
    data_dir = tmp_path / 'data'
    data_dir.mkdir()

    proc = start_server(port, data_dir, token)
    assert wait_for_server(port, token), 'server failed to start'

    try:
        # upload
        url = f'http://127.0.0.1:{port}/upload'
        files = {'file': ('hello.txt', b'hello world')}
        r = requests.post(url, files=files, headers={'X-Auth-Token': token})
        r.raise_for_status()
        assert 'saved' in r.json()

        # list
        r = requests.get(f'http://127.0.0.1:{port}/files', headers={'X-Auth-Token': token})
        r.raise_for_status()
        j = r.json()
        paths = [f['path'] for f in j['files']]
        assert 'hello.txt' in paths

        # download
        r = requests.get(f'http://127.0.0.1:{port}/download/hello.txt', headers={'X-Auth-Token': token})
        r.raise_for_status()
        assert r.content == b'hello world'
    finally:
        stop_server(proc)


def test_path_traversal_blocked(tmp_path):
    port = _find_free_port()
    token = 'testtoken'
    data_dir = tmp_path / 'data'
    data_dir.mkdir()

    proc = start_server(port, data_dir, token)
    assert wait_for_server(port, token), 'server failed to start'

    try:
        # Attempt to request a file outside the data dir via traversal
        r = requests.get(f'http://127.0.0.1:{port}/download/../file_server.py', headers={'X-Auth-Token': token})
        # server should reject (400) or not found (404)
        assert r.status_code in (400, 404)
    finally:
        stop_server(proc)


def test_client_rejects_bad_remote(tmp_path):
    # call client.py with invalid --remote and expect non-zero exit
    bad_remote = '../etc/passwd'
    cmd = [sys.executable, str(Path(__file__).parents[1] / 'client.py'), 'upload', 'http://127.0.0.1:1', str(tmp_path / 'f.txt'), '--remote', bad_remote]
    # create dummy file
    (tmp_path / 'f.txt').write_text('x')
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.wait()
    assert p.returncode != 0
