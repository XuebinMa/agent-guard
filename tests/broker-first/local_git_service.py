"""Finite local Git/TLS fixture. Not a deployable HTTP server.

Uses the installed Git CGI backend rather than reimplementing smart HTTP:
https://git-scm.com/docs/git-http-backend . All identities, keys, repositories,
and authorization values are generated for the temporary test directory.
Default binding is loopback only; the native fixture may opt into the verified
private docker0 address, never a wildcard/public/listener on another interface.
"""

import base64
import hmac
import http.server
import ipaddress
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import ssl
import subprocess
import threading
from urllib.parse import urlsplit


def git_env():
    """No developer config, hooks, proxy, helper, or Git environment inheritance."""
    return {
        "PATH": os.defpath,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "LC_ALL": "C",
    }


def run_git(repo, *args, check=True):
    return subprocess.run(
        [shutil.which("git"), "-c", "core.hooksPath=" + os.devnull, *args],
        cwd=repo, env=git_env(), capture_output=True, timeout=20, check=check,
    )


def docker_bridge_listener(address):
    """Opt-in native fixture listener, never wildcard or a public/LAN interface.

    The native driver additionally checks the trusted daemon's default bridge
    Gateway. Here require the exact private address on the host's docker0
    interface before binding, rather than accepting any RFC1918 address.
    """
    ip = ipaddress.IPv4Address(address)
    private_ranges = [ipaddress.IPv4Network(value) for value in
                      ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]]
    if str(ip) != address or not any(ip in network for network in private_ranges):
        raise ValueError("fixture bridge address must be canonical RFC1918 IPv4")
    if platform.system() != "Linux":
        raise ValueError("Docker bridge fixture requires native Linux")
    binary = shutil.which("ip", path="/usr/sbin:/usr/bin:/sbin:/bin")
    if binary is None:
        raise ValueError("iproute2 is required to verify the local Docker bridge")
    result = subprocess.run(
        [binary, "-j", "address", "show", "dev", "docker0"],
        check=True, capture_output=True, text=True, timeout=5,
        env={"PATH": os.defpath, "LC_ALL": "C"},
    )
    interfaces = json.loads(result.stdout)
    if not isinstance(interfaces, list) or not any(
        isinstance(interface, dict) and any(
            isinstance(entry, dict) and entry.get("family") == "inet"
            and entry.get("local") == address
            for entry in interface.get("addr_info", [])
        ) for interface in interfaces
    ):
        raise ValueError("fixture address is not present on local docker0")
    return address


class LocalGitService:
    """Authenticated local fixture; loopback unless native bridge is verified."""

    def __init__(self, root, *, docker_bridge_address=None):
        address = "127.0.0.1" if docker_bridge_address is None else docker_bridge_listener(docker_bridge_address)
        self.root = Path(root)
        self.remote = self.root / "repo.git"
        self.cert = self.root / "test-ca.pem"
        self.key = self.root / "test-key.pem"
        self._auth = "Basic " + base64.b64encode(
            ("fixture:" + secrets.token_hex(24)).encode()
        ).decode()
        self._lock = threading.Lock()
        self.handshake_started = threading.Event()
        self._closed = False
        self.requests = []  # method, path, authenticated; never raw headers.
        run_git(self.root, "init", "--bare", "-b", "main", str(self.remote))
        # No live identity or key store. Key/cert are ephemeral and private.
        subprocess.run(
            [shutil.which("openssl"), "req", "-x509", "-newkey", "rsa:2048",
             "-nodes", "-days", "1", "-subj", "/CN=localhost",
             "-addext", "subjectAltName=DNS:localhost,IP:" + address,
             "-keyout", str(self.key), "-out", str(self.cert)],
            check=True, capture_output=True, timeout=20,
        )
        self.key.chmod(0o600)
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *_):
                pass  # Do not log tokens, payloads, or arbitrary client text.

            def do_GET(self):
                self.serve()

            def do_POST(self):
                self.serve()

            def refuse(self, status):
                self.send_response(status)
                if status == 401:
                    self.send_header("WWW-Authenticate", 'Basic realm="local-fixture"')
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True

            def serve(self):
                self.connection.settimeout(5)
                parsed = urlsplit(self.path)
                # Exactly three trusted CGI routes; no filesystem translation
                # of arbitrary client paths, scripts, or percent-encoded names.
                if parsed.path not in {
                    "/repo.git/info/refs", "/repo.git/git-upload-pack",
                    "/repo.git/git-receive-pack",
                }:
                    self.refuse(404)
                    return
                supplied = self.headers.get("Authorization", "")
                authenticated = hmac.compare_digest(supplied.encode(), owner._auth.encode())
                with owner._lock:
                    owner.requests.append((self.command, parsed.path, authenticated))
                if not authenticated:
                    self.refuse(401)
                    return
                if self.headers.get("Transfer-Encoding"):
                    self.refuse(400)
                    return
                try:
                    size = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    self.refuse(400)
                    return
                if not 0 <= size <= 16 * 1024 * 1024:
                    self.refuse(413)
                    return
                data = self.rfile.read(size)
                if len(data) != size:
                    self.refuse(400)
                    return
                env = git_env()
                env.update({
                    "GIT_PROJECT_ROOT": str(owner.root), "GIT_HTTP_EXPORT_ALL": "1",
                    "PATH_INFO": parsed.path, "QUERY_STRING": parsed.query,
                    "REQUEST_METHOD": self.command, "REMOTE_USER": "fixture",
                    "CONTENT_TYPE": self.headers.get("Content-Type", ""),
                    "CONTENT_LENGTH": str(size), "SERVER_PROTOCOL": "HTTP/1.0",
                })
                try:
                    result = subprocess.run(
                        [shutil.which("git"), "http-backend"], input=data, env=env,
                        capture_output=True, timeout=10, cwd=owner.root,
                    )
                except subprocess.TimeoutExpired:
                    self.refuse(504)
                    return
                headers, separator, body = result.stdout.partition(b"\r\n\r\n")
                if not separator or result.returncode:
                    self.refuse(502)
                    return
                fields = [line.split(b":", 1) for line in headers.split(b"\r\n")]
                if any(len(field) != 2 for field in fields):
                    self.refuse(502)
                    return
                status = 200
                for key, value in fields:
                    if key.lower() == b"status":
                        status = int(value.split()[0])
                self.send_response(status)
                for key, value in fields:
                    if key.lower() in {b"content-type", b"cache-control", b"expires", b"pragma"}:
                        self.send_header(key.decode("ascii"), value.strip().decode("ascii"))
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        tls.load_cert_chain(self.cert, self.key)

        class FixtureServer(http.server.ThreadingHTTPServer):
            def get_request(self):
                connection, address = super().get_request()
                # Bound TLS setup *before* the HTTP handler exists. Wrapping
                # the listening socket would handshake before Handler's timeout.
                connection.settimeout(1)
                owner.handshake_started.set()
                try:
                    return tls.wrap_socket(connection, server_side=True), address
                except OSError:
                    connection.close()
                    raise

        self.server = FixtureServer((address, 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_port
        self.url = f"https://{address}:{self.port}/repo.git"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def trusted_config(self, path):
        path = Path(path)
        # JSON is a safe double-quoted Git value for this absolute fixture path.
        path.write_text(
            f'[http "{self.url}"]\nsslCAInfo = {json.dumps(str(self.cert))}\n'
            f'extraHeader = {self._auth_header()}\n', encoding="utf-8",
        )
        path.chmod(0o600)
        return path

    def _auth_header(self):
        return "Authorization: " + self._auth

    def tip(self):
        result = run_git(self.remote, "show-ref", "--quiet", "--verify", "refs/heads/main", check=False)
        if result.returncode == 1:
            return None  # Git's explicit no-matching-ref result, not any error.
        result.check_returncode()
        return run_git(self.remote, "rev-parse", "--verify", "refs/heads/main").stdout.decode().strip()

    def close(self):
        if self._closed:
            return
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        if self.thread.is_alive():
            raise RuntimeError("local Git fixture did not stop")
        self._closed = True
