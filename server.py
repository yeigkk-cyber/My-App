from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock
from urllib.parse import urlparse
import base64, hashlib, hmac, json, os, secrets, shutil, socket, sys, time

ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("FABRIC_DATA_DIR", ROOT / "private-data")).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)
DATA = DATA_DIR / "fabric-data.json"
AUTH = DATA_DIR / "auth.json"
LEGACY_DATA = ROOT / "fabric-data.json"
if not DATA.exists() and LEGACY_DATA.exists():
    shutil.copy2(LEGACY_DATA, DATA)
LOCK = Lock()
SESSIONS = {}
ATTEMPTS = {}
ITERATIONS = 420_000
SESSION_TTL = 12 * 60 * 60

def _derive(code, salt):
    return hashlib.pbkdf2_hmac("sha256", code.encode("utf-8"), salt, ITERATIONS)

def configure_code():
    if AUTH.exists():
        try:
            return json.loads(AUTH.read_text(encoding="utf-8"))
        except Exception as exc:
            raise RuntimeError("Login configuration is unreadable; restore auth.json from backup.") from exc
    code = os.environ.get("FABRIC_LOGIN_CODE", "")
    if not code and sys.stdin.isatty():
        import getpass
        print("Set one shared app login code (at least 6 characters).")
        code = getpass.getpass("New login code: ")
        confirm = getpass.getpass("Confirm login code: ")
        if not hmac.compare_digest(code, confirm):
            raise RuntimeError("The two codes did not match.")
    if len(code) < 6 or len(code) > 128:
        raise RuntimeError("Set FABRIC_LOGIN_CODE to a code of 6-128 characters before starting the public app.")
    salt = secrets.token_bytes(16)
    record = {"salt": base64.b64encode(salt).decode(), "hash": base64.b64encode(_derive(code, salt)).decode(), "iterations": ITERATIONS}
    _write_auth(record)
    return record

def _write_auth(record):
    tmp = AUTH.with_suffix(".tmp")
    tmp.write_text(json.dumps(record), encoding="utf-8")
    os.replace(tmp, AUTH)

def read_data():
    if not DATA.exists():
        return {"items": [], "history": [], "deletedIds": []}
    try:
        return json.loads(DATA.read_text(encoding="utf-8"))
    except Exception:
        return {"items": [], "history": [], "deletedIds": []}

def merge_data(incoming):
    with LOCK:
        current = read_data()
        tombstones = set(current.get("deletedIds", [])) | set(incoming.get("deletedIds", []))
        items = {str(x.get("id")): x for x in current.get("items", []) if x.get("id") and str(x.get("id")) not in tombstones}
        for item in incoming.get("items", []):
            if item.get("id") and str(item["id"]) not in tombstones:
                items[str(item["id"])] = item
        logs = {str(x.get("id")): x for x in current.get("history", []) if x.get("id")}
        for entry in incoming.get("history", []):
            if entry.get("id"):
                logs[str(entry["id"])] = entry
        result = {"items": list(items.values()), "history": list(logs.values()), "deletedIds": list(tombstones)}
        tmp = DATA.with_suffix(".tmp")
        tmp.write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, DATA)
        return result

def _json(handler, status, obj, extra_headers=()):
    body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    for key, value in extra_headers:
        handler.send_header(key, value)
    handler.end_headers()
    handler.wfile.write(body)

def _cookie_secure(handler):
    return handler.headers.get("X-Forwarded-Proto", "").split(",")[0].strip() == "https" or handler.connection.__class__.__name__ == "SSLSocket"

class Handler(BaseHTTPRequestHandler):
    server_version = "FabricApp"
    sys_version = ""

    def _path(self):
        return urlparse(self.path).path

    def _session(self):
        cookie = self.headers.get("Cookie", "")
        token = ""
        for part in cookie.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "fabric_session": token = v
        rec = SESSIONS.get(token)
        if rec and rec["expires"] > time.time():
            rec["expires"] = time.time() + SESSION_TTL
            return token
        if token: SESSIONS.pop(token, None)
        return None

    def _require_auth(self):
        if self._session(): return True
        _json(self, 401, {"error": "unauthorized"})
        return False

    def _read_json(self, limit=30_000_000):
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > limit: raise ValueError("Invalid request size")
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def do_GET(self):
        path = self._path()
        if path == "/health": return _json(self, 200, {"ok": True})
        if path == "/api/auth/status": return _json(self, 200, {"authenticated": bool(self._session())})
        if path in ("/", "/index.html"):
            body = (ROOT / "index.html").read_bytes()
            self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body))); self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff"); self.send_header("Referrer-Policy", "same-origin")
            self.end_headers(); self.wfile.write(body); return
        if path == "/api/data":
            if not self._require_auth(): return
            return _json(self, 200, read_data())
        self.send_error(404)

    def do_POST(self):
        path = self._path()
        try:
            if path == "/api/auth/login":
                ip = self.client_address[0]
                now = time.time(); failures = [t for t in ATTEMPTS.get(ip, []) if now - t < 900]
                ATTEMPTS[ip] = failures
                if len(failures) >= 8: return _json(self, 429, {"error": "too_many_attempts"}, (("Retry-After", "900"),))
                data = self._read_json(4096); code = str(data.get("code", ""))
                rec = json.loads(AUTH.read_text(encoding="utf-8")); salt = base64.b64decode(rec["salt"])
                candidate = _derive(code, salt)
                if len(code) > 128 or not hmac.compare_digest(candidate, base64.b64decode(rec["hash"])):
                    failures.append(now); ATTEMPTS[ip] = failures
                    return _json(self, 401, {"error": "invalid_code"})
                ATTEMPTS.pop(ip, None)
                token = secrets.token_urlsafe(32); SESSIONS[token] = {"expires": now + SESSION_TTL}
                cookie = f"fabric_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}" + ("; Secure" if _cookie_secure(self) else "")
                return _json(self, 200, {"ok": True}, (("Set-Cookie", cookie),))
            if path == "/api/auth/logout":
                token = self._session()
                if token: SESSIONS.pop(token, None)
                cookie = "fabric_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0" + ("; Secure" if _cookie_secure(self) else "")
                return _json(self, 200, {"ok": True}, (("Set-Cookie", cookie),))
            if path == "/api/auth/change-code":
                if not self._require_auth(): return
                data = self._read_json(4096); code = str(data.get("newCode", ""))
                if len(code) < 6 or len(code) > 128: return _json(self, 400, {"error": "code_length"})
                salt = secrets.token_bytes(16)
                _write_auth({"salt": base64.b64encode(salt).decode(), "hash": base64.b64encode(_derive(code, salt)).decode(), "iterations": ITERATIONS})
                SESSIONS.clear()
                token = secrets.token_urlsafe(32)
                SESSIONS[token] = {"expires": time.time() + SESSION_TTL}
                cookie = f"fabric_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}" + ("; Secure" if _cookie_secure(self) else "")
                return _json(self, 200, {"ok": True}, (("Set-Cookie", cookie),))
            if path == "/api/data":
                if not self._require_auth(): return
                incoming = self._read_json()
                if not isinstance(incoming, dict): return _json(self, 400, {"error": "invalid_data"})
                return _json(self, 200, merge_data(incoming))
            return self.send_error(404)
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            return _json(self, 400, {"error": "invalid_request"})
        except Exception:
            return _json(self, 500, {"error": "server_error"})

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args), flush=True)

if __name__ == "__main__":
    try: configure_code()
    except Exception as e:
        print(f"Login setup error: {e}", file=sys.stderr); raise SystemExit(2)
    port = int(os.environ.get("PORT", "8766"))
    host = socket.gethostbyname(socket.gethostname())
    print(f"Listening on 0.0.0.0:{port}", flush=True)
    print("Local: http://127.0.0.1:%s" % port, flush=True)
    if host: print("Same Wi-Fi/LAN: http://%s:%s" % (host, port), flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
