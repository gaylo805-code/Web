#!/usr/bin/env python3
"""
ESP32 Web IDE - Server có xác thực
- Yêu cầu mật khẩu để đăng nhập (lấy từ biến môi trường WEB_PASSWORD)
- Mọi API (trừ /login) đều cần token hợp lệ trong header Authorization
- Không có endpoint chạy lệnh shell tùy ý
- Mọi thao tác file đều bị giới hạn trong WORK_DIR (chống path traversal)
"""
import http.server
import json
import os
import secrets
import subprocess
import time
import urllib.parse
from pathlib import Path

WORK_DIR = os.environ.get("WORK_DIR", os.getcwd())
WEB_PASSWORD = os.environ.get("WEB_PASSWORD", "")
SESSION_TTL = 6 * 3600  # 6 tiếng

# Danh sách target hợp lệ cho build (tránh nhận chuỗi tùy ý) — dùng cho idf.py set-target
ALLOWED_TARGETS = {"esp32", "esp32s2", "esp32s3", "esp32c3"}

# Lệnh chẩn đoán cố định — KHÔNG nhận chuỗi lệnh tùy ý từ người dùng.
# Đây là biện pháp an toàn: server chạy công khai, không cho phép RCE tự do
# dù đã có mật khẩu, để tránh máy bị lợi dụng nếu mật khẩu rò rỉ.
# Đường dẫn cài ESP-IDF (khớp với bước cài trong workflow)
IDF_EXPORT = "source $HOME/esp-idf/export.sh"


def run_idf(shell_cmd, cwd=None, timeout=600):
    """Chạy lệnh trong môi trường đã (cố gắng) source export.sh của ESP-IDF.
    Nếu export.sh chưa tồn tại/lỗi, vẫn tiếp tục chạy lệnh (để các lệnh không cần idf.py như
    list_files, disk_space vẫn hoạt động bình thường)."""
    return subprocess.run(
        ["bash", "-lc", f"( {IDF_EXPORT} ) > /dev/null 2>&1; {shell_cmd}"],
        cwd=cwd or WORK_DIR, capture_output=True, text=True, timeout=timeout,
    )


# Lệnh chẩn đoán cố định — KHÔNG nhận chuỗi lệnh tùy ý từ người dùng.
# Đây là biện pháp an toàn: server chạy công khai, không cho phép RCE tự do
# dù đã có mật khẩu, để tránh máy bị lợi dụng nếu mật khẩu rò rỉ.
DIAG_COMMANDS = {
    "idf_version": "idf.py --version",
    "list_targets": "idf.py --list-targets",
    "menuconfig_check": "idf.py set-target esp32 2>&1 | tail -20",
    "list_files": "find . -maxdepth 3 -type f -not -path './.git/*'",
    "disk_space": "df -h .",
    "build_dir": "ls -la build 2>&1 || echo 'Chưa có thư mục build'",
    "size_info": "idf.py size 2>&1 || echo 'Chưa build lần nào'",
}

# token -> hết hạn (epoch)
_sessions = {}

# Chống brute-force: ip -> [timestamps các lần login sai]
_failed_logins = {}
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 60

# Lịch sử build gần nhất (lưu trong RAM, mất khi restart server)
_build_history = []
MAX_HISTORY = 20


def new_session():
    token = secrets.token_urlsafe(32)
    _sessions[token] = time.time() + SESSION_TTL
    return token


def is_valid_session(token):
    exp = _sessions.get(token)
    if exp is None:
        return False
    if time.time() > exp:
        _sessions.pop(token, None)
        return False
    return True


def safe_path(name: str) -> str:
    """Trả về đường dẫn tuyệt đối bên trong WORK_DIR, chặn '..' và path traversal."""
    base = Path(WORK_DIR).resolve()
    candidate = (base / name).resolve()
    if base not in candidate.parents and candidate != base:
        raise ValueError("Đường dẫn không hợp lệ")
    return str(candidate)


def ensure_esp_idf_project():
    """Đảm bảo có cấu trúc project ESP-IDF tối thiểu (CMakeLists.txt + main/) nếu chưa có."""
    base = Path(WORK_DIR).resolve()

    cmake_file = base / "CMakeLists.txt"
    if not cmake_file.exists():
        cmake_file.write_text(
            "cmake_minimum_required(VERSION 3.16)\n\n"
            "include($ENV{IDF_PATH}/tools/cmake/project.cmake)\n"
            f"project({base.name.replace('-', '_')})\n"
        )
        print("✅ Đã tạo CMakeLists.txt")

    main_dir = base / "main"
    main_dir.mkdir(exist_ok=True)

    main_cmake = main_dir / "CMakeLists.txt"
    if not main_cmake.exists():
        main_cmake.write_text('idf_component_register(SRCS "main.c"\n                       INCLUDE_DIRS ".")\n')
        print("✅ Đã tạo main/CMakeLists.txt")

    main_c = main_dir / "main.c"
    if not main_c.exists():
        main_c.write_text(
            "#include <stdio.h>\n"
            '#include "freertos/FreeRTOS.h"\n'
            '#include "freertos/task.h"\n\n'
            "void app_main(void)\n"
            "{\n"
            "    while (1) {\n"
            '        printf("Hello from ESP32!\\n");\n'
            "        vTaskDelay(pdMS_TO_TICKS(1000));\n"
            "    }\n"
            "}\n"
        )
        print("✅ Đã tạo main/main.c")


class APIHandler(http.server.SimpleHTTPRequestHandler):

    def _send_json(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return False
        token = auth[len("Bearer "):]
        return is_valid_session(token)

    def _require_auth(self):
        if not self._authorized():
            self._send_json(401, {"error": "Chưa đăng nhập hoặc token hết hạn"})
            return False
        return True

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/":
            self.path = "/login.html" if not self._authorized() else "/dashboard.html"
            return http.server.SimpleHTTPRequestHandler.do_GET(self)

        if parsed.path == "/files":
            if not self._require_auth():
                return
            files = []
            for f in Path(WORK_DIR).rglob("*"):
                if f.is_file() and ".git" not in str(f) and "build" not in str(f):
                    files.append({"name": str(f.relative_to(WORK_DIR)), "size": f.stat().st_size})
            self._send_json(200, files)
            return

        if parsed.path == "/file":
            if not self._require_auth():
                return
            params = urllib.parse.parse_qs(parsed.query)
            name = params.get("name", [""])[0]
            try:
                filepath = safe_path(name)
            except ValueError as e:
                self._send_json(400, {"error": str(e)})
                return
            if os.path.exists(filepath) and os.path.isfile(filepath):
                with open(filepath, "r", errors="replace") as f:
                    content = f.read()
                self._send_json(200, {"content": content})
            else:
                self._send_json(404, {"error": "Không tìm thấy file"})
            return

        if parsed.path == "/download":
            if not self._require_auth():
                return
            params = urllib.parse.parse_qs(parsed.query)
            filename = params.get("file", [""])[0]
            allowed_ext = (".bin", ".elf", ".map")
            if not filename.endswith(allowed_ext):
                self._send_json(400, {"error": f"Chỉ cho phép tải file {allowed_ext}"})
                return
            try:
                filepath = safe_path("build/" + filename)
            except ValueError as e:
                self._send_json(400, {"error": str(e)})
                return
            if not os.path.exists(filepath):
                self._send_json(404, {"error": "Không tìm thấy file firmware"})
                return
            try:
                with open(filepath, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", f"attachment; filename={filename.split('/')[-1]}")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            except Exception as e:
                self._send_json(500, {"error": str(e)})
            return

        if parsed.path == "/build_files":
            if not self._require_auth():
                return
            build_dir = Path(WORK_DIR) / "build"
            files = []
            if build_dir.is_dir():
                for f in build_dir.rglob("*"):
                    if f.is_file() and f.suffix in (".bin", ".elf", ".map"):
                        files.append({"name": str(f.relative_to(build_dir)), "size": f.stat().st_size})
            self._send_json(200, files)
            return

        if parsed.path == "/build/history":
            if not self._require_auth():
                return
            self._send_json(200, _build_history)
            return

        if parsed.path == "/library/list":
            if not self._require_auth():
                return
            try:
                comp_dir = Path(WORK_DIR) / "managed_components"
                names = [d.name for d in comp_dir.iterdir() if d.is_dir()] if comp_dir.is_dir() else []
                self._send_json(200, names)
            except Exception:
                self._send_json(200, [])
            return

        if parsed.path == "/export":
            if not self._require_auth():
                return
            try:
                import io, zipfile
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                    for f in Path(WORK_DIR).rglob("*"):
                        rel = str(f.relative_to(WORK_DIR))
                        if f.is_file() and not rel.startswith((".git/", "build/", "__pycache__/")):
                            zf.write(f, rel)
                content = buf.getvalue()
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Disposition", "attachment; filename=project-export.zip")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            except Exception as e:
                self._send_json(500, {"error": str(e)})
            return

        try:
            if parsed.path.startswith("/.") or "/." in parsed.path:
                self.send_response(403)
                self.end_headers()
                return
            with open(parsed.path[1:], "rb") as f:
                content = f.read()
                self.send_response(200)
                if parsed.path.endswith(".html"):
                    self.send_header("Content-Type", "text/html")
                elif parsed.path.endswith(".css"):
                    self.send_header("Content-Type", "text/css")
                elif parsed.path.endswith(".js"):
                    self.send_header("Content-Type", "application/javascript")
                else:
                    self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
        except FileNotFoundError:
            self.send_response(404)
            self.end_headers()
        except Exception:
            self.send_response(500)
            self.end_headers()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else b"{}"
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            data = {}

        if parsed.path == "/login":
            ip = self.client_address[0]
            now = time.time()
            attempts = [t for t in _failed_logins.get(ip, []) if now - t < LOGIN_LOCKOUT_SECONDS]
            _failed_logins[ip] = attempts
            if len(attempts) >= MAX_LOGIN_ATTEMPTS:
                wait = int(LOGIN_LOCKOUT_SECONDS - (now - attempts[0]))
                self._send_json(429, {"error": f"Sai quá nhiều lần, thử lại sau {wait}s"})
                return

            password = data.get("password", "")
            if not WEB_PASSWORD:
                self._send_json(500, {"error": "Server chưa cấu hình WEB_PASSWORD"})
                return
            if secrets.compare_digest(password, WEB_PASSWORD):
                _failed_logins.pop(ip, None)
                token = new_session()
                self._send_json(200, {"token": token, "expires_in": SESSION_TTL})
            else:
                _failed_logins.setdefault(ip, []).append(now)
                remaining = MAX_LOGIN_ATTEMPTS - len(_failed_logins[ip])
                self._send_json(401, {"error": f"Sai mật khẩu (còn {max(remaining,0)} lần thử)"})
            return

        if parsed.path == "/logout":
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                _sessions.pop(auth[len("Bearer "):], None)
            self._send_json(200, {"message": "Đã đăng xuất"})
            return

        if not self._require_auth():
            return

        if parsed.path == "/build":
            target = data.get("target", "esp32")
            if target not in ALLOWED_TARGETS:
                self._send_json(400, {"error": f"Target không hợp lệ. Cho phép: {sorted(ALLOWED_TARGETS)}"})
                return
            try:
                ensure_esp_idf_project()
                start = time.time()
                result = run_idf(f"idf.py -B build set-target {target} && idf.py -B build build", timeout=900)
                success = result.returncode == 0
                duration = round(time.time() - start, 1)

                _build_history.insert(0, {
                    "time": time.strftime("%H:%M:%S"),
                    "target": target,
                    "success": success,
                    "duration": duration,
                })
                del _build_history[MAX_HISTORY:]

                self._send_json(200, {
                    "success": success,
                    "output": result.stdout[-4000:],
                    "error": result.stderr[-2000:] if not success else "",
                    "bin": "build/*.bin" if success else "",
                    "duration": duration,
                })
            except Exception as e:
                self._send_json(500, {"success": False, "error": str(e)})
            return

        if parsed.path == "/library/install":
            name = data.get("name", "").strip()
            if not name or not __import__("re").match(r"^[A-Za-z0-9_./\-]{1,80}$", name):
                self._send_json(400, {"error": "Tên component không hợp lệ (định dạng: namespace/component)"})
                return
            try:
                result = run_idf(f"idf.py add-dependency '{name}'", timeout=180)
                success = result.returncode == 0
                self._send_json(200, {
                    "success": success,
                    "output": (result.stdout + result.stderr)[-2000:],
                })
            except Exception as e:
                self._send_json(500, {"success": False, "error": str(e)})
            return

        if parsed.path == "/clean":
            try:
                build_dir = os.path.join(WORK_DIR, "build")
                if os.path.isdir(build_dir):
                    import shutil
                    shutil.rmtree(build_dir)
                self._send_json(200, {"success": True, "output": "Đã xóa thư mục build"})
            except Exception as e:
                self._send_json(500, {"success": False, "error": str(e)})
            return

        if parsed.path == "/diag":
            key = data.get("command", "")
            cmd = DIAG_COMMANDS.get(key)
            if cmd is None:
                self._send_json(400, {"error": f"Lệnh không hợp lệ. Cho phép: {sorted(DIAG_COMMANDS)}"})
                return
            try:
                result = run_idf(cmd, timeout=60)
                self._send_json(200, {
                    "success": result.returncode == 0,
                    "output": (result.stdout + result.stderr)[-4000:],
                })
            except Exception as e:
                self._send_json(500, {"success": False, "error": str(e)})
            return

        if parsed.path == "/save":
            name = data.get("name", "")
            content = data.get("content", "")
            try:
                filepath = safe_path(name)
            except ValueError as e:
                self._send_json(400, {"error": str(e)})
                return
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, "w") as f:
                f.write(content)
            self._send_json(200, {"message": f"Đã lưu {name}"})
            return

        if parsed.path == "/upload":
            name = data.get("name", "")
            content = data.get("content", "")
            try:
                filepath = safe_path(name)
            except ValueError as e:
                self._send_json(400, {"error": str(e)})
                return
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, "w") as f:
                f.write(content)
            self._send_json(200, {"message": f"Đã upload {name}"})
            return

        self._send_json(404, {"error": "Không tìm thấy endpoint"})

    def do_DELETE(self):
        if not self._require_auth():
            return
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/delete":
            params = urllib.parse.parse_qs(parsed.query)
            name = params.get("name", [""])[0]
            try:
                filepath = safe_path(name)
            except ValueError as e:
                self._send_json(400, {"error": str(e)})
                return
            if os.path.exists(filepath):
                os.remove(filepath)
                self._send_json(200, {"message": f"Đã xóa {name}"})
            else:
                self._send_json(404, {"error": "Không tìm thấy file"})
            return
        self._send_json(404, {"error": "Không tìm thấy endpoint"})


if __name__ == "__main__":
    ensure_esp_idf_project()
    if not WEB_PASSWORD:
        print("⚠️  CẢNH BÁO: Biến môi trường WEB_PASSWORD chưa được đặt")
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    PORT = int(os.environ.get("PORT", 9999))  # 👈 PORT 9999
    server = http.server.HTTPServer(("0.0.0.0", PORT), APIHandler)
    print(f"✅ Web IDE server đang chạy tại port {PORT}")
    server.serve_forever()
