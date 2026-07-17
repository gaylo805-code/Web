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

WORK_DIR = os.environ.get("WORK_DIR", os.getcwd())  # Sửa: dùng getcwd() thay vì hardcode
WEB_PASSWORD = os.environ.get("WEB_PASSWORD", "")
SESSION_TTL = 6 * 3600  # 6 tiếng

# Danh sách target hợp lệ cho build (tránh nhận chuỗi tùy ý)
ALLOWED_TARGETS = {"esp32", "esp32s2", "esp32s3", "esp32c3"}

# token -> hết hạn (epoch)
_sessions = {}


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


def ensure_esp_project():
    """Tạo cấu trúc project ESP-IDF nếu chưa có (fix lỗi CMakeLists.txt)"""
    base = Path(WORK_DIR).resolve()
    print(f"📁 Đảm bảo project ESP-IDF trong: {base}")

    # Tạo CMakeLists.txt gốc
    cmake_file = base / "CMakeLists.txt"
    if not cmake_file.exists():
        cmake_file.write_text("""cmake_minimum_required(VERSION 3.5)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(dns_sniffer)
""")
        print("✅ Đã tạo CMakeLists.txt")

    # Tạo thư mục main
    main_dir = base / "main"
    main_dir.mkdir(exist_ok=True)

    # Tạo main/CMakeLists.txt
    main_cmake = main_dir / "CMakeLists.txt"
    if not main_cmake.exists():
        main_cmake.write_text("""idf_component_register(SRCS "main.c")
""")
        print("✅ Đã tạo main/CMakeLists.txt")

    # Tạo main/main.c (mẫu)
    main_c = main_dir / "main.c"
    if not main_c.exists():
        main_c.write_text("""#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

void app_main(void) {
    printf("ESP32 DNS Sniffer Started!\\n");
    while (1) {
        printf("Running...\\n");
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
}
""")
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

        # Chuyển hướng root đến login/dashboard (dựa trên token trong header)
        if parsed.path == "/":
            self.path = "/login.html" if not self._authorized() else "/dashboard.html"
            return http.server.SimpleHTTPRequestHandler.do_GET(self)

        if parsed.path == "/files":
            if not self._require_auth():
                return
            files = []
            for f in Path(WORK_DIR).rglob("*"):
                if f.is_file() and ".git" not in str(f):
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

        # Phục vụ các file tĩnh (html, css, js) từ thư mục hiện tại
        try:
            # Chặn truy cập vào các file nhạy cảm
            if parsed.path.startswith("/.") or "/." in parsed.path:
                self.send_response(403)
                self.end_headers()
                return
            # Mở file
            with open(parsed.path[1:], "rb") as f:
                content = f.read()
                self.send_response(200)
                # Xác định content-type
                if parsed.path.endswith(".html"):
                    self.send_header("Content-Type", "text/html")
                elif parsed.path.endswith(".css"):
                    self.send_header("Content-Type", "text/css")
                elif parsed.path.endswith(".js"):
                    self.send_header("Content-Type", "application/javascript")
                elif parsed.path.endswith(".png"):
                    self.send_header("Content-Type", "image/png")
                elif parsed.path.endswith(".ico"):
                    self.send_header("Content-Type", "image/x-icon")
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
            password = data.get("password", "")
            if not WEB_PASSWORD:
                self._send_json(500, {"error": "Server chưa cấu hình WEB_PASSWORD"})
                return
            if secrets.compare_digest(password, WEB_PASSWORD):
                token = new_session()
                self._send_json(200, {"token": token, "expires_in": SESSION_TTL})
            else:
                self._send_json(401, {"error": "Sai mật khẩu"})
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
                # Đảm bảo project ESP-IDF đã có trước khi build
                ensure_esp_project()
                result = subprocess.run(
                    ["bash", "-lc", f"source ~/esp-idf/export.sh && idf.py set-target {target} && idf.py build"],
                    cwd=WORK_DIR, capture_output=True, text=True, timeout=600,
                )
                success = result.returncode == 0
                self._send_json(200, {
                    "success": success,
                    "output": result.stdout[-4000:],
                    "error": result.stderr[-2000:] if not success else "",
                    "bin": "build/dns_sniffer.bin" if success else "",
                })
            except Exception as e:
                self._send_json(500, {"success": False, "error": str(e)})
            return

        if parsed.path == "/clean":
            try:
                result = subprocess.run(
                    ["bash", "-lc", "source ~/esp-idf/export.sh && idf.py fullclean"],
                    cwd=WORK_DIR, capture_output=True, text=True, timeout=120,
                )
                self._send_json(200, {"success": result.returncode == 0, "output": result.stdout[-2000:]})
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
    # Tạo project ESP-IDF ngay khi khởi động (fix lỗi CMakeLists.txt)
    ensure_esp_project()

    if not WEB_PASSWORD:
        print("⚠️  CẢNH BÁO: Biến môi trường WEB_PASSWORD chưa được đặt — server sẽ từ chối mọi đăng nhập.")

    # Chuyển đến thư mục chứa file server.py để phục vụ file tĩnh
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    server = http.server.HTTPServer(("0.0.0.0", 3000), APIHandler)
    print("✅ Web IDE server (có xác thực) đang chạy tại port 3000")
    server.serve_forever()
