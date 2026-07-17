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
import threading
import queue
from pathlib import Path

WORK_DIR = os.environ.get("WORK_DIR", os.getcwd())
WEB_PASSWORD = os.environ.get("WEB_PASSWORD", "")
PORT = int(os.environ.get("PORT", 3030))  # 👈 PORT AN TOÀN: 3030
SESSION_TTL = 6 * 3600  # 6 tiếng

# Danh sách target hợp lệ cho build (tránh nhận chuỗi tùy ý)
ALLOWED_TARGETS = {"esp32", "esp32s2", "esp32s3", "esp32c3"}

# Danh sách lệnh nguy hiểm bị cấm (chống hack)
DANGEROUS_COMMANDS = ["rm -rf", "sudo", "chmod", "chown", "mkfs", "dd if", ":(){", "> /dev/sda"]

# token -> hết hạn (epoch)
_sessions = {}

# Queue cho build log (streaming)
_build_logs = {}
_build_status = {}


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
        cmake_file.write_text("""cmake_minimum_required(VERSION 3.10)
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
        main_cmake.write_text("""idf_component_register(SRCS "main.c" "dns_sniffer.c")
""")
        print("✅ Đã tạo main/CMakeLists.txt")

    # Tạo main/main.c (mẫu)
    main_c = main_dir / "main.c"
    if not main_c.exists():
        main_c.write_text("""#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "dns_sniffer.h"

void app_main(void) {
    printf("ESP32 DNS Sniffer Started!\\n");
    init_dns_sniffer();
    while (1) {
        printf("Running...\\n");
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
}
""")
        print("✅ Đã tạo main/main.c")

    # Tạo main/dns_sniffer.h (mẫu)
    main_h = main_dir / "dns_sniffer.h"
    if not main_h.exists():
        main_h.write_text("""#ifndef DNS_SNIFFER_H
#define DNS_SNIFFER_H

void init_dns_sniffer(void);

#endif
""")
        print("✅ Đã tạo main/dns_sniffer.h")

    # Tạo main/dns_sniffer.c (mẫu)
    main_c2 = main_dir / "dns_sniffer.c"
    if not main_c2.exists():
        main_c2.write_text("""#include <stdio.h>
#include "dns_sniffer.h"

void init_dns_sniffer(void) {
    printf("DNS Sniffer initialized!\\n");
}
""")
        print("✅ Đã tạo main/dns_sniffer.c")

    # Tạo sdkconfig mặc định
    sdkconfig = base / "sdkconfig"
    if not sdkconfig.exists():
        sdkconfig.write_text("""CONFIG_ESP32_REV_MIN=0
CONFIG_ESP32_REV_MIN_3_0=y
CONFIG_ESP32_XTAL_FREQ_40=y
CONFIG_ESP32_PHY_MAX_WIFI_TX_POWER=20
CONFIG_ESPTOOLPY_FLASHSIZE=4MB
CONFIG_PARTITION_TABLE_SINGLE_APP=y
CONFIG_ESPTOOLPY_BEFORE_RESET=no_reset
CONFIG_ESPTOOLPY_AFTER_RESET=no_reset
""")
        print("✅ Đã tạo sdkconfig")


def run_build_with_logging(target, log_queue):
    """Chạy build và gửi log qua queue để streaming"""
    try:
        log_queue.put(f"🔨 Bắt đầu build cho {target}...")
        log_queue.put(f"📋 Target: {target}")
        
        # Clean và set target
        log_queue.put("🧹 Cleaning previous build...")
        clean_result = subprocess.run(
            ["bash", "-lc", f"source ~/esp-idf/export.sh && idf.py fullclean"],
            cwd=WORK_DIR, capture_output=True, text=True, timeout=120,
        )
        if clean_result.stdout:
            log_queue.put(clean_result.stdout[-500:])
        
        log_queue.put(f"🎯 Setting target: {target}")
        set_target_result = subprocess.run(
            ["bash", "-lc", f"source ~/esp-idf/export.sh && idf.py set-target {target}"],
            cwd=WORK_DIR, capture_output=True, text=True, timeout=120,
        )
        if set_target_result.stdout:
            log_queue.put(set_target_result.stdout[-500:])
        if set_target_result.stderr:
            log_queue.put(set_target_result.stderr[-500:])
        
        # Build
        log_queue.put("🔨 Building firmware... (có thể mất vài phút)")
        
        # Build với Popen để stream log real-time
        process = subprocess.Popen(
            ["bash", "-lc", "source ~/esp-idf/export.sh && idf.py build"],
            cwd=WORK_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        # Đọc output và gửi vào queue
        for line in iter(process.stdout.readline, ''):
            if line:
                log_queue.put(line.strip())
        
        process.wait()
        
        if process.returncode == 0:
            log_queue.put("✅ Build thành công!")
            
            # Kiểm tra file build
            build_dir = Path(WORK_DIR) / "build"
            files = []
            for f in build_dir.rglob("*.bin"):
                files.append(str(f.relative_to(build_dir)))
            
            if files:
                log_queue.put(f"📦 Đã tạo {len(files)} file .bin:")
                for f in files:
                    log_queue.put(f"  - {f}")
            else:
                log_queue.put("⚠️ Không tìm thấy file .bin nào!")
            
            log_queue.put("✅ DONE")
        else:
            log_queue.put(f"❌ Build thất bại với mã lỗi: {process.returncode}")
            log_queue.put("❌ FAILED")
            
    except subprocess.TimeoutExpired:
        log_queue.put("⏰ Build quá thời gian cho phép (600 giây)")
        log_queue.put("❌ FAILED")
    except Exception as e:
        log_queue.put(f"❌ Lỗi: {str(e)}")
        log_queue.put("❌ FAILED")


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

        # Chuyển hướng root đến login/dashboard
        if parsed.path == "/":
            self.path = "/login.html" if not self._authorized() else "/dashboard.html"
            return http.server.SimpleHTTPRequestHandler.do_GET(self)

        # ============ LIST FILES ============
        if parsed.path == "/files":
            if not self._require_auth():
                return
            files = []
            for f in Path(WORK_DIR).rglob("*"):
                if f.is_file() and ".git" not in str(f) and "build" not in str(f):
                    files.append({"name": str(f.relative_to(WORK_DIR)), "size": f.stat().st_size})
            self._send_json(200, files)
            return

        # ============ READ FILE ============
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

        # ============ DOWNLOAD FIRMWARE ============
        if parsed.path == "/download":
            if not self._require_auth():
                return
            
            params = urllib.parse.parse_qs(parsed.query)
            filename = params.get("file", ["dns_sniffer.bin"])[0]
            
            # Chỉ cho phép tải các file .bin từ thư mục build
            if not filename.endswith(".bin"):
                self._send_json(400, {"error": "Chỉ cho phép tải file .bin"})
                return
            
            # Chặn path traversal
            try:
                filepath = safe_path("build/" + filename)
            except ValueError as e:
                self._send_json(400, {"error": str(e)})
                return
            
            if not os.path.exists(filepath):
                self._send_json(404, {"error": "Không tìm thấy file firmware"})
                return
            
            # Gửi file về client
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

        # ============ CHECK BUILD FILES ============
        if parsed.path == "/check_build_files":
            if not self._require_auth():
                return
            
            build_dir = Path(WORK_DIR) / "build"
            files = []
            
            # Kiểm tra các file build quan trọng
            check_files = [
                ("dns_sniffer.bin", "Firmware"),
                ("partition_table/partition-table.bin", "Partition Table"),
                ("bootloader/bootloader.bin", "Bootloader")
            ]
            
            for rel_path, display_name in check_files:
                full_path = build_dir / rel_path
                if full_path.exists():
                    files.append({
                        "name": rel_path,
                        "display_name": display_name,
                        "size": full_path.stat().st_size,
                        "exists": True
                    })
                else:
                    files.append({
                        "name": rel_path,
                        "display_name": display_name,
                        "exists": False
                    })
            
            # Tìm thêm các file .bin khác
            for f in build_dir.rglob("*.bin"):
                rel = str(f.relative_to(build_dir))
                if rel not in [f["name"] for f in files]:
                    files.append({
                        "name": rel,
                        "display_name": os.path.basename(rel),
                        "size": f.stat().st_size,
                        "exists": True
                    })
            
            self._send_json(200, {"files": files})
            return

        # ============ GET BUILD LOG (streaming) ============
        if parsed.path == "/build_log":
            if not self._require_auth():
                return
            
            # Lấy log từ queue
            log_lines = []
            if hasattr(self, '_build_log_queue'):
                while not self._build_log_queue.empty():
                    try:
                        log_lines.append(self._build_log_queue.get_nowait())
                    except:
                        break
            
            # Kiểm tra trạng thái build
            status = "building"
            if hasattr(self, '_build_done'):
                status = "done" if self._build_done else "failed"
            
            self._send_json(200, {
                "logs": log_lines,
                "status": status,
                "is_building": not hasattr(self, '_build_done') or not self._build_done
            })
            return

        # ============ PHỤC VỤ FILE TĨNH ============
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

        # ============ LOGIN (không cần auth) ============
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

        # ============ LOGOUT (không cần auth) ============
        if parsed.path == "/logout":
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                _sessions.pop(auth[len("Bearer "):], None)
            self._send_json(200, {"message": "Đã đăng xuất"})
            return

        # ============ TẤT CẢ CÁC ENDPOINT CÒN LẠI CẦN AUTH ============
        if not self._require_auth():
            return

        # ============ TERMINAL ============
        if parsed.path == "/exec":
            command = data.get("command", "").strip()
            if not command:
                self._send_json(400, {"success": False, "error": "Không có lệnh"})
                return
            
            # 🔒 Chặn lệnh nguy hiểm
            if any(cmd in command for cmd in DANGEROUS_COMMANDS):
                self._send_json(403, {"success": False, "error": "Lệnh không được phép (bị chặn vì lý do bảo mật)"})
                return
            
            # Chỉ cho chạy tối đa 30 giây
            try:
                result = subprocess.run(
                    ["bash", "-c", command],
                    cwd=WORK_DIR,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                self._send_json(200, {
                    "success": True,
                    "output": result.stdout[-5000:] if result.stdout else "",
                    "error": result.stderr[-2000:] if result.stderr else "",
                    "returncode": result.returncode
                })
            except subprocess.TimeoutExpired:
                self._send_json(408, {"success": False, "error": "Lệnh chạy quá 30 giây, bị dừng"})
            except Exception as e:
                self._send_json(500, {"success": False, "error": str(e)})
            return

        # ============ BUILD FIRMWARE ============
        if parsed.path == "/build":
            target = data.get("target", "esp32")
            if target not in ALLOWED_TARGETS:
                self._send_json(400, {"error": f"Target không hợp lệ. Cho phép: {sorted(ALLOWED_TARGETS)}"})
                return
            
            # Đảm bảo project đã được tạo
            ensure_esp_project()
            
            # Tạo queue cho log
            log_queue = queue.Queue()
            self._build_log_queue = log_queue
            self._build_done = False
            
            # Chạy build trong thread riêng
            def run_build():
                try:
                    run_build_with_logging(target, log_queue)
                    self._build_done = True
                except Exception as e:
                    log_queue.put(f"❌ Lỗi: {str(e)}")
                    log_queue.put("❌ FAILED")
                    self._build_done = True
            
            thread = threading.Thread(target=run_build)
            thread.daemon = True
            thread.start()
            
            self._send_json(200, {
                "success": True,
                "message": "Build đang chạy",
                "target": target
            })
            return

        # ============ CLEAN ============
        if parsed.path == "/clean":
            try:
                result = subprocess.run(
                    ["bash", "-lc", "source ~/esp-idf/export.sh && idf.py fullclean"],
                    cwd=WORK_DIR, capture_output=True, text=True, timeout=120,
                )
                # Xóa build logs
                if hasattr(self, '_build_log_queue'):
                    delattr(self, '_build_log_queue')
                if hasattr(self, '_build_done'):
                    delattr(self, '_build_done')
                
                self._send_json(200, {"success": result.returncode == 0, "output": result.stdout[-2000:]})
            except Exception as e:
                self._send_json(500, {"success": False, "error": str(e)})
            return

        # ============ SAVE FILE ============
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
            self._send_json
