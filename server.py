#!/usr/bin/env python3
import http.server
import json
import os
import subprocess
import urllib.parse
from pathlib import Path

WORK_DIR = "/home/runner/work/Buld-code-esp-32/Buld-code-esp-32"

class APIHandler(http.server.SimpleHTTPRequestHandler):
    
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        
        if parsed.path == '/files':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            files = []
            for f in Path(WORK_DIR).rglob('*'):
                if f.is_file() and '.git' not in str(f):
                    files.append({
                        'name': str(f.relative_to(WORK_DIR)),
                        'size': f.stat().st_size
                    })
            self.wfile.write(json.dumps(files).encode())
            return
            
        elif parsed.path == '/file':
            params = urllib.parse.parse_qs(parsed.query)
            name = params.get('name', [''])[0]
            filepath = os.path.join(WORK_DIR, name)
            if os.path.exists(filepath):
                with open(filepath) as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'content': content}).encode())
            else:
                self.send_error(404)
            return
            
        elif parsed.path == '/monitor':
            # Serial monitor qua EventSource
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()
            self.wfile.write(b'data: Serial monitor started\n\n')
            return
        
        # Serve static files
        if self.path == '/':
            self.path = '/dashboard.html'
        return http.server.SimpleHTTPRequestHandler.do_GET(self)
    
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)
        data = json.loads(body)
        
        parsed = urllib.parse.urlparse(self.path)
        
        if parsed.path == '/build':
            target = data.get('target', 'esp32')
            try:
                os.chdir(WORK_DIR)
                result = subprocess.run(
                    f'source ~/esp/esp-idf/export.sh && idf.py set-target {target} && idf.py build',
                    shell=True, capture_output=True, text=True, timeout=300,
                    executable='/bin/bash'
                )
                success = result.returncode == 0
                response = {
                    'success': success,
                    'output': result.stdout[-2000:],
                    'error': result.stderr[-1000:] if not success else '',
                    'bin': 'build/dns_sniffer.bin' if success else ''
                }
            except Exception as e:
                response = {'success': False, 'error': str(e)}
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
            return
        
        elif parsed.path == '/save':
            name = data.get('name', '')
            content = data.get('content', '')
            filepath = os.path.join(WORK_DIR, name)
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, 'w') as f:
                f.write(content)
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'message': f'Đã lưu {name}'}).encode())
            return
        
        elif parsed.path == '/exec':
            cmd = data.get('command', '')
            try:
                result = subprocess.run(
                    f'source ~/esp/esp-idf/export.sh && {cmd}',
                    shell=True, capture_output=True, text=True, timeout=60,
                    executable='/bin/bash', cwd=WORK_DIR
                )
                response = {
                    'success': result.returncode == 0,
                    'output': result.stdout[-2000:] or result.stderr[-2000:]
                }
            except Exception as e:
                response = {'success': False, 'error': str(e)}
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
            return
        
        elif parsed.path == '/upload':
            name = data.get('name', '')
            content = data.get('content', '')
            filepath = os.path.join(WORK_DIR, name)
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, 'w') as f:
                f.write(content)
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'message': f'Uploaded {name}'}).encode())
            return
    
    def do_DELETE(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == '/delete':
            params = urllib.parse.parse_qs(parsed.query)
            name = params.get('name', [''])[0]
            filepath = os.path.join(WORK_DIR, name)
            if os.path.exists(filepath):
                os.remove(filepath)
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'message': f'Đã xóa {name}'}).encode())

if __name__ == '__main__':
    os.chdir(os.path.expanduser('~'))
    server = http.server.HTTPServer(('0.0.0.0', 3000), APIHandler)
    print('Dashboard server running on port 3000')
    server.serve_forever()
