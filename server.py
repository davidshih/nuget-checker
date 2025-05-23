import http.server
import socketserver
import json
import urllib.parse
from vulnerability_checker import VulnerabilityChecker

class VulnerabilityHandler(http.server.BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.checker = VulnerabilityChecker()
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """處理 GET 請求 - 提供 HTML 頁面"""
        if self.path == '/' or self.path == '/index.html':
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            
            with open('index.html', 'r', encoding='utf-8') as f:
                html_content = f.read()
            self.wfile.write(html_content.encode('utf-8'))
            
        elif self.path == '/style.css':
            self.send_response(200)
            self.send_header('Content-type', 'text/css')
            self.end_headers()
            
            with open('style.css', 'r', encoding='utf-8') as f:
                css_content = f.read()
            self.wfile.write(css_content.encode('utf-8'))
            
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'404 Not Found')
    
    def do_POST(self):
        """處理 POST 請求 - 檢查漏洞"""
        if self.path == '/check':
            try:
                # 讀取請求內容
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                
                # 解析 JSON 資料
                data = json.loads(post_data.decode('utf-8'))
                packages_input = data.get('packages', '')
                
                # 分割套件清單
                packages = [pkg.strip() for pkg in packages_input.split(',') if pkg.strip()]
                
                if not packages:
                    self.send_json_response({'error': '請輸入至少一個套件名稱'}, 400)
                    return
                
                # 檢查漏洞
                print(f"開始檢查 {len(packages)} 個套件...")
                vulnerabilities = self.checker.check_vulnerabilities(packages)
                
                # 回傳結果
                response_data = {
                    'success': True,
                    'total_packages': len(packages),
                    'total_vulnerabilities': len(vulnerabilities),
                    'vulnerabilities': vulnerabilities
                }
                
                self.send_json_response(response_data)
                
            except json.JSONDecodeError:
                self.send_json_response({'error': '無效的 JSON 格式'}, 400)
            except Exception as e:
                print(f"伺服器錯誤: {e}")
                self.send_json_response({'error': f'伺服器錯誤: {str(e)}'}, 500)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'404 Not Found')
    
    def send_json_response(self, data, status_code=200):
        """發送 JSON 回應"""
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        
        json_data = json.dumps(data, ensure_ascii=False, indent=2)
        self.wfile.write(json_data.encode('utf-8'))
    
    def do_OPTIONS(self):
        """處理 CORS 預檢請求"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def log_message(self, format, *args):
        """自定義日誌格式"""
        print(f"[{self.date_time_string()}] {format % args}")

def run_server(port=8000):
    """啟動伺服器"""
    handler = VulnerabilityHandler
    
    with socketserver.TCPServer(("", port), handler) as httpd:
        print(f"NuGet 漏洞檢查器伺服器啟動")
        print(f"請在瀏覽器中開啟: http://localhost:{port}")
        print("按 Ctrl+C 停止伺服器")
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n伺服器已停止")
            httpd.shutdown()

if __name__ == "__main__":
    run_server()
