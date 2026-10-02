"""Three local teaching apps. Python 3.10+, standard library only."""
import argparse
import json
import sqlite3
import threading
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
DB = ROOT / 'data' / 'practice.sqlite3'
# Exact, per-resource browser permissions. App 2 has no CORS middleware.
POLICY = {1: {'/api/info': 'http://localhost:8082'}, 2: {},
          3: {'/api/primer1': 'http://localhost:8081',
              '/api/primer2': 'http://localhost:8082'}}
QUERIES = {'/api/primer1': 'SELECT id, name, description FROM primer1 ORDER BY id',
           '/api/primer2': 'SELECT id, name, description FROM primer2 ORDER BY id'}

def init_db():
    DB.parent.mkdir(exist_ok=True)
    with closing(sqlite3.connect(DB)) as con:
        with con:
            con.executescript((ROOT / 'schema.sql').read_text(encoding='utf-8'))

def handler(app, enabled):
    class Handler(BaseHTTPRequestHandler):
        def reply(self, status, body=b'', mime='application/json; charset=utf-8', cors=False, preflight=False):
            if not isinstance(body, bytes):
                body = json.dumps(body, ensure_ascii=False).encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', mime)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self' http://localhost:8081 http://localhost:8083; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
            if app in (1, 3):
                self.send_header('Vary', 'Origin, Access-Control-Request-Method, Access-Control-Request-Headers')
            if cors:
                self.send_header('Access-Control-Allow-Origin', POLICY[app][urlsplit(self.path).path])
                if preflight:
                    self.send_header('Access-Control-Allow-Methods', 'GET')
                    self.send_header('Access-Control-Allow-Headers', 'X-Lab-Demo')
                    self.send_header('Access-Control-Max-Age', '0')
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = urlsplit(self.path).path
            if path == '/api/status':
                return self.reply(200, {'app': app, 'cors': enabled and app in (1, 3)})
            static = {'/': ('index.html', 'text/html'), '/app.js': ('app.js', 'text/javascript'), '/style.css': ('style.css', 'text/css')}
            if path in static:
                file, mime = static[path]
                return self.reply(200, (ROOT / 'web' / file).read_bytes(), mime + '; charset=utf-8')
            if path not in POLICY[app]:
                return self.reply(404, {'error': 'Route not found'})
            origin = self.headers.get('Origin')
            allowed = enabled and origin == POLICY[app][path]
            # Without Origin: ordinary direct navigation / non-browser client.
            # Origin is NOT an authentication credential.
            if enabled and origin is not None and not allowed:
                return self.reply(403, {'error': 'Origin is not allowed for this resource'})
            if app == 1:
                return self.reply(200, {'app': 1, 'message': 'Ответ приложения 1 приложению 2'}, cors=allowed)
            with closing(sqlite3.connect(DB)) as con:
                con.row_factory = sqlite3.Row
                rows = [dict(row) for row in con.execute(QUERIES[path])]
            self.reply(200, {'table': path.rsplit('/', 1)[1], 'rows': rows}, cors=allowed)

        def do_OPTIONS(self):
            path = urlsplit(self.path).path
            if path not in POLICY[app]:
                return self.reply(404, {'error': 'Route not found'})
            if not enabled:
                return self.reply(204)
            requested = {h.strip().lower() for h in self.headers.get('Access-Control-Request-Headers', '').split(',') if h.strip()}
            if (self.headers.get('Origin') != POLICY[app][path]
                    or self.headers.get('Access-Control-Request-Method') != 'GET'
                    or not requested.issubset({'x-lab-demo'})):
                return self.reply(403, {'error': 'Preflight denied'})
            self.reply(204, cors=True, preflight=True)

        def do_POST(self):
            self.reply(405, {'error': 'Only GET is supported'})
        do_PUT = do_DELETE = do_PATCH = do_POST
    return Handler

def start(enabled):
    init_db()
    servers = []
    try:
        # Bind all ports before starting: no partially running lab on failure.
        for app in (1, 2, 3):
            servers.append(ThreadingHTTPServer(('127.0.0.1', 8080 + app), handler(app, enabled)))
    except OSError:
        for server in servers:
            server.server_close()
        raise
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    return servers

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cors', choices=['off', 'on'], default='off')
    args = parser.parse_args()
    try:
        servers = start(args.cors == 'on')
    except OSError as exc:
        print(f'Cannot start: {exc}. Check ports 8081, 8082, 8083.')
        return 1
    print(f'CORS: {args.cors}. Open http://localhost:8081 and http://localhost:8082')
    print('App 3: http://localhost:8083. Press Ctrl+C to stop all apps.', flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
