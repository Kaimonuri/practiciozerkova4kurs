import json
import sys
import uuid
from contextlib import contextmanager
import unittest
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server

@contextmanager
def test_folder():
    folder = server.ROOT / ('test-data-' + uuid.uuid4().hex)
    folder.mkdir()
    try:
        yield folder
    finally:
        for file in folder.iterdir():
            file.unlink()
        folder.rmdir()

class HTTPTests(unittest.TestCase):
    def fetch(self, port, path, origin=None, method='GET', extra=None):
        headers = dict(extra or {})
        if origin is not None:
            headers['Origin'] = origin
        req = Request(f'http://localhost:{port}{path}', headers=headers, method=method)
        try:
            response = urlopen(req, timeout=3)
        except HTTPError as exc:
            response = exc
        with response:
            return response.status, dict(response.headers), response.read()

    def test_before_and_after(self):
        original_db = server.DB
        with test_folder() as folder:
            server.DB = Path(folder) / 'test.sqlite3'
            try:
                for enabled in (False, True):
                    servers = server.start(enabled)
                    try:
                        for app in (1, 2, 3):
                            self.assertEqual(self.fetch(8080+app, '/')[0], 200)
                        for app in (1, 2):
                            path = f'/api/primer{app}'
                            origin = f'http://localhost:{8080+app}'
                            status, headers, body = self.fetch(8083, path, origin)
                            self.assertEqual(status, 200)
                            self.assertEqual(json.loads(body)['table'], f'primer{app}')
                            self.assertEqual(len(json.loads(body)['rows']), 3)
                            self.assertEqual(headers.get('Access-Control-Allow-Origin'), origin if enabled else None)
                            self.assertNotIn('Access-Control-Allow-Credentials', headers)
                            for denied in ('null', 'https://example.com', 'http://localhost:8081.evil.test', f'http://localhost:{8083-app}', 'http://127.0.0.1:8081'):
                                status, headers, _ = self.fetch(8083, path, denied)
                                self.assertEqual(status, 403 if enabled else 200)
                                self.assertNotIn('Access-Control-Allow-Origin', headers)
                            status, headers, _ = self.fetch(8083, path, origin, 'OPTIONS', {'Access-Control-Request-Method':'GET','Access-Control-Request-Headers':'X-Lab-Demo'})
                            self.assertEqual(status, 204)
                            self.assertEqual(headers.get('Access-Control-Allow-Methods'), 'GET' if enabled else None)
                            for extra in ({'Access-Control-Request-Method':'DELETE'}, {'Access-Control-Request-Method':'GET','Access-Control-Request-Headers':'Authorization'}):
                                self.assertEqual(self.fetch(8083,path,origin,'OPTIONS',extra)[0],403 if enabled else 204)
                        status, headers, _ = self.fetch(8081, '/api/info', 'http://localhost:8082')
                        self.assertEqual(status, 200)
                        self.assertEqual(headers.get('Access-Control-Allow-Origin'), 'http://localhost:8082' if enabled else None)
                        self.assertEqual(self.fetch(8083, '/api/primer1')[0], 200)
                        self.assertEqual(self.fetch(8083, '/api/missing')[0], 404)
                        self.assertEqual(self.fetch(8083, '/api/primer1', method='POST')[0], 405)
                        self.assertEqual(self.fetch(8083, '/server.py')[0], 404)
                        self.assertNotIn('Access-Control-Allow-Origin', self.fetch(8082, '/', 'http://localhost:8081')[1])
                    finally:
                        for item in servers:
                            item.shutdown()
                            item.server_close()
            finally:
                server.DB = original_db

if __name__ == '__main__':
    unittest.main()
