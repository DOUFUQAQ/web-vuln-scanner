"""Flask API 冒烟测试。

需要 flask + flask-sqlalchemy + requests（扫描器基类会 import requests）。
这三个包不在时整组跳过 —— 保证"只有 python"的环境也能跑出全绿。
CI 里装了依赖，所以这组会真的执行。
"""
import unittest

try:
    import flask  # noqa: F401
    import flask_sqlalchemy  # noqa: F401
    import requests  # noqa: F401
    FLASK_AVAILABLE = True
    MISSING_REASON = ''
except ImportError as exc:  # pragma: no cover - 取决于运行环境
    FLASK_AVAILABLE = False
    MISSING_REASON = f'缺少依赖: {exc}'


@unittest.skipUnless(FLASK_AVAILABLE, MISSING_REASON or '需要 flask 依赖')
class ApiSmokeTest(unittest.TestCase):

    def setUp(self):
        from app import create_app
        self.app = create_app({
            'TESTING': True,
            'SECRET_KEY': 'unit-test',
            'SQLALCHEMY_DATABASE_URI': 'sqlite://',
        })
        self.client = self.app.test_client()

    def test_health(self):
        response = self.client.get('/api/health')
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload['status'], 'ok')

    def test_create_target_accepts_http(self):
        response = self.client.post('/api/scan/targets', json={
            'url': 'http://example.com/login',
            'name': '示例站点',
        })
        self.assertEqual(response.status_code, 201)
        data = response.get_json()['data']
        self.assertEqual(data['url'], 'http://example.com/login')
        self.assertEqual(data['name'], '示例站点')

    def test_create_target_rejects_file_scheme(self):
        response = self.client.post('/api/scan/targets', json={'url': 'file:///etc/passwd'})
        self.assertEqual(response.status_code, 400)
        self.assertIn('不支持的协议', response.get_json()['message'])

    def test_create_target_rejects_empty_url(self):
        response = self.client.post('/api/scan/targets', json={})
        self.assertEqual(response.status_code, 400)
        self.assertIn('不能为空', response.get_json()['message'])

    def test_create_target_without_body_does_not_500(self):
        response = self.client.post('/api/scan/targets')
        self.assertEqual(response.status_code, 400)

    def test_targets_list_is_empty_on_fresh_db(self):
        response = self.client.get('/api/scan/targets')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['data'], [])

    def test_statistics_shape(self):
        response = self.client.get('/api/scan/statistics')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()['data']
        for key in ('total_scans', 'completed_scans', 'total_vulnerabilities',
                    'severity_distribution', 'type_distribution'):
            self.assertIn(key, data)
        self.assertEqual(data['total_scans'], 0)

    def test_start_scan_on_missing_target_returns_404(self):
        response = self.client.post('/api/scan/start', json={'target_id': 999})
        self.assertEqual(response.status_code, 404)


@unittest.skipUnless(FLASK_AVAILABLE, MISSING_REASON or '需要 flask 依赖')
class BlockPrivateTargetsTest(unittest.TestCase):
    """``SCANNER_BLOCK_PRIVATE_TARGETS=true`` 时，录入本机地址必须被 400 拒掉。"""

    def setUp(self):
        import os
        from app import create_app
        self._old = os.environ.get('SCANNER_BLOCK_PRIVATE_TARGETS')
        os.environ['SCANNER_BLOCK_PRIVATE_TARGETS'] = 'true'
        self.app = create_app({
            'TESTING': True,
            'SECRET_KEY': 'unit-test',
            'SQLALCHEMY_DATABASE_URI': 'sqlite://',
        })
        self.client = self.app.test_client()

    def tearDown(self):
        import os
        if self._old is None:
            os.environ.pop('SCANNER_BLOCK_PRIVATE_TARGETS', None)
        else:
            os.environ['SCANNER_BLOCK_PRIVATE_TARGETS'] = self._old

    def test_localhost_rejected(self):
        response = self.client.post('/api/scan/targets', json={'url': 'http://127.0.0.1:8080/user?id=1'})
        self.assertEqual(response.status_code, 400)
        self.assertIn('私网', response.get_json()['message'])

    def test_public_target_still_allowed(self):
        response = self.client.post('/api/scan/targets', json={'url': 'https://example.com/'})
        self.assertEqual(response.status_code, 201)


if __name__ == '__main__':
    unittest.main()
