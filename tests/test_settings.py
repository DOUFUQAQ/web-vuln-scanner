"""配置层的单元测试：默认值、环境变量覆盖、类型解析容错。

配置读错是"能起服务但行为诡异"的典型来源，所以这里把优先级
（显式入参 > 环境变量 > 默认值）和非法值回退都钉死。
"""
import unittest

from settings import (
    DEFAULT_DATABASE_URL,
    DEFAULT_SECRET_KEY,
    env_bool,
    env_int,
    env_list,
    env_str,
    load_settings,
)


class EnvPrimitivesTest(unittest.TestCase):

    def test_env_str(self):
        self.assertEqual(env_str({}, 'X', 'fallback'), 'fallback')
        self.assertEqual(env_str({'X': ''}, 'X', 'fallback'), 'fallback')
        self.assertEqual(env_str({'X': 'value'}, 'X', 'fallback'), 'value')

    def test_env_bool_truthy(self):
        for raw in ('1', 'true', 'TRUE', 'yes', 'on'):
            with self.subTest(raw=raw):
                self.assertTrue(env_bool({'X': raw}, 'X', False))

    def test_env_bool_falsy(self):
        for raw in ('0', 'false', 'no', 'off', ''):
            with self.subTest(raw=raw):
                self.assertFalse(env_bool({'X': raw}, 'X', True))

    def test_env_bool_invalid_falls_back(self):
        self.assertTrue(env_bool({'X': 'maybe'}, 'X', True))
        self.assertFalse(env_bool({'X': 'maybe'}, 'X', False))

    def test_env_int(self):
        self.assertEqual(env_int({}, 'X', 7), 7)
        self.assertEqual(env_int({'X': '8080'}, 'X', 7), 8080)
        self.assertEqual(env_int({'X': ' 8080 '}, 'X', 7), 8080)

    def test_env_int_invalid_falls_back(self):
        self.assertEqual(env_int({'X': 'abc'}, 'X', 7), 7)
        self.assertEqual(env_int({'X': ''}, 'X', 7), 7)

    def test_env_int_respects_minimum(self):
        self.assertEqual(env_int({'X': '0'}, 'X', 7, minimum=1), 7)
        self.assertEqual(env_int({'X': '1'}, 'X', 7, minimum=1), 1)

    def test_env_list(self):
        self.assertEqual(env_list({}, 'X'), ())
        self.assertEqual(env_list({'X': ''}, 'X'), ())
        self.assertEqual(env_list({'X': ' a , , b '}, 'X'), ('a', 'b'))


class LoadSettingsTest(unittest.TestCase):

    def test_defaults_are_local_and_quiet(self):
        settings = load_settings({})
        self.assertEqual(settings['host'], '127.0.0.1')
        self.assertEqual(settings['port'], 5000)
        self.assertFalse(settings['debug'])
        self.assertFalse(settings['tls_verify'])
        self.assertFalse(settings['block_private_targets'])
        self.assertEqual(settings['allowed_target_hosts'], ())
        self.assertEqual(settings['cors_origins'], '*')
        self.assertEqual(settings['http_timeout'], 10)
        self.assertEqual(settings['secret_key'], DEFAULT_SECRET_KEY)
        self.assertEqual(settings['database_url'], DEFAULT_DATABASE_URL)

    def test_env_overrides(self):
        settings = load_settings({
            'SCANNER_SECRET_KEY': 'from-env',
            'DATABASE_URL': 'postgresql://u:p@db:5432/scans',
            'SCANNER_CORS_ORIGINS': 'https://ui.example.com',
            'SCANNER_HOST': '0.0.0.0',
            'SCANNER_PORT': '8080',
            'SCANNER_DEBUG': 'true',
            'SCANNER_HTTP_TIMEOUT': '3',
            'SCANNER_TLS_VERIFY': '1',
            'SCANNER_BLOCK_PRIVATE_TARGETS': 'yes',
            'SCANNER_ALLOWED_TARGET_HOSTS': '*.example.com, lab.local',
        })
        self.assertEqual(settings['secret_key'], 'from-env')
        self.assertEqual(settings['database_url'], 'postgresql://u:p@db:5432/scans')
        self.assertEqual(settings['cors_origins'], 'https://ui.example.com')
        self.assertEqual(settings['host'], '0.0.0.0')
        self.assertEqual(settings['port'], 8080)
        self.assertTrue(settings['debug'])
        self.assertEqual(settings['http_timeout'], 3)
        self.assertTrue(settings['tls_verify'])
        self.assertTrue(settings['block_private_targets'])
        self.assertEqual(settings['allowed_target_hosts'], ('*.example.com', 'lab.local'))


if __name__ == '__main__':
    unittest.main()
