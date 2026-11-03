"""目标 URL 策略的单元测试：协议白名单、私网拦截、主机白名单、状态码判定。

这一组测试对应的是"能不能把任意 URL 丢给扫描器"这个安全边界——
即所谓 SSRF 风险的**第一道**闸门，注意它只有一道。
"""
import unittest

from scanner.target_policy import (
    TargetPolicyError,
    classify_target_status,
    host_is_private,
    parse_allowed_hosts,
    validate_target_url,
)


class ParseAllowedHostsTest(unittest.TestCase):

    def test_empty_means_no_restriction(self):
        self.assertEqual(parse_allowed_hosts(''), ())
        self.assertEqual(parse_allowed_hosts(None), ())

    def test_comma_and_semicolon_both_work(self):
        self.assertEqual(
            parse_allowed_hosts(' A.com, B.com ;c.com , '),
            ('a.com', 'b.com', 'c.com'),
        )


class HostIsPrivateTest(unittest.TestCase):

    def test_loopback_and_private_ranges(self):
        for host in ('127.0.0.1', '10.0.0.5', '192.168.1.1', '172.16.0.1', '::1', '[::1]'):
            with self.subTest(host=host):
                self.assertTrue(host_is_private(host))

    def test_link_local_and_metadata(self):
        self.assertTrue(host_is_private('169.254.169.254'))
        self.assertTrue(host_is_private('100.100.100.200'))

    def test_localhost_names(self):
        for host in ('localhost', 'app.localhost', 'printer.local', 'metadata'):
            with self.subTest(host=host):
                self.assertTrue(host_is_private(host))

    def test_public_hosts(self):
        for host in ('example.com', '8.8.8.8', '93.184.216.34'):
            with self.subTest(host=host):
                self.assertFalse(host_is_private(host))

    def test_empty_host_is_treated_as_private(self):
        self.assertTrue(host_is_private(''))


class ValidateTargetUrlTest(unittest.TestCase):

    def test_accepts_http_and_https(self):
        self.assertEqual(
            validate_target_url('http://example.com/a?b=1'),
            'http://example.com/a?b=1',
        )
        self.assertEqual(validate_target_url('https://example.com'), 'https://example.com')

    def test_strips_surrounding_whitespace(self):
        self.assertEqual(
            validate_target_url('   http://example.com  '),
            'http://example.com',
        )

    def test_rejects_empty(self):
        for value in ('', '   ', None):
            with self.subTest(value=value):
                with self.assertRaises(TargetPolicyError) as ctx:
                    validate_target_url(value)
                self.assertIn('不能为空', str(ctx.exception))

    def test_rejects_dangerous_schemes(self):
        for url in ('file:///etc/passwd', 'ftp://example.com/x',
                    'gopher://example.com/', 'javascript:alert(1)'):
            with self.subTest(url=url):
                with self.assertRaises(TargetPolicyError) as ctx:
                    validate_target_url(url)
                self.assertIn('不支持的协议', str(ctx.exception))

    def test_rejects_missing_scheme(self):
        with self.assertRaises(TargetPolicyError) as ctx:
            validate_target_url('example.com/path')
        self.assertIn('缺少协议', str(ctx.exception))

    def test_rejects_missing_host(self):
        with self.assertRaises(TargetPolicyError) as ctx:
            validate_target_url('http://')
        self.assertIn('缺少主机名', str(ctx.exception))

    def test_private_allowed_by_default(self):
        # 默认放行本机，否则本地靶场（localhost:8080）根本扫不了
        self.assertEqual(
            validate_target_url('http://127.0.0.1:8080/user?id=1'),
            'http://127.0.0.1:8080/user?id=1',
        )

    def test_private_blocked_when_flag_off(self):
        with self.assertRaises(TargetPolicyError) as ctx:
            validate_target_url('http://127.0.0.1:8080/user?id=1', allow_private=False)
        self.assertIn('私网', str(ctx.exception))

    def test_metadata_address_is_blocked_even_when_allowlist_matches(self):
        with self.assertRaises(TargetPolicyError) as ctx:
            validate_target_url(
                'http://169.254.169.254/latest/meta-data/',
                allow_private=False,
            )
        self.assertIn('元数据', str(ctx.exception))

    def test_public_target_passes_with_private_blocked(self):
        self.assertEqual(
            validate_target_url('https://example.com/', allow_private=False),
            'https://example.com/',
        )


class AllowedHostsTest(unittest.TestCase):

    def test_exact_match_only(self):
        allowed = parse_allowed_hosts('example.com')
        self.assertTrue(validate_target_url('https://example.com/x', allowed_hosts=allowed))
        with self.assertRaises(TargetPolicyError) as ctx:
            validate_target_url('https://sub.example.com/x', allowed_hosts=allowed)
        self.assertIn('白名单', str(ctx.exception))

    def test_wildcard_matches_subdomains_and_apex(self):
        allowed = parse_allowed_hosts('*.example.com')
        for url in ('https://a.example.com/', 'https://deep.b.example.com/', 'https://example.com/'):
            with self.subTest(url=url):
                self.assertEqual(validate_target_url(url, allowed_hosts=allowed), url)

    def test_unlisted_host_rejected(self):
        allowed = parse_allowed_hosts('*.example.com')
        with self.assertRaises(TargetPolicyError):
            validate_target_url('https://evil.test/', allowed_hosts=allowed)


class ClassifyTargetStatusTest(unittest.TestCase):
    """可达性判定的三档结论，阈值与原始实现一致。"""

    def test_ok(self):
        verdict, message = classify_target_status(200)
        self.assertEqual(verdict, 'ok')
        self.assertIn('200', message)

    def test_not_found_is_error(self):
        verdict, message = classify_target_status(404)
        self.assertEqual(verdict, 'error')
        self.assertIn('404', message)

    def test_forbidden_is_error(self):
        verdict, message = classify_target_status(403)
        self.assertEqual(verdict, 'error')
        self.assertIn('403', message)

    def test_server_error_is_error(self):
        for code in (500, 502, 503):
            with self.subTest(code=code):
                verdict, message = classify_target_status(code)
                self.assertEqual(verdict, 'error')
                self.assertIn(str(code), message)

    def test_other_codes_only_warn(self):
        for code in (301, 302, 401, 204):
            with self.subTest(code=code):
                verdict, _ = classify_target_status(code)
                self.assertEqual(verdict, 'warn')


if __name__ == '__main__':
    unittest.main()
