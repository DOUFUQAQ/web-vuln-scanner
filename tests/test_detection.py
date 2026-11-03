"""检测逻辑的单元测试：报错特征匹配、XSS 反射判定、URL 拼装、长度异常。

全部离线，不需要 requests / bs4 / 网络。
"""
import unittest

from scanner.detection import (
    build_url,
    detect_sql_error,
    response_length_is_anomalous,
    split_query,
    xss_reflection_detected,
)


class SqlErrorSignatureTest(unittest.TestCase):
    """5 类数据库报错特征 + 负样本。"""

    def test_mysql(self):
        body = ("You have an error in your SQL syntax; check the manual that "
                "corresponds to your MySQL server version for the right syntax")
        db, matched = detect_sql_error(body)
        self.assertEqual(db, 'MySQL')
        self.assertIsNotNone(matched)

    def test_postgresql(self):
        db, _ = detect_sql_error('PostgreSQL query failed: ERROR: syntax error at or near')
        self.assertEqual(db, 'PostgreSQL')

    def test_mssql(self):
        db, _ = detect_sql_error("Microsoft OLE DB Provider for SQL Server error '80040e14'")
        self.assertEqual(db, 'MSSQL')

    def test_oracle(self):
        db, matched = detect_sql_error('ORA-01756: quoted string not properly terminated')
        self.assertEqual(db, 'Oracle')
        # 正则只吃 4 位数字（`\bORA-[0-9][0-9][0-9][0-9]`），所以命中的片段是
        # 'ORA-0175'，被截断了。够用来识别数据库类型，但别指望它当错误码用。
        self.assertTrue(matched.startswith('ORA-'))

    def test_sqlite(self):
        db, _ = detect_sql_error('sqlite3.OperationalError: unrecognized token: "\'"')
        self.assertEqual(db, 'SQLite')

    def test_sqlite_chinese_message(self):
        db, _ = detect_sql_error('<h1>数据库错误</h1><p>Error: near "1": syntax error</p>')
        self.assertEqual(db, 'SQLite')

    def test_clean_page_is_not_an_error(self):
        self.assertEqual(detect_sql_error('<html><body>Hello, world</body></html>'), (None, None))

    def test_empty_body(self):
        self.assertEqual(detect_sql_error(''), (None, None))

    def test_matching_is_case_insensitive(self):
        db, _ = detect_sql_error('warning: mysql_fetch_array() expects parameter 1')
        self.assertEqual(db, 'MySQL')

    def test_first_db_in_dict_order_wins(self):
        # 同时含 MySQL 与 SQLite 的特征时，按 SQL_ERRORS 的插入顺序返回 MySQL
        body = 'You have an error in your SQL syntax (MySQL server) and a syntax error'
        db, _ = detect_sql_error(body)
        self.assertEqual(db, 'MySQL')

    def test_matched_text_comes_from_the_body(self):
        body = 'fatal: unrecognized token: "x"'
        _, matched = detect_sql_error(body)
        self.assertIn(matched, body)


class XssReflectionTest(unittest.TestCase):
    """反射判定的两级证据 + 已知误判。"""

    PAYLOAD = "<script>alert('XSS')</script>"

    def test_raw_payload_in_body_is_a_hit(self):
        self.assertTrue(xss_reflection_detected(self.PAYLOAD, '<p>结果: ' + self.PAYLOAD + '</p>'))

    def test_html_escaped_payload_is_not_a_hit(self):
        escaped = '&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;'
        self.assertFalse(xss_reflection_detected(self.PAYLOAD, '<p>结果: ' + escaped + '</p>'))

    def test_shared_dangerous_token_counts_as_hit(self):
        payload = '<svg/onload=alert(1)>'
        body = '&lt;svg/onload=alert(1)&gt;'
        # 尖括号被转义了，理论上无法执行，但 onload= 两边都在 -> 仍判命中。
        # 这是弱证据判据的已知误报，README「已知局限」里写明了。
        self.assertTrue(xss_reflection_detected(payload, body))

    def test_token_only_on_one_side_is_not_a_hit(self):
        self.assertFalse(xss_reflection_detected('<img src=x onerror=alert(1)>', 'nothing here'))

    def test_event_handler_case_insensitive(self):
        self.assertTrue(xss_reflection_detected('<BODY ONLOAD=alert(1)>', '<body onload=x>'))

    def test_empty_inputs(self):
        self.assertFalse(xss_reflection_detected('', '<html></html>'))
        self.assertFalse(xss_reflection_detected(self.PAYLOAD, ''))


class ResponseLengthTest(unittest.TestCase):
    """盲注启发式：只看长度差是否超过阈值。"""

    def test_over_threshold(self):
        self.assertTrue(response_length_is_anomalous(1000, 1101))

    def test_exactly_threshold_is_not_enough(self):
        self.assertFalse(response_length_is_anomalous(1000, 1100))

    def test_shorter_response_also_counts(self):
        self.assertTrue(response_length_is_anomalous(1000, 799))

    def test_custom_threshold(self):
        self.assertTrue(response_length_is_anomalous(100, 130, threshold=20))
        self.assertFalse(response_length_is_anomalous(100, 110, threshold=20))


class UrlBuildingTest(unittest.TestCase):
    """payload 注入靠 urlencode 拼 query，被注入位置的编码必须精确。"""

    def test_merges_params_and_keeps_untouched_values(self):
        url = 'http://target/user?id=1&page=2'
        built = build_url(url, {'id': ["1' OR '1'='1"], 'page': ['2']})
        self.assertEqual(built, 'http://target/user?id=1%27+OR+%271%27%3D%271&page=2')

    def test_payload_is_percent_encoded(self):
        built = build_url('http://target/s?q=x', {'q': ["' UNION SELECT NULL--"]})
        self.assertNotIn("'", built)
        # urlencode 默认 quote_plus：引号转义、空格变 '+'
        self.assertIn('%27+UNION+SELECT+NULL--', built)

    def test_list_values_take_first_element(self):
        built = build_url('http://target/p?a=1', {'a': ['first', 'second']})
        self.assertEqual(built, 'http://target/p?a=first')

    def test_scalar_values_are_accepted(self):
        built = build_url('http://target/p?a=1', {'a': 'scalar'})
        self.assertEqual(built, 'http://target/p?a=scalar')

    def test_path_fragment_and_port_are_preserved(self):
        built = build_url('https://host:8443/deep/path?a=1#frag', {'a': ['2']})
        self.assertEqual(built, 'https://host:8443/deep/path?a=2#frag')

    def test_split_query_roundtrip(self):
        params = split_query('http://target/user?id=1&q=hello')
        self.assertEqual(params, {'id': ['1'], 'q': ['hello']})

    def test_split_query_without_params(self):
        self.assertEqual(split_query('http://target/user'), {})


if __name__ == '__main__':
    unittest.main()
