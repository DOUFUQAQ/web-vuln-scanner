"""CSRF 判定规则的单元测试（不依赖 BeautifulSoup）。

扫描器负责把 ``<form>`` 拆成普通 dict，规则在这里验证：
令牌字段识别、敏感表单识别。
"""
import unittest

from scanner.detection import has_csrf_token, is_sensitive_form


def field(name='', value='', type_=''):
    return {'name': name, 'value': value, 'type': type_}


class HasCsrfTokenTest(unittest.TestCase):

    def test_django_style_hidden_token(self):
        hidden = [field('csrfmiddlewaretoken', 'abc123', 'hidden')]
        self.assertTrue(has_csrf_token(hidden, hidden))

    def test_hidden_token_without_value_is_not_protection(self):
        hidden = [field('csrf_token', '', 'hidden')]
        self.assertFalse(has_csrf_token(hidden, hidden))

    def test_rails_style_token(self):
        hidden = [field('authenticity_token', 'xyz', 'hidden')]
        self.assertTrue(has_csrf_token(hidden, hidden))

    def test_any_hidden_name_containing_token_is_accepted(self):
        # 隐藏域走子串匹配，所以 access_token 也会被当成 CSRF 令牌。
        # 这是原实现的既有行为，会带来漏报（false negative），测试锁住它。
        hidden = [field('access_token', 'abc', 'hidden')]
        self.assertTrue(has_csrf_token(hidden, hidden))

    def test_visible_exact_name_is_accepted(self):
        visible = [field('_token', 'abc', 'text')]
        self.assertTrue(has_csrf_token([], visible))

    def test_visible_partial_name_is_not(self):
        # 第二轮要求全等，所以 user_token 不算
        visible = [field('user_token', 'abc', 'text')]
        self.assertFalse(has_csrf_token([], visible))

    def test_no_fields_at_all(self):
        self.assertFalse(has_csrf_token([], []))

    def test_none_name_field_is_ignored(self):
        self.assertFalse(has_csrf_token([{'name': None, 'value': 'x'}], []))


class IsSensitiveFormTest(unittest.TestCase):

    def test_action_keyword(self):
        self.assertTrue(is_sensitive_form('/user/login', []))
        self.assertTrue(is_sensitive_form('/admin/settings', []))

    def test_action_keyword_is_case_insensitive(self):
        self.assertTrue(is_sensitive_form('/USER/LOGIN', []))

    def test_password_input(self):
        self.assertTrue(is_sensitive_form('/post', [field('q', '', 'password')]))

    def test_sensitive_field_name(self):
        self.assertTrue(is_sensitive_form('/post', [field('account_id', '')]))
        self.assertTrue(is_sensitive_form('/submit', [field('pwd', '')]))

    def test_neutral_form(self):
        self.assertFalse(is_sensitive_form('/search', [field('q', '', 'text')]))
        self.assertFalse(is_sensitive_form('', [field('comment', '', 'textarea')]))

    def test_empty_action_and_fields(self):
        self.assertFalse(is_sensitive_form('', []))


if __name__ == '__main__':
    unittest.main()
