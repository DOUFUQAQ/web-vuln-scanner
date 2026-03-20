"""CSRF 扫描器（令牌缺失 + SameSite Cookie 属性）。

只做两件事，都是"看"而不是"打"：

1. 用 BeautifulSoup 取出页面里所有 ``method=POST`` 的表单，检查是否存在
   带值的 CSRF 令牌字段（判定规则见 ``detection.has_csrf_token``，两轮
   子串/全等匹配）；缺令牌就报一条，命中敏感关键字或 password 字段的
   报 high，其余报 medium；
2. 检查响应头 ``Set-Cookie`` 里有没有 ``SameSite``，没有就报一条 medium。

**没有做 Referer / Origin 校验**，也**没有做**"令牌是否真的绑定会话"的验证
（那需要登录态和两次对比请求，超出本工具的会话模型）。所以这里报的是
"可能缺防护"，不是"确认可利用"——真正的 CSRF 可利用性必须人工验证。
"""
from typing import Any, Dict, List

from bs4 import BeautifulSoup

from .detection import has_csrf_token, is_sensitive_form
from .payloads import CSRF_TOKEN_NAMES
from .vulnerability_base import VulnerabilityScanner


class CSRFScanner(VulnerabilityScanner):
    """CSRF 跨站请求伪造扫描器"""

    CSRF_TOKEN_NAMES = CSRF_TOKEN_NAMES

    def get_scanner_name(self) -> str:
        return "CSRF扫描器"

    def scan(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        """扫描 CSRF 防护缺失。"""
        vulnerabilities: List[Dict[str, Any]] = []

        try:
            response = self._make_request('GET', url)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            for form_idx, form in enumerate(forms):
                method = form.get('method', 'GET').upper()
                action = form.get('action', '')

                # 只检查 POST 表单：GET 表单本身不该改状态，CSRF 意义有限
                if method != 'POST':
                    continue

                hidden_fields, all_fields = self._extract_fields(form)

                if has_csrf_token(hidden_fields, all_fields):
                    continue

                sensitive = is_sensitive_form(action, all_fields)
                vulnerabilities.append({
                    'vuln_type': 'CSRF（跨站请求伪造）',
                    'severity': 'high' if sensitive else 'medium',
                    'title': f'CSRF防护缺失 - 表单 #{form_idx + 1}',
                    'description': '检测到POST表单缺少CSRF令牌保护。攻击者可能诱导用户执行非预期的操作。',
                    'location': f'{url} (表单action: {action or "当前页面"})',
                    'evidence': f'表单方法: {method}\n表单action: {action}\n未发现CSRF令牌',
                    'recommendation': '1. 为所有状态改变操作添加CSRF令牌\n2. 验证请求来源（Referer检查）\n3. 使用SameSite Cookie属性\n4. 实施双重提交Cookie模式',
                    'form_action': action,
                    'is_sensitive': sensitive,
                })

            header_vuln = self._check_csrf_headers(response, url)
            if header_vuln:
                vulnerabilities.append(header_vuln)

        except Exception:
            # 目标不可解析 / 不可达时静默跳过，由调用方按任务状态体现
            pass

        return vulnerabilities

    @staticmethod
    def _extract_fields(form):
        """把表单字段拆成 ``(隐藏域列表, 全部 input 列表)``，元素是普通 dict。

        转成 dict 之后 ``detection.has_csrf_token`` / ``is_sensitive_form``
        就不必依赖 BeautifulSoup，可以在纯标准库环境里单测。
        """
        def to_dict(element):
            return {
                'name': element.get('name', '') or '',
                'value': element.get('value', '') or '',
                'type': element.get('type', '') or '',
            }

        hidden_fields = [to_dict(el) for el in form.find_all('input', {'type': 'hidden'})]
        all_fields = [to_dict(el) for el in form.find_all('input')]
        # 敏感关键字判定还要看 textarea / select 的 name
        for el in form.find_all(['textarea', 'select']):
            all_fields.append(to_dict(el))
        return hidden_fields, all_fields

    def _check_csrf_token(self, form) -> bool:
        """兼容旧调用点：隐藏域 + 全部字段两轮匹配。"""
        hidden_fields, all_fields = self._extract_fields(form)
        return has_csrf_token(hidden_fields, all_fields)

    def _is_sensitive_form(self, form, action: str) -> bool:
        """兼容旧调用点：action / password 字段 / 字段名三类判据。"""
        _, all_fields = self._extract_fields(form)
        return is_sensitive_form(action, all_fields)

    def _check_csrf_headers(self, response, url: str) -> Dict[str, Any]:
        """Cookie 缺 ``SameSite`` 时返回一条 medium 漏洞，否则返回 None。"""
        set_cookie = response.headers.get('Set-Cookie', '')

        if set_cookie and 'samesite' not in set_cookie.lower():
            evidence = f'Set-Cookie头: {set_cookie[:200]}...' if len(set_cookie) > 200 else f'Set-Cookie头: {set_cookie}'
            return {
                'vuln_type': 'CSRF防护不足',
                'severity': 'medium',
                'title': 'Cookie缺少SameSite属性',
                'description': 'Cookie未设置SameSite属性，可能增加CSRF攻击风险。',
                'location': url,
                'evidence': evidence,
                'recommendation': '为Cookie设置SameSite属性（推荐值：Strict或Lax）',
            }

        return None
