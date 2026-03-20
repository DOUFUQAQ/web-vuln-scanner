"""XSS 扫描器（反射型为主，外加一层表单注入）。

两个入口：

* ``_test_parameter``：遍历 URL 查询参数，16 条 payload 全打；
* ``_test_forms``：用 BeautifulSoup 解析页面里的 ``<form>``，跳过
  ``submit`` / ``button`` / ``hidden`` 字段，对每个可写字段只打**前 5 条**
  payload，GET 表单走 query、POST 表单走 body。

判定统一走 ``detection.xss_reflection_detected()``：payload 原样回显即命中，
或 payload 与响应共享 ``<script`` / ``javascript:`` 等危险片段。

关于"存储型 XSS"：本实现**没有**做存储型检测。要验证存储型必须"注入 → 找到
回显页面 → 再请求一次"，这套系统每次只打被注入的这一条 URL，所以只覆盖
反射型，以及"提交后立刻回显"那部分自反射。
"""
from typing import Any, Dict, List
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from .detection import build_url, split_query, xss_reflection_detected
from .payloads import FORM_PAYLOAD_LIMIT, XSS_PAYLOADS
from .vulnerability_base import VulnerabilityScanner


class XSSScanner(VulnerabilityScanner):
    """XSS 跨站脚本扫描器"""

    XSS_PAYLOADS = XSS_PAYLOADS

    def get_scanner_name(self) -> str:
        return "XSS扫描器"

    def scan(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        vulnerabilities: List[Dict[str, Any]] = []

        params = split_query(url)
        if params:
            for param_name in params.keys():
                vulnerabilities.extend(self._test_parameter(url, param_name, params))

        try:
            vulnerabilities.extend(self._test_forms(url))
        except Exception:
            # 表单探测是附加能力，页面结构异常不该让整次扫描失败
            pass

        return vulnerabilities

    def _test_parameter(self, url: str, param_name: str, all_params: Dict) -> List[Dict[str, Any]]:
        """测试 URL 参数。命中第一条 payload 后停止该参数。"""
        vulnerabilities: List[Dict[str, Any]] = []

        for payload in self.XSS_PAYLOADS:
            try:
                test_params = all_params.copy()
                test_params[param_name] = [payload]
                test_url = build_url(url, test_params)

                response = self._make_request('GET', test_url)

                if xss_reflection_detected(payload, response.text):
                    vulnerabilities.append({
                        'vuln_type': 'XSS（跨站脚本）',
                        'severity': 'high',
                        'title': f'反射型XSS漏洞 - {param_name}参数',
                        'description': f'在参数"{param_name}"中检测到反射型XSS漏洞。攻击者可以注入恶意脚本，窃取用户cookie、会话令牌或其他敏感信息。',
                        'location': f'{url} (参数: {param_name})',
                        'evidence': f'测试载荷: {payload}\n载荷未经编码直接反射在响应中',
                        'recommendation': '1. 对所有用户输入进行HTML实体编码\n2. 使用Content Security Policy (CSP)\n3. 设置HttpOnly和Secure标志的Cookie\n4. 验证和过滤用户输入',
                        'payload': payload,
                    })
                    break

            except Exception:
                continue

        return vulnerabilities

    def _test_forms(self, url: str) -> List[Dict[str, Any]]:
        """测试页面内表单的可写字段。"""
        vulnerabilities: List[Dict[str, Any]] = []

        try:
            response = self._make_request('GET', url)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            for form_idx, form in enumerate(forms):
                action = form.get('action', '')
                method = form.get('method', 'GET').upper()
                form_url = self._resolve_form_action(url, action)

                inputs = form.find_all(['input', 'textarea'])

                for input_field in inputs:
                    input_name = input_field.get('name')
                    input_type = input_field.get('type', 'text')

                    if not input_name or input_type in ['submit', 'button', 'hidden']:
                        continue

                    for payload in self.XSS_PAYLOADS[:FORM_PAYLOAD_LIMIT]:
                        try:
                            form_data = {input_name: payload}

                            if method == 'POST':
                                test_response = self._make_request('POST', form_url, data=form_data)
                            else:
                                test_response = self._make_request('GET', form_url, params=form_data)

                            if xss_reflection_detected(payload, test_response.text):
                                vulnerabilities.append({
                                    'vuln_type': 'XSS（跨站脚本）',
                                    'severity': 'high',
                                    'title': f'表单XSS漏洞 - {input_name}字段',
                                    'description': f'在表单字段"{input_name}"中检测到XSS漏洞。攻击者可能通过此漏洞执行恶意脚本。',
                                    'location': f'{form_url} (表单字段: {input_name}, 方法: {method})',
                                    'evidence': f'测试载荷: {payload}',
                                    'recommendation': '1. 对表单输入进行严格验证和编码\n2. 使用CSP策略\n3. 实施输出编码',
                                    'payload': payload,
                                })
                                break

                        except Exception:
                            continue

        except Exception:
            pass

        return vulnerabilities

    @staticmethod
    def _resolve_form_action(url: str, action: str) -> str:
        """把 ``<form action>`` 补成绝对 URL（相对路径按当前页面拼）。"""
        if not action:
            return url
        if action.startswith('http'):
            return action
        parsed = urlparse(url)
        if action.startswith('/'):
            return f"{parsed.scheme}://{parsed.netloc}{action}"
        return f"{url.rstrip('/')}/{action.lstrip('/')}"

    def _detect_xss(self, payload: str, content: str) -> bool:
        """兼容旧调用点的薄包装，逻辑在 ``detection.xss_reflection_detected``。"""
        return xss_reflection_detected(payload, content)

    def _build_url(self, base_url: str, params: Dict) -> str:
        """兼容旧调用点的薄包装，逻辑在 ``detection.build_url``。"""
        return build_url(base_url, params)
