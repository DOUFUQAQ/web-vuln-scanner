"""SQL 注入扫描器（报错型 + 长度异常启发式）。

检测流程（对 URL 的**每一个**查询参数分别来一遍）：

1. 先请求原 URL 拿到基准响应长度；
2. 依次把 16 条 payload 注入该参数（其余参数回填原值），重新请求；
3. 响应用 ``detection.detect_sql_error()`` 匹配 5 类数据库报错特征，
   命中即判定为**报错型注入**，记 high 并停止该参数的后续 payload；
4. 没命中特征、但响应长度与基准相差 > 100 字节的，记一条
   "SQL注入（疑似）"（medium），同样停止该参数。

**没有实现布尔盲注和时间盲注。** 第 4 步只是"长度变了"的启发式，
既不比对真假条件对的差异，也不测响应时间。真正的布尔盲注需要对
``AND '1'='1'`` / ``AND '1'='2'`` 这一对 payload 做响应相似度差分，
时间盲注需要注入 ``SLEEP()`` 并测延迟——这两件事本实现都没做，
``SQL_PAYLOADS`` 里的盲注对照组只是打进去了，没有配套的判定逻辑。
"""
from typing import Any, Dict, List

from .detection import (
    build_url,
    detect_sql_error,
    response_length_is_anomalous,
    split_query,
)
from .payloads import BLIND_DIFF_THRESHOLD, SQL_ERRORS, SQL_PAYLOADS
from .vulnerability_base import VulnerabilityScanner


class SQLInjectionScanner(VulnerabilityScanner):
    """SQL 注入扫描器"""

    #: 探测载荷（定义在 ``payloads.py``，这里转发一份便于外部引用）
    SQL_PAYLOADS = SQL_PAYLOADS
    #: 报错特征库
    SQL_ERRORS = SQL_ERRORS
    #: 盲注长度差阈值
    BLIND_DIFF_THRESHOLD = BLIND_DIFF_THRESHOLD

    def get_scanner_name(self) -> str:
        return "SQL注入扫描器"

    def scan(self, url: str, **kwargs) -> List[Dict[str, Any]]:
        """扫描 SQL 注入。URL 没有查询参数时直接返回空列表（不做表单探测）。"""
        vulnerabilities: List[Dict[str, Any]] = []

        print(f"  [SQL注入扫描器] 开始扫描: {url}")

        params = split_query(url)
        if not params:
            print("  [SQL注入扫描器] URL没有参数，跳过")
            return vulnerabilities

        print(f"  [SQL注入扫描器] 发现 {len(params)} 个参数: {list(params.keys())}")

        for param_name in params.keys():
            print(f"  [SQL注入扫描器] 测试参数: {param_name}")
            param_vulns = self._test_parameter(url, param_name, params)
            vulnerabilities.extend(param_vulns)
            if param_vulns:
                print(f"  [SQL注入扫描器] ✓ 在参数 '{param_name}' 中发现 {len(param_vulns)} 个漏洞")

        print(f"  [SQL注入扫描器] 扫描完成，共发现 {len(vulnerabilities)} 个漏洞")
        return vulnerabilities

    def _test_parameter(self, url: str, param_name: str, all_params: Dict) -> List[Dict[str, Any]]:
        """测试单个参数。目标不可达时静默返回空列表（不中断其它参数）。"""
        vulnerabilities: List[Dict[str, Any]] = []

        try:
            normal_response = self._make_request('GET', url)
            normal_content = normal_response.text
            normal_length = len(normal_content)
            print(f"    - 正常响应长度: {normal_length} 字节")
        except Exception as e:
            print(f"    - ✗ 无法访问目标URL: {str(e)}")
            return vulnerabilities

        payload_count = 0
        for payload in self.SQL_PAYLOADS:
            try:
                payload_count += 1
                test_params = all_params.copy()
                test_params[param_name] = [payload]
                test_url = build_url(url, test_params)

                print(f"    - 测试payload [{payload_count}/{len(self.SQL_PAYLOADS)}]: {payload[:40]}...")

                response = self._make_request('GET', test_url)
                response_content = response.text
                status_code = response.status_code

                print(f"      状态码: {status_code}, 响应长度: {len(response_content)} 字节")

                detected_db, error_msg = self._detect_sql_error(response_content)

                if detected_db:
                    print(f"    - ✓ 检测到SQL注入！数据库: {detected_db}, Payload: {payload[:30]}...")
                    print(f"      错误信息: {error_msg[:100]}")
                    vulnerabilities.append({
                        'vuln_type': 'SQL注入',
                        'severity': 'high',
                        'title': f'SQL注入漏洞 - {param_name}参数',
                        'description': f'在参数"{param_name}"中检测到SQL注入漏洞。攻击者可能利用此漏洞访问、修改或删除数据库中的数据。',
                        'location': f'{url} (参数: {param_name})',
                        'evidence': f'数据库类型: {detected_db}\n测试载荷: {payload}\n错误信息: {error_msg}',
                        'recommendation': '1. 使用参数化查询或预编译语句\n2. 对用户输入进行严格验证和过滤\n3. 限制数据库权限\n4. 避免在错误信息中暴露数据库细节',
                        'database_type': detected_db,
                        'payload': payload,
                    })
                    break  # 发现漏洞后停止测试此参数

                elif response_length_is_anomalous(normal_length, len(response_content)):
                    print(f"    - ⚠️ 检测到响应长度异常 (正常:{normal_length}, 当前:{len(response_content)})")
                    vulnerabilities.append({
                        'vuln_type': 'SQL注入（疑似）',
                        'severity': 'medium',
                        'title': f'疑似SQL盲注漏洞 - {param_name}参数',
                        'description': f'在参数"{param_name}"中检测到异常响应，可能存在SQL盲注漏洞。',
                        'location': f'{url} (参数: {param_name})',
                        'evidence': f'测试载荷: {payload}\n正常响应长度: {normal_length}\n异常响应长度: {len(response_content)}',
                        'recommendation': '1. 使用参数化查询\n2. 对用户输入进行严格验证\n3. 进行人工验证确认漏洞',
                        'payload': payload,
                    })
                    break

                else:
                    preview = response_content[:100].replace('\n', ' ')
                    print(f"      预览: {preview}...")

            except Exception as e:
                print(f"    - ✗ Payload测试失败: {str(e)}")
                continue

        return vulnerabilities

    def _detect_sql_error(self, content: str) -> tuple:
        """兼容旧调用点的薄包装，逻辑在 ``detection.detect_sql_error``。"""
        return detect_sql_error(content)

    def _build_url(self, base_url: str, params: Dict) -> str:
        """兼容旧调用点的薄包装，逻辑在 ``detection.build_url``。"""
        return build_url(base_url, params)
