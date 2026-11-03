"""检测逻辑（纯函数）。

把"给定响应文本 / payload / 表单字段，判断是不是命中"这一层从
``requests`` 与 ``bs4`` 的 IO 层里剥离出来，只用标准库。

各扫描器现在只是"发请求 + 调这里"，所以：

* ``tests/test_detection.py`` 可以完全离线地跑（不需要 requests / bs4）；
* 想调整某个正则或阈值，只改这两个文件，不用碰网络代码。

所有函数都是无副作用的，函数签名刻意保留原实现里私方法的语义，
方便对照 ``git log`` 里改造前的版本。
"""
import re
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from .payloads import (
    BLIND_DIFF_THRESHOLD,
    CSRF_TOKEN_NAMES,
    SENSITIVE_FORM_KEYWORDS,
    SQL_ERRORS,
    XSS_DANGEROUS_TOKENS,
)


def build_url(base_url: str, params: Dict[str, object]) -> str:
    """把参数字典拼回完整 URL。

    只取每个参数的**第一个**值（``parse_qs`` 返回的是 list），保持原有
    "一次只注入一个参数、其余参数回填原值"的行为；path / params /
    fragment 原样保留。
    """
    parsed = urlparse(base_url)
    param_dict = {
        key: (value[0] if isinstance(value, list) else value)
        for key, value in params.items()
    }
    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        urlencode(param_dict),
        parsed.fragment,
    ))


def split_query(url: str) -> Dict[str, List[str]]:
    """取出 URL 的查询参数（没有参数时返回空 dict）。"""
    return parse_qs(urlparse(url).query)


def detect_sql_error(content: str) -> Tuple[Optional[str], Optional[str]]:
    """在响应正文里找数据库报错特征。

    Returns:
        ``(数据库类型, 命中的原始片段)``；没有命中返回 ``(None, None)``。
    """
    if not content:
        return None, None
    for db_type, patterns in SQL_ERRORS.items():
        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return db_type, match.group(0)
    return None, None


def response_length_is_anomalous(
    normal_length: int,
    current_length: int,
    threshold: int = BLIND_DIFF_THRESHOLD,
) -> bool:
    """响应长度差是否超过阈值（疑似盲注的启发式判据）。"""
    return abs(current_length - normal_length) > threshold


def xss_reflection_detected(payload: str, content: str) -> bool:
    """判断 payload 是否未经编码地反射进了响应。

    两级判据：

    1. 原始 payload 字符串完整出现 —— 强证据；
    2. payload 与响应同时包含同一个危险片段（``<script`` /
       ``javascript:`` / ``onerror=`` ...）—— 弱证据。

    第 2 级只看"两边的交集"，不看片段在响应中的位置，所以对
    ``&lt;script`` 这类转义输出会漏判（因为它已不含 ``<script``），
    但对"只转义了引号、没转义尖括号"的场景会误判。这条取舍写在
    README 的「已知局限」里。
    """
    if not payload or not content:
        return False
    if payload in content:
        return True
    payload_lower = payload.lower()
    content_lower = content.lower()
    return any(
        token in payload_lower and token in content_lower
        for token in XSS_DANGEROUS_TOKENS
    )


def has_csrf_token(
    hidden_fields: Iterable[Dict[str, str]],
    all_fields: Iterable[Dict[str, str]],
) -> bool:
    """表单里是否存在带值的 CSRF 令牌字段。

    两轮匹配（保留原实现语义）：

    * 隐藏域：字段名**包含**任一令牌名即算，且必须有非空 ``value``；
    * 其余 input：字段名与令牌名**全等**才算，同样要求 ``value`` 非空。

    隐藏域用子串匹配是为了兼容 ``csrfmiddlewaretoken`` /
    ``__RequestVerificationToken`` 这类带前后缀的命名，副作用是
    ``access_token`` 这种普通隐藏域也会被当成令牌（漏报，见 README）。
    """
    for field in hidden_fields:
        name = (field.get('name') or '').lower()
        if not name or not field.get('value'):
            continue
        for token_name in CSRF_TOKEN_NAMES:
            if token_name.lower() in name:
                return True
    for field in all_fields:
        name = (field.get('name') or '').lower()
        if not name or not field.get('value'):
            continue
        for token_name in CSRF_TOKEN_NAMES:
            if token_name.lower() == name:
                return True
    return False


def is_sensitive_form(action: str, fields: Iterable[Dict[str, str]]) -> bool:
    """判断表单是否属于状态改变型（决定漏洞报 high 还是 medium）。

    判据：action 里出现敏感关键字，或表单里存在 ``type=password``，
    或字段名里出现敏感关键字。
    """
    action_lower = (action or '').lower()
    for keyword in SENSITIVE_FORM_KEYWORDS:
        if keyword in action_lower:
            return True
    for field in fields:
        name = (field.get('name') or '').lower()
        field_type = (field.get('type') or '').lower()
        if field_type == 'password':
            return True
        for keyword in SENSITIVE_FORM_KEYWORDS:
            if keyword in name:
                return True
    return False
