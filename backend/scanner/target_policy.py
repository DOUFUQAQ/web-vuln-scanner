"""目标 URL 策略：协议白名单、私网/内网拦截、可达性判定。

**这不是一个完整的 SSRF 防护。** 它只做三件确定能做对的事：

1. 协议白名单（``http`` / ``https``），挡掉 ``file://``、``ftp://``、
   ``gopher://``、``dict://`` 这类被 ``requests`` 或下游解析器支持、
   但扫描器完全不需要的 scheme；
2. 主机白名单（可选，逗号分隔，支持 ``*.example.com`` 后缀匹配）；
3. 私网地址拦截（**默认关闭**，见下）。

关于第 3 条的默认值：原项目的主要用法是扫本机靶场
（``http://localhost:8080/user?id=1``），所以 ``allow_private`` 默认是
``True``——先把功能跑通，再谈收紧。部署到多人共享的环境时，必须把
``SCANNER_BLOCK_PRIVATE_TARGETS=true``，否则任何能调到 API 的人都可以
让服务器去请求内网地址。

已知挡不住的情况（README 里同步写了）：域名解析到内网 IP（DNS rebinding /
单纯的 A 记录指向 127.0.0.1）、302 跳转到内网、IPv4-mapped IPv6 之类的
变形。要做真正的 SSRF 防护得在**建立连接的那一层**校验解析后的 IP，
那是 requests 之外的活。

本模块只依赖标准库，因此 ``tests/test_target_policy.py`` 可以离线验证。
"""
import ipaddress
from typing import Iterable, Tuple
from urllib.parse import urlparse

#: 允许扫描的协议。扫描器只会发 HTTP 请求，其它协议没有存在意义。
ALLOWED_SCHEMES = frozenset({'http', 'https'})

#: 各云厂商的元数据服务地址，即便开了私网扫描也应该拦掉。
METADATA_HOSTS = frozenset({
    '169.254.169.254',          # AWS / GCP / Azure / 阿里云
    'metadata.google.internal',
    'metadata',                 # OpenStack
    '100.100.100.200',          # 阿里云 ECS
})

#: 明确的本机别名。``.local`` / ``.localhost`` 走后缀判断，不在这里列。
LOCAL_HOSTNAMES = frozenset({'localhost', 'localhost.localdomain', 'ip6-localhost'})


class TargetPolicyError(ValueError):
    """目标 URL 违反策略。``str(exc)`` 直接可以回给前端当提示语。"""


def parse_allowed_hosts(raw: str) -> Tuple[str, ...]:
    """解析 ``SCANNER_ALLOWED_TARGET_HOSTS``：逗号分隔、去空白、转小写。

    空字符串表示"不限制主机"，返回空元组。
    """
    if not raw:
        return ()
    hosts = []
    for chunk in raw.replace(';', ',').split(','):
        host = chunk.strip().lower()
        if host:
            hosts.append(host)
    return tuple(hosts)


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def host_is_private(host: str) -> bool:
    """判断主机名是否指向本机 / 私网 / 链路本地 / 保留地址。

    * IP 字面量：交给 ``ipaddress`` 的 ``is_private`` / ``is_loopback`` /
      ``is_link_local`` / ``is_reserved`` / ``is_unspecified``；
    * 域名：只认 ``localhost`` 家族和 ``.local`` 后缀——**不做 DNS 解析**，
      所以 ``127.0.0.1.nip.io`` 这类会漏。
    """
    host = (host or '').strip().lower().strip('[]')
    if not host:
        return True
    if host in METADATA_HOSTS or host in LOCAL_HOSTNAMES:
        return True
    if host.endswith('.localhost') or host.endswith('.local'):
        return True
    if _is_ip_literal(host):
        ip = ipaddress.ip_address(host)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_unspecified
            or ip.is_multicast
        )
    return False


def _host_matches_allowlist(host: str, allowed_hosts: Iterable[str]) -> bool:
    """白名单匹配：``example.com`` 精确匹配；``*.example.com`` / ``.example.com``
    匹配其子域（也匹配裸域本身）。"""
    host = (host or '').strip().lower()
    for entry in allowed_hosts:
        entry = entry.strip().lower()
        if not entry:
            continue
        if entry.startswith('*.'):
            suffix = entry[1:]          # '.example.com'
        elif entry.startswith('.'):
            suffix = entry
        else:
            suffix = None
        if suffix is not None:
            if host == suffix[1:] or host.endswith(suffix):
                return True
        elif host == entry:
            return True
    return False


def validate_target_url(
    url: str,
    allow_private: bool = True,
    allowed_hosts: Iterable[str] = (),
) -> str:
    """校验目标 URL，返回去掉首尾空白的规范化结果。

    Args:
        url: 待校验 URL。
        allow_private: 是否允许私网 / 本机地址（默认允许，见模块 docstring）。
        allowed_hosts: 主机白名单；空表示不限制。

    Raises:
        TargetPolicyError: 协议不在白名单、缺少主机、主机不在白名单、
            或（``allow_private=False`` 时）主机指向私网。
    """
    candidate = (url or '').strip()
    if not candidate:
        raise TargetPolicyError('目标URL不能为空')

    parsed = urlparse(candidate)
    scheme = (parsed.scheme or '').lower()
    if not scheme:
        raise TargetPolicyError('目标URL缺少协议，请以 http:// 或 https:// 开头')
    if scheme not in ALLOWED_SCHEMES:
        allowed = ' / '.join(sorted(ALLOWED_SCHEMES))
        raise TargetPolicyError(f'不支持的协议 "{scheme}"，只允许 {allowed}')

    host = (parsed.hostname or '').strip().lower()
    if not host:
        raise TargetPolicyError('目标URL缺少主机名')

    if allowed_hosts and not _host_matches_allowlist(host, allowed_hosts):
        raise TargetPolicyError(
            f'主机 "{host}" 不在扫描白名单内（见 SCANNER_ALLOWED_TARGET_HOSTS）'
        )

    if not allow_private:
        if host in METADATA_HOSTS:
            raise TargetPolicyError(f'拒绝访问云元数据地址 "{host}"')
        if host_is_private(host):
            raise TargetPolicyError(
                f'拒绝访问私网/本机地址 "{host}"（SCANNER_BLOCK_PRIVATE_TARGETS=true）'
            )

    return candidate


def classify_target_status(status_code: int) -> Tuple[str, str]:
    """把目标可达性探测的 HTTP 状态码翻译成 ``(判定, 说明)``。

    判定取值：``ok``（继续扫描）、``warn``（继续扫描但提示）、
    ``error``（终止任务，扫描器会把说明写进任务失败原因）。

    阈值与原始实现一致：404 当成"页面不存在"，403 当成"拒绝访问"，
    ≥500 当成"目标服务器错误"，其余非 200 一律警告后继续。
    """
    if status_code == 200:
        return 'ok', f'目标URL可访问 (状态码: {status_code})'
    if status_code == 404:
        return 'error', '目标URL不存在 (404 Not Found)'
    if status_code == 403:
        return 'error', '目标URL拒绝访问 (403 Forbidden)'
    if status_code >= 500:
        return 'error', f'目标服务器错误 ({status_code})'
    return 'warn', f'目标返回状态码 {status_code}，继续扫描'
