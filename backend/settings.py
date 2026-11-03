"""运行期配置：全部从环境变量读，代码里不存任何凭据。

优先级：显式入参 > 环境变量 / ``.env`` > 代码内默认值。
默认值一律是"能本地跑起来"，不是"能上生产"——生产要覆盖哪些项，
README 的「部署与安全默认值」表格里逐项列了。

本模块只依赖标准库（含 ``os.environ`` 的纯函数封装），
``tests/test_settings.py`` 通过传入假 ``environ`` 就能覆盖全部分支。
"""
import os
import sys
from typing import List, Mapping, Optional, Tuple

#: 占位密钥。真的用了它会在启动时打印告警，别拿它上任何公网环境。
DEFAULT_SECRET_KEY = 'dev-only-insecure-secret-key'

#: 默认 SQLite 落盘位置（相对启动目录）。生产请换 ``DATABASE_URL``。
DEFAULT_DATABASE_URL = 'sqlite:///vulnerability_scanner.db'

_TRUTHY = frozenset({'1', 'true', 'yes', 'on', 'y', 't'})
_FALSY = frozenset({'', '0', 'false', 'no', 'off', 'n', 'f'})


def env_str(environ: Mapping[str, str], name: str, default: str = '') -> str:
    """读字符串环境变量，未设置或为空时用默认值。"""
    value = environ.get(name)
    if value is None or value == '':
        return default
    return value


def env_bool(environ: Mapping[str, str], name: str, default: bool = False) -> bool:
    """读布尔环境变量。认 ``1/true/yes/on`` 与 ``0/false/no/off``，
    其它值原样退回默认值（不抛异常，配置写错不该让服务起不来）。"""
    value = environ.get(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in _TRUTHY:
        return True
    if normalized in _FALSY:
        return False
    return default


def env_int(
    environ: Mapping[str, str],
    name: str,
    default: int,
    minimum: Optional[int] = None,
) -> int:
    """读整数环境变量，非法值退回默认值。"""
    value = environ.get(name)
    if value is None or value.strip() == '':
        return default
    try:
        parsed = int(value.strip())
    except ValueError:
        return default
    if minimum is not None and parsed < minimum:
        return default
    return parsed


def env_list(environ: Mapping[str, str], name: str) -> Tuple[str, ...]:
    """读逗号分隔的列表环境变量（自动去空白、丢空项）。"""
    raw = environ.get(name, '')
    if not raw:
        return ()
    items: List[str] = []
    for chunk in raw.replace(';', ',').split(','):
        item = chunk.strip()
        if item:
            items.append(item)
    return tuple(items)


def tolerate_console_encoding() -> None:
    """让 ``print('✓')`` 在 GBK 控制台下不再抛 ``UnicodeEncodeError``。

    扫描器会打 ✓ / ✗ / ⚠️ / → 这类符号。Windows 默认控制台是 cp936（GBK），
    ``print`` 遇到编码表里没有的字符会直接抛异常——在后台线程里这意味着
    整条扫描任务被判失败，在启动流程里意味着服务起不来。

    做法是只把 ``errors`` 换成 ``replace``（**不动 encoding**）：中文照旧正常，
    无法编码的符号降级成 ``?``。这样 UTF-8 终端输出不变，GBK 终端也不崩。
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, 'reconfigure', None)
        if reconfigure is None:          # 被重定向/测试替身，跳过
            continue
        try:
            reconfigure(errors='replace')
        except (ValueError, OSError):    # 已关闭或不可重配的流，忽略
            pass


def load_settings(environ: Optional[Mapping[str, str]] = None) -> dict:
    """汇总所有配置项。

    Args:
        environ: 注入的环境变量映射，默认 ``os.environ``。测试用它替身。
    """
    env = os.environ if environ is None else environ
    return {
        # --- Flask ---
        'secret_key': env_str(env, 'SCANNER_SECRET_KEY', DEFAULT_SECRET_KEY),
        'database_url': env_str(env, 'DATABASE_URL', DEFAULT_DATABASE_URL),
        'cors_origins': env_str(env, 'SCANNER_CORS_ORIGINS', '*'),
        'host': env_str(env, 'SCANNER_HOST', '127.0.0.1'),
        'port': env_int(env, 'SCANNER_PORT', 5000, minimum=1),
        'debug': env_bool(env, 'SCANNER_DEBUG', False),
        # --- 扫描器行为 ---
        'http_timeout': env_int(env, 'SCANNER_HTTP_TIMEOUT', 10, minimum=1),
        'tls_verify': env_bool(env, 'SCANNER_TLS_VERIFY', False),
        'block_private_targets': env_bool(env, 'SCANNER_BLOCK_PRIVATE_TARGETS', False),
        'allowed_target_hosts': env_list(env, 'SCANNER_ALLOWED_TARGET_HOSTS'),
    }
