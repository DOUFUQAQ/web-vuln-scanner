"""漏洞扫描器模块。

**懒加载**是刻意的：三个扫描器都依赖 ``requests``（XSS / CSRF 还要 ``bs4``），
而 ``payloads`` / ``detection`` / ``target_policy`` 三个纯逻辑模块只依赖标准库。
如果在包初始化时就 ``from .sql_injection import ...``，那么"想测一下正则"也得
先装 requests —— 这正是改造前的状态。

现在 ``import scanner.detection`` 不会连带把 requests 拉进来；
``from scanner import SQLInjectionScanner`` 依然照旧可用（首次访问时才真正 import）。
"""
from importlib import import_module

_LAZY_ATTRIBUTES = {
    'VulnerabilityScanner': '.vulnerability_base',
    'SQLInjectionScanner': '.sql_injection',
    'XSSScanner': '.xss_scanner',
    'CSRFScanner': '.csrf_scanner',
}

__all__ = list(_LAZY_ATTRIBUTES)


def __getattr__(name):
    """PEP 562：模块级属性按需加载。"""
    target = _LAZY_ATTRIBUTES.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(target, __name__), name)
    globals()[name] = value          # 缓存，后续访问不再走 __getattr__
    return value


def __dir__():
    return sorted(list(globals().keys()) + __all__)
