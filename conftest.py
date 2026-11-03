"""pytest 入口：把仓库根和 ``backend/`` 都放进 ``sys.path``。

两种跑法都支持：

    python -m unittest discover -s tests -t .    # 只用标准库
    python -m pytest -q                          # 需要 pytest

测试本身用标准库 ``unittest`` 写，唯一的第三方依赖是 flask——
而依赖 flask 的那组用例用 ``skipUnless(FLASK_AVAILABLE)`` 跳过，
所以"机器上只有 python"也能跑出一片绿。
"""
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.join(ROOT, "backend")

for _path in (BACKEND, ROOT):
    if _path not in sys.path:
        sys.path.insert(0, _path)

# 让任何意外触发的 create_app() 也落到内存库、假密钥上，别碰真实文件
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SCANNER_SECRET_KEY", "test-only-secret")
