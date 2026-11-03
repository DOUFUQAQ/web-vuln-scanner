"""测试包：让 ``python -m unittest discover`` 也能 import 到 ``backend`` 下的模块。

``conftest.py`` 只在 pytest 下生效，所以这里把同样的 ``sys.path`` 修补再做一遍。
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, "backend")

for _path in (BACKEND, ROOT):
    if _path not in sys.path:
        sys.path.insert(0, _path)

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SCANNER_SECRET_KEY", "test-only-secret")
