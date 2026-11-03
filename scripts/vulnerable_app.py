"""故意留洞的靶场应用 —— 只给本仓库的扫描器做冒烟验证用。

运行：python scripts/vulnerable_app.py（需要 flask），默认监听 8080，
被占用时自动换到 8888。它会在当前目录建一个 test_vulnerable.db。

简介：简单的漏洞测试应用 - 仅用于测试扫描器
警告：此代码包含故意设计的安全漏洞，仅用于学习和测试目的
切勿在生产环境中使用！
"""
from flask import Flask, request, render_template_string
import sqlite3
import os

app = Flask(__name__)

# 创建测试数据库
def init_db():
    db_path = 'test_vulnerable.db'
    if os.path.exists(db_path):
        os.remove(db_path)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # 创建测试表
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            email TEXT,
            password TEXT
        )
    ''')
    
    # 插入测试数据
    test_users = [
        (1, 'admin', 'admin@test.com', 'admin123'),
        (2, 'user1', 'user1@test.com', 'password1'),
        (3, 'test', 'test@test.com', 'test123'),
    ]
    
    cursor.executemany('INSERT INTO users VALUES (?, ?, ?, ?)', test_users)
    conn.commit()
    conn.close()
    print(f"[OK] 测试数据库已创建: {db_path}")

# SQL注入漏洞页面
@app.route('/user')
def user_profile():
    user_id = request.args.get('id', '1')
    
    try:
        conn = sqlite3.connect('test_vulnerable.db')
        cursor = conn.cursor()
        
        # 故意的SQL注入漏洞 - 直接拼接SQL
        query = f"SELECT * FROM users WHERE id = {user_id}"
        print(f"执行SQL: {query}")
        
        cursor.execute(query)
        result = cursor.fetchone()
        conn.close()
        
        if result:
            html = f"""
            <html>
            <head><title>用户信息</title></head>
            <body>
                <h1>用户信息</h1>
                <p>ID: {result[0]}</p>
                <p>用户名: {result[1]}</p>
                <p>邮箱: {result[2]}</p>
            </body>
            </html>
            """
            return html
        else:
            return "<html><body><h1>用户不存在</h1></body></html>"
            
    except Exception as e:
        # 故意暴露错误信息
        return f"""
        <html>
        <body>
            <h1>数据库错误</h1>
            <p style='color:red'>Error: {str(e)}</p>
            <p>SQL: {query}</p>
        </body>
        </html>
        """, 500

# XSS漏洞页面
@app.route('/search')
def search():
    query = request.args.get('q', '')
    
    # 故意的XSS漏洞 - 不转义用户输入
    html = f"""
    <html>
    <head><title>搜索结果</title></head>
    <body>
        <h1>搜索结果</h1>
        <p>您搜索的内容: {query}</p>
        <form action="/search" method="get">
            <input type="text" name="q" placeholder="输入搜索内容">
            <input type="submit" value="搜索">
        </form>
    </body>
    </html>
    """
    return html

# CSRF漏洞页面
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if request.method == 'POST':
        new_password = request.form.get('password', '')
        # 故意的CSRF漏洞 - 没有CSRF令牌验证
        return f"""
        <html>
        <body>
            <h1>密码已修改</h1>
            <p>新密码: {new_password}</p>
        </body>
        </html>
        """
    
    # 故意不包含CSRF令牌
    return """
    <html>
    <head><title>修改密码</title></head>
    <body>
        <h1>修改密码</h1>
        <form action="/change_password" method="post">
            <input type="password" name="password" placeholder="新密码">
            <input type="submit" value="提交">
        </form>
    </body>
    </html>
    """

@app.route('/')
def index():
    return """
    <html>
    <head><title>漏洞测试应用</title></head>
    <body>
        <h1>漏洞测试应用</h1>
        <p>[!] 警告：此应用包含故意设计的安全漏洞，仅用于测试！</p>
        <ul>
            <li><a href="/user?id=1">SQL注入测试页面</a></li>
            <li><a href="/search?q=test">XSS测试页面</a></li>
            <li><a href="/change_password">CSRF测试页面</a></li>
        </ul>
    </body>
    </html>
    """

if __name__ == '__main__':
    print("=" * 60)
    print("启动漏洞测试应用...")
    print("[!] 警告：此应用包含故意的安全漏洞，仅用于学习和测试！")
    print("=" * 60)
    
    init_db()
    
    # 尝试使用8080端口，如果被占用则使用8888
    import socket
    
    def is_port_in_use(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('localhost', port)) == 0
    
    port = 8080
    if is_port_in_use(port):
        print(f"\n[!] 端口 {port} 已被占用，切换到端口 8888")
        port = 8888
    
    print(f"\n测试URL (端口: {port}):")
    print(f"  主页: http://localhost:{port}/")
    print(f"  SQL注入: http://localhost:{port}/user?id=1")
    print(f"  XSS: http://localhost:{port}/search?q=test")
    print(f"  CSRF: http://localhost:{port}/change_password")
    print("\n" + "=" * 60)
    
    print(f"\n服务器将在端口 {port} 启动...")
    app.run(host='0.0.0.0', port=port, debug=True)
