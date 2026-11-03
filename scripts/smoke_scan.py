"""对本地靶场跑一遍三个扫描器，人工看输出（不是单元测试）。

用法：

    # 终端 1：起靶场
    python scripts/vulnerable_app.py

    # 终端 2：扫它
    python scripts/smoke_scan.py
    SMOKE_TARGET=http://127.0.0.1:8888 python scripts/smoke_scan.py   # 换端口

退出码 0 表示三个扫描器都至少报出一条，1 表示有扫描器没命中。
它真的会发 HTTP 请求，所以不在 tests/ 里跑，CI 也不碰。
"""
import os
import sys

BACKEND = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'backend')
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from settings import tolerate_console_encoding  # noqa: E402

tolerate_console_encoding()

from scanner.sql_injection import SQLInjectionScanner  # noqa: E402
from scanner.xss_scanner import XSSScanner  # noqa: E402
from scanner.csrf_scanner import CSRFScanner  # noqa: E402
import requests  # noqa: E402

BASE_URL = os.environ.get('SMOKE_TARGET', 'http://localhost:8080').rstrip('/')

def check_server():
    """检查测试服务器是否运行"""
    try:
        response = requests.get(BASE_URL + '/', timeout=2)
        return response.status_code == 200
    except:
        return False

def test_sql_injection():
    """测试SQL注入扫描"""
    print("\n" + "=" * 60)
    print("测试 SQL注入扫描器")
    print("=" * 60)
    
    scanner = SQLInjectionScanner()
    test_url = f"{BASE_URL}/user?id=1"
    
    print(f"目标URL: {test_url}\n")
    
    try:
        vulnerabilities = scanner.scan(test_url)
        
        print(f"\n结果: 发现 {len(vulnerabilities)} 个漏洞")
        
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"\n漏洞 #{i}:")
            print(f"  类型: {vuln['vuln_type']}")
            print(f"  严重程度: {vuln['severity']}")
            print(f"  标题: {vuln['title']}")
            print(f"  载荷: {vuln.get('payload', 'N/A')}")
            print(f"  数据库: {vuln.get('database_type', 'N/A')}")
            
        return len(vulnerabilities) > 0
        
    except Exception as e:
        print(f"✗ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        scanner.close()

def test_xss():
    """测试XSS扫描"""
    print("\n" + "=" * 60)
    print("测试 XSS扫描器")
    print("=" * 60)
    
    scanner = XSSScanner()
    test_url = f"{BASE_URL}/search?q=test"
    
    print(f"目标URL: {test_url}\n")
    
    try:
        vulnerabilities = scanner.scan(test_url)
        
        print(f"\n结果: 发现 {len(vulnerabilities)} 个漏洞")
        
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"\n漏洞 #{i}:")
            print(f"  类型: {vuln['vuln_type']}")
            print(f"  严重程度: {vuln['severity']}")
            print(f"  标题: {vuln['title']}")
            print(f"  载荷: {vuln.get('payload', 'N/A')[:50]}")
            
        return len(vulnerabilities) > 0
        
    except Exception as e:
        print(f"✗ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        scanner.close()

def test_csrf():
    """测试CSRF扫描"""
    print("\n" + "=" * 60)
    print("测试 CSRF扫描器")
    print("=" * 60)
    
    scanner = CSRFScanner()
    test_url = f"{BASE_URL}/change_password"
    
    print(f"目标URL: {test_url}\n")
    
    try:
        vulnerabilities = scanner.scan(test_url)
        
        print(f"\n结果: 发现 {len(vulnerabilities)} 个漏洞")
        
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"\n漏洞 #{i}:")
            print(f"  类型: {vuln['vuln_type']}")
            print(f"  严重程度: {vuln['severity']}")
            print(f"  标题: {vuln['title']}")
            
        return len(vulnerabilities) > 0
        
    except Exception as e:
        print(f"✗ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        scanner.close()

def main():
    print("=" * 60)
    print("本地漏洞扫描器测试")
    print("=" * 60)
    
    # 检查测试服务器
    print("\n检查测试服务器...")
    if not check_server():
        print("✗ 测试服务器未运行！")
        print("\n请先在另一个命令行窗口中运行:")
        print("  python scripts/vulnerable_app.py")
        print("\n然后再运行此测试脚本。")
        return
    
    print("✓ 测试服务器正在运行\n")
    
    # 运行测试
    results = {
        'SQL注入': test_sql_injection(),
        'XSS': test_xss(),
        'CSRF': test_csrf()
    }
    
    # 总结
    print("\n" + "=" * 60)
    print("测试总结")
    print("=" * 60)
    
    for scanner_name, success in results.items():
        status = "✓ 通过" if success else "✗ 失败"
        print(f"{scanner_name:20} {status}")
    
    success_count = sum(results.values())
    total_count = len(results)
    
    print(f"\n通过率: {success_count}/{total_count} ({success_count*100//total_count}%)")
    
    if success_count == total_count:
        print("\n🎉 所有扫描器测试通过！")
        print("你的系统现在可以正常检测漏洞了。")
    else:
        print("\n⚠️ 部分扫描器测试失败。")
        print("请检查错误信息并调试相应的扫描器代码。")
    
    print("\n" + "=" * 60)
    return 0 if success_count == total_count else 1


if __name__ == '__main__':
    sys.exit(main())
