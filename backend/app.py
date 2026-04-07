"""Flask 应用主文件：Web 应用漏洞检测与风险评估平台。

启动方式（在 ``backend/`` 目录下）：

    python app.py

配置全部来自环境变量 / ``.env``（见仓库根的 ``.env.example``），
代码里没有任何硬编码凭据。默认只监听 ``127.0.0.1:5000``、关闭 debug，
这样"顺手起个服务"不会把带扫描能力的 API 暴露到局域网。
"""
from datetime import datetime

from flask import Flask, jsonify
from flask_cors import CORS

from models import db
from models.database import ScanTask
from routes.scan_routes import scan_bp
from settings import DEFAULT_SECRET_KEY, load_settings, tolerate_console_encoding

# 必须在任何 print 之前执行：Windows GBK 控制台下 ✓/✗ 会抛 UnicodeEncodeError
tolerate_console_encoding()


def _load_dotenv_if_available():
    """有 python-dotenv 就读 .env，没有就纯环境变量，两条路都能跑。"""
    try:
        from dotenv import load_dotenv
    except ImportError:
        return False
    load_dotenv()
    return True


_load_dotenv_if_available()


def cleanup_incomplete_tasks():
    """把上次进程退出时残留的 ``running`` 任务标记为失败。

    扫描任务跑在 daemon 线程里，进程一退线程就没了，但数据库里那条记录
    还停在 ``running``，前端会一直显示"运行中"。启动时扫一遍能自愈。
    注意：这里只清理 ``running``，``pending`` 的记录保持原样。
    """
    try:
        running_tasks = ScanTask.query.filter_by(status='running').all()

        if running_tasks:
            print(f"\n发现 {len(running_tasks)} 个未完成的扫描任务，正在清理...")

            for task in running_tasks:
                task.status = 'failed'
                task.completed_at = datetime.utcnow()
                print(f"  - 任务 #{task.id}: '{task.target.name}' 标记为失败（程序异常关闭）")

            db.session.commit()
            print("✓ 未完成任务清理完成\n")
        else:
            print("✓ 没有需要清理的未完成任务\n")

    except Exception as e:
        print(f"✗ 清理未完成任务时出错: {str(e)}\n")
        db.session.rollback()


def create_app(overrides=None):
    """创建 Flask 应用。

    Args:
        overrides: 覆盖 ``app.config`` 的字典，测试用它注入内存数据库。
    """
    settings = load_settings()

    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=settings['secret_key'],
        SQLALCHEMY_DATABASE_URI=settings['database_url'],
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        CORS_ORIGINS=settings['cors_origins'],
    )
    if overrides:
        app.config.update(overrides)

    if app.config['SECRET_KEY'] == DEFAULT_SECRET_KEY:
        print("⚠️ 正在使用默认 SECRET_KEY，仅限本地开发。部署前请设置 SCANNER_SECRET_KEY。")

    db.init_app(app)
    # 默认 SCANNER_CORS_ORIGINS='*'：本项目没有登录态，前后端分离开发方便优先。
    # 真要暴露到公网，请把它收窄成具体 origin（README 已列为已知风险）。
    CORS(app, origins=app.config['CORS_ORIGINS'])

    app.register_blueprint(scan_bp)

    @app.route('/api/health', methods=['GET'])
    def health_check():
        return jsonify({
            'status': 'ok',
            'message': 'Web应用漏洞检测与评估平台运行正常'
        })

    with app.app_context():
        db.create_all()
        cleanup_incomplete_tasks()

    return app


if __name__ == '__main__':
    settings = load_settings()
    app = create_app()

    print("=" * 60)
    print("Web应用漏洞信息安全检测与评估平台")
    print("=" * 60)
    print("后端服务启动中...")
    print(f"访问地址: http://{settings['host']}:{settings['port']}")
    print(f"健康检查: http://{settings['host']}:{settings['port']}/api/health")
    print(f"调试模式: {'开启' if settings['debug'] else '关闭'}")
    print("=" * 60)

    app.run(host=settings['host'], port=settings['port'], debug=settings['debug'])
