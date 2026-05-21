"""
扫描相关API路由
"""
from flask import Blueprint, request, jsonify, current_app
from models import db, ScanTarget, ScanTask, Vulnerability
from scanner import SQLInjectionScanner, XSSScanner, CSRFScanner
from evaluator import CVSSCalculator
from evaluator.risk import aggregate_risk_scores
from scanner.target_policy import (
    TargetPolicyError,
    classify_target_status,
    validate_target_url,
)
from settings import load_settings
from datetime import datetime
import threading
import urllib3

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

scan_bp = Blueprint('scan', __name__, url_prefix='/api/scan')


def run_scan_task(app_instance, task_id: int, target_url: str, scan_type: str):
    """
    在后台线程中执行扫描任务
    
    Args:
        app_instance: Flask应用实例
        task_id: 扫描任务ID
        target_url: 目标URL
        scan_type: 扫描类型
    """
    with app_instance.app_context():
        try:
            # 获取任务
            task = ScanTask.query.get(task_id)
            if not task:
                return
            
            # 更新任务状态
            task.status = 'running'
            task.started_at = datetime.utcnow()
            db.session.commit()
            
            print(f"\n{'='*60}")
            print(f"开始扫描任务 #{task_id}")
            print(f"目标URL: {target_url}")
            print(f"扫描类型: {scan_type}")
            print(f"{'='*60}\n")
            
            # 目标可达性探测。URL 策略（协议白名单 / 私网拦截 / 主机白名单）
            # 在录入目标时就校验过，这里只确认"能不能连上、状态码值不值得继续扫"。
            print("验证目标URL可访问性...")
            settings = load_settings()
            try:
                import requests
                verify_response = requests.get(
                    target_url,
                    timeout=settings['http_timeout'],
                    verify=settings['tls_verify'],
                    allow_redirects=True,
                )
                verdict, message = classify_target_status(verify_response.status_code)
                if verdict == 'error':
                    # 非 RequestException，不会被下面三个 except 吞掉，直接终止任务
                    raise Exception(message)
                elif verdict == 'warn':
                    print(f"⚠️ 警告: {message}")
                else:
                    print(f"✓ {message}")

            except requests.exceptions.Timeout:
                raise Exception("目标URL连接超时，请检查网络或URL是否正确")
            except requests.exceptions.ConnectionError:
                raise Exception("无法连接到目标URL，请检查网址是否正确或网络是否畅通")
            except requests.exceptions.RequestException as e:
                raise Exception(f"访问目标URL失败: {str(e)}")
            
            # 执行扫描
            all_vulnerabilities = []
            
            # 根据扫描类型选择扫描器
            scanners = []
            if scan_type == 'all' or scan_type == 'sql_injection':
                scanners.append(SQLInjectionScanner())
            if scan_type == 'all' or scan_type == 'xss':
                scanners.append(XSSScanner())
            if scan_type == 'all' or scan_type == 'csrf':
                scanners.append(CSRFScanner())
            
            print(f"启动 {len(scanners)} 个扫描器...")
            
            # 执行所有扫描器
            for scanner in scanners:
                scanner_name = scanner.get_scanner_name()
                try:
                    print(f"→ 执行 {scanner_name} 扫描...")
                    vulns = scanner.scan(target_url)
                    print(f"  {scanner_name} 发现 {len(vulns)} 个漏洞")
                    all_vulnerabilities.extend(vulns)
                except Exception as e:
                    print(f"✗ {scanner_name} 执行失败: {str(e)}")
                    import traceback
                    traceback.print_exc()
                finally:
                    scanner.close()
            
            # 保存漏洞到数据库，并按 CVSS 基本分聚合任务风险
            base_scores = []
            for vuln_data in all_vulnerabilities:
                # 计算CVSS分数（按漏洞类型查预设 profile，见 evaluator/cvss_calculator.py）
                cvss_scores = CVSSCalculator.calculate_vulnerability_score(vuln_data['vuln_type'])
                base_scores.append(cvss_scores['base_score'])

                # 创建漏洞记录
                vuln = Vulnerability(
                    scan_id=task_id,
                    vuln_type=vuln_data['vuln_type'],
                    severity=cvss_scores['severity'],
                    title=vuln_data['title'],
                    description=vuln_data['description'],
                    location=vuln_data['location'],
                    cvss_base_score=cvss_scores['base_score'],
                    cvss_temporal_score=cvss_scores['temporal_score'],
                    cvss_environmental_score=cvss_scores['environmental_score'],
                    cvss_vector=cvss_scores['cvss_vector'],
                    evidence=vuln_data.get('evidence', ''),
                    recommendation=vuln_data.get('recommendation', '')
                )
                db.session.add(vuln)

            # 任务风险分 = 各漏洞 CVSS 基本分的算术平均（口径见 evaluator/risk.py）
            task.risk_score, task.risk_level = aggregate_risk_scores(base_scores)
            
            # 更新任务状态
            task.status = 'completed'
            task.completed_at = datetime.utcnow()
            db.session.commit()
            
            print(f"\n{'='*60}")
            print(f"✓ 扫描任务 #{task_id} 完成")
            print(f"  发现漏洞: {len(all_vulnerabilities)} 个")
            print(f"  风险评分: {task.risk_score}")
            print(f"  风险等级: {task.risk_level}")
            print(f"{'='*60}\n")
            
        except Exception as e:
            # 扫描失败
            print(f"\n{'='*60}")
            print(f"✗ 扫描任务 #{task_id} 失败")
            print(f"{'='*60}")
            print(f"错误原因: {str(e)}")
            print(f"{'='*60}\n")
            
            task = ScanTask.query.get(task_id)
            if task:
                task.status = 'failed'
                task.completed_at = datetime.utcnow()
                db.session.commit()
            
            # 打印详细错误堆栈（调试用）
            import traceback
            traceback.print_exc()


@scan_bp.route('/targets', methods=['GET'])
def get_targets():
    """获取所有扫描目标"""
    try:
        targets = ScanTarget.query.order_by(ScanTarget.created_at.desc()).all()
        return jsonify({
            'success': True,
            'data': [target.to_dict() for target in targets]
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


@scan_bp.route('/tasks/clear', methods=['DELETE'])
def clear_tasks():
    """批量清空扫描任务
    支持参数：
    - scope: 'recent' | 'all'，默认'recent'
    - limit: 当scope为'recent'时有效，默认5
    - target_id: 可选，仅清空指定目标的任务
    """
    try:
        scope = request.args.get('scope', 'recent')
        limit = request.args.get('limit', type=int) or 5
        target_id = request.args.get('target_id', type=int)

        query = ScanTask.query.order_by(ScanTask.created_at.desc())
        if target_id:
            query = query.filter_by(target_id=target_id)

        if scope == 'all':
            tasks = query.all()
        else:
            tasks = query.limit(limit).all()

        deleted = 0
        for task in tasks:
            db.session.delete(task)
            deleted += 1

        db.session.commit()

        return jsonify({
            'success': True,
            'deleted': deleted,
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


@scan_bp.route('/targets', methods=['POST'])
def create_target():
    """创建扫描目标"""
    try:
        # silent=True：没有 body / content-type 不对时返回 None 而不是抛 415，
        # 这样下面能给出明确的 400 提示，而不是被 except 兜成 500
        data = request.get_json(silent=True) or {}

        # 验证必填字段
        if not data.get('url'):
            return jsonify({
                'success': False,
                'message': '目标URL不能为空'
            }), 400

        # 录入时即做协议白名单 / 私网拦截 / 主机白名单校验，
        # 避免把 file://、内网地址之类的目标先存进库
        settings = load_settings()
        try:
            url = validate_target_url(
                data['url'],
                allow_private=not settings['block_private_targets'],
                allowed_hosts=settings['allowed_target_hosts'],
            )
        except TargetPolicyError as e:
            return jsonify({
                'success': False,
                'message': str(e)
            }), 400

        # 创建目标
        target = ScanTarget(
            url=url,
            name=data.get('name', ''),
            description=data.get('description', '')
        )
        
        db.session.add(target)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'data': target.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


@scan_bp.route('/targets/<int:target_id>', methods=['DELETE'])
def delete_target(target_id):
    """删除扫描目标"""
    try:
        target = ScanTarget.query.get(target_id)
        if not target:
            return jsonify({
                'success': False,
                'message': '目标不存在'
            }), 404
        
        db.session.delete(target)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '删除成功'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


@scan_bp.route('/start', methods=['POST'])
def start_scan():
    """启动扫描任务"""
    try:
        data = request.get_json(silent=True) or {}

        # 验证必填字段
        target_id = data.get('target_id')
        scan_type = data.get('scan_type', 'all')
        
        if not target_id:
            return jsonify({
                'success': False,
                'message': '目标ID不能为空'
            }), 400
        
        # 检查目标是否存在
        target = ScanTarget.query.get(target_id)
        if not target:
            return jsonify({
                'success': False,
                'message': '目标不存在'
            }), 404
        
        # 复用同一套策略：目标可能是策略收紧之前录入的旧数据
        settings = load_settings()
        try:
            validate_target_url(
                target.url,
                allow_private=not settings['block_private_targets'],
                allowed_hosts=settings['allowed_target_hosts'],
            )
        except TargetPolicyError as e:
            return jsonify({
                'success': False,
                'message': str(e)
            }), 400

        # 创建扫描任务
        task = ScanTask(
            target_id=target_id,
            scan_type=scan_type,
            status='pending'
        )
        
        db.session.add(task)
        db.session.commit()
        
        # 在后台线程中执行扫描
        thread = threading.Thread(
            target=run_scan_task,
            args=(current_app._get_current_object(), task.id, target.url, scan_type)
        )
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True,
            'data': task.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


@scan_bp.route('/tasks', methods=['GET'])
def get_tasks():
    """获取所有扫描任务"""
    try:
        # 支持按target_id过滤
        target_id = request.args.get('target_id', type=int)
        
        query = ScanTask.query
        if target_id:
            query = query.filter_by(target_id=target_id)
        
        tasks = query.order_by(ScanTask.created_at.desc()).all()
        
        return jsonify({
            'success': True,
            'data': [task.to_dict() for task in tasks]
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


@scan_bp.route('/tasks/<int:task_id>', methods=['GET'])
def get_task(task_id):
    """获取单个扫描任务详情"""
    try:
        task = ScanTask.query.get(task_id)
        if not task:
            return jsonify({
                'success': False,
                'message': '任务不存在'
            }), 404
        
        # 获取关联的目标和漏洞
        target = task.target
        vulnerabilities = task.vulnerabilities
        
        return jsonify({
            'success': True,
            'data': {
                **task.to_dict(),
                'target': target.to_dict() if target else None,
                'vulnerabilities': [vuln.to_dict() for vuln in vulnerabilities]
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


@scan_bp.route('/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    """获取所有漏洞"""
    try:
        # 支持按scan_id过滤
        scan_id = request.args.get('scan_id', type=int)
        
        query = Vulnerability.query
        if scan_id:
            query = query.filter_by(scan_id=scan_id)
        
        vulnerabilities = query.order_by(Vulnerability.created_at.desc()).all()
        
        return jsonify({
            'success': True,
            'data': [vuln.to_dict() for vuln in vulnerabilities]
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


@scan_bp.route('/statistics', methods=['GET'])
def get_statistics():
    """获取统计信息"""
    try:
        # 总扫描任务数
        total_scans = ScanTask.query.count()
        
        # 已完成扫描数
        completed_scans = ScanTask.query.filter_by(status='completed').count()
        
        # 总漏洞数
        total_vulnerabilities = Vulnerability.query.count()
        
        # 按严重程度统计漏洞
        severity_stats = db.session.query(
            Vulnerability.severity,
            db.func.count(Vulnerability.id)
        ).group_by(Vulnerability.severity).all()
        
        severity_dict = {severity: count for severity, count in severity_stats}
        
        # 按类型统计漏洞
        type_stats = db.session.query(
            Vulnerability.vuln_type,
            db.func.count(Vulnerability.id)
        ).group_by(Vulnerability.vuln_type).all()
        
        type_dict = {vuln_type: count for vuln_type, count in type_stats}
        
        return jsonify({
            'success': True,
            'data': {
                'total_scans': total_scans,
                'completed_scans': completed_scans,
                'total_vulnerabilities': total_vulnerabilities,
                'severity_distribution': severity_dict,
                'type_distribution': type_dict
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500
