"""
数据库模型定义
包含：扫描目标、扫描任务、漏洞记录等
"""
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class ScanTarget(db.Model):
    """扫描目标表"""
    __tablename__ = 'scan_targets'
    
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    name = db.Column(db.String(200))
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # 关联扫描任务
    scans = db.relationship('ScanTask', backref='target', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'url': self.url,
            'name': self.name,
            'description': self.description,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class ScanTask(db.Model):
    """扫描任务表"""
    __tablename__ = 'scan_tasks'
    
    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey('scan_targets.id'), nullable=False)
    status = db.Column(db.String(50), default='pending')  # pending, running, completed, failed
    scan_type = db.Column(db.String(100))  # 扫描类型：all, sql_injection, xss, csrf等
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 评估结果
    risk_score = db.Column(db.Float)  # CVSS总评分
    risk_level = db.Column(db.String(50))  # 风险等级：low, medium, high
    
    # 关联漏洞记录
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'target_id': self.target_id,
            'target_name': self.target.name if self.target else '',
            'target_url': self.target.url if self.target else '',
            'status': self.status,
            'scan_type': self.scan_type,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'risk_score': self.risk_score,
            'risk_level': self.risk_level,
            'vulnerabilities_count': len(self.vulnerabilities) if self.vulnerabilities else 0
        }


class Vulnerability(db.Model):
    """漏洞记录表"""
    __tablename__ = 'vulnerabilities'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan_tasks.id'), nullable=False)
    
    # 漏洞基本信息
    vuln_type = db.Column(db.String(100), nullable=False)  # SQL注入、XSS、CSRF等
    severity = db.Column(db.String(50))  # 严重程度：low, medium, high, critical
    title = db.Column(db.String(500))
    description = db.Column(db.Text)
    location = db.Column(db.String(1000))  # 漏洞位置（URL、参数等）
    
    # CVSS评分相关
    cvss_base_score = db.Column(db.Float)  # 基本评价分数
    cvss_temporal_score = db.Column(db.Float)  # 生命周期评价分数
    cvss_environmental_score = db.Column(db.Float)  # 环境评价分数
    cvss_vector = db.Column(db.String(200))  # CVSS向量字符串
    
    # 漏洞详情
    evidence = db.Column(db.Text)  # 漏洞证据
    recommendation = db.Column(db.Text)  # 修复建议
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'vuln_type': self.vuln_type,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'location': self.location,
            'cvss_base_score': self.cvss_base_score,
            'cvss_temporal_score': self.cvss_temporal_score,
            'cvss_environmental_score': self.cvss_environmental_score,
            'cvss_vector': self.cvss_vector,
            'evidence': self.evidence,
            'recommendation': self.recommendation,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
