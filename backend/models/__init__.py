"""
数据模型模块初始化
"""
from .database import db, ScanTarget, ScanTask, Vulnerability

__all__ = ['db', 'ScanTarget', 'ScanTask', 'Vulnerability']
