"""
CVSS评分计算器
基于CVSS 2.0标准实现漏洞风险评分
"""
from typing import Dict, Any
from enum import Enum


class AccessVector(Enum):
    """攻击途径"""
    LOCAL = 0.395
    ADJACENT_NETWORK = 0.646
    NETWORK = 1.0


class AccessComplexity(Enum):
    """攻击复杂度"""
    HIGH = 0.35
    MEDIUM = 0.61
    LOW = 0.71


class Authentication(Enum):
    """认证要求"""
    MULTIPLE = 0.45
    SINGLE = 0.56
    NONE = 0.704


class Impact(Enum):
    """影响程度"""
    NONE = 0.0
    PARTIAL = 0.275
    COMPLETE = 0.660


class Exploitability(Enum):
    """可利用性"""
    UNPROVEN = 0.85
    PROOF_OF_CONCEPT = 0.9
    FUNCTIONAL = 0.95
    HIGH = 1.0


class RemediationLevel(Enum):
    """修复措施"""
    OFFICIAL_FIX = 0.87
    TEMPORARY_FIX = 0.90
    WORKAROUND = 0.95
    UNAVAILABLE = 1.0


class ReportConfidence(Enum):
    """确认程度"""
    UNCONFIRMED = 0.90
    UNCORROBORATED = 0.95
    CONFIRMED = 1.0


class CVSSCalculator:
    """CVSS评分计算器"""
    
    @staticmethod
    def calculate_base_score(
        access_vector: AccessVector,
        access_complexity: AccessComplexity,
        authentication: Authentication,
        confidentiality_impact: Impact,
        integrity_impact: Impact,
        availability_impact: Impact
    ) -> float:
        """
        计算基本评价分数
        
        公式：BaseScore = round_to_1_decimal(
            ((0.6 * Impact) + (0.4 * Exploitability) - 1.5) * f(Impact)
        )
        
        其中：
        Impact = 10.41 * (1 - (1 - ConfImpact) * (1 - IntegImpact) * (1 - AvailImpact))
        Exploitability = 20 * AccessVector * AccessComplexity * Authentication
        f(Impact) = 0 if Impact = 0, 1.176 otherwise
        """
        # 计算影响分数
        impact = 10.41 * (
            1 - (1 - confidentiality_impact.value) * 
            (1 - integrity_impact.value) * 
            (1 - availability_impact.value)
        )
        
        # 计算可利用性分数
        exploitability = 20 * access_vector.value * access_complexity.value * authentication.value
        
        # 计算f(Impact)
        f_impact = 0 if impact == 0 else 1.176
        
        # 计算基本评价分数
        base_score = ((0.6 * impact) + (0.4 * exploitability) - 1.5) * f_impact
        
        # 四舍五入到1位小数
        return round(min(10.0, max(0.0, base_score)), 1)
    
    @staticmethod
    def calculate_temporal_score(
        base_score: float,
        exploitability: Exploitability,
        remediation_level: RemediationLevel,
        report_confidence: ReportConfidence
    ) -> float:
        """
        计算生命周期评价分数
        
        公式：TemporalScore = round_to_1_decimal(
            BaseScore * Exploitability * RemediationLevel * ReportConfidence
        )
        """
        temporal_score = (
            base_score * 
            exploitability.value * 
            remediation_level.value * 
            report_confidence.value
        )
        
        return round(min(10.0, max(0.0, temporal_score)), 1)
    
    @staticmethod
    def calculate_environmental_score(
        temporal_score: float,
        collateral_damage_potential: float = 0.0,  # 0-0.5
        target_distribution: float = 0.0  # 0-1.0
    ) -> float:
        """
        计算环境评价分数
        
        公式：EnvironmentalScore = round_to_1_decimal(
            (TemporalScore + (10 - TemporalScore) * CollateralDamagePotential) * TargetDistribution
        )
        
        Args:
            temporal_score: 生命周期评价分数
            collateral_damage_potential: 危害影响程度 (0-0.5)
            target_distribution: 目标分布范围 (0-1.0)
        """
        environmental_score = (
            (temporal_score + (10 - temporal_score) * collateral_damage_potential) * 
            target_distribution
        )
        
        return round(min(10.0, max(0.0, environmental_score)), 1)
    
    @staticmethod
    def get_severity_rating(score: float) -> str:
        """
        根据分数获取严重性等级
        
        Args:
            score: CVSS分数
            
        Returns:
            严重性等级：low, medium, high, critical
        """
        if score >= 9.0:
            return 'critical'
        elif score >= 7.0:
            return 'high'
        elif score >= 4.0:
            return 'medium'
        else:
            return 'low'
    
    @classmethod
    def calculate_vulnerability_score(cls, vuln_type: str) -> Dict[str, Any]:
        """
        根据漏洞类型自动计算CVSS分数
        
        Args:
            vuln_type: 漏洞类型
            
        Returns:
            包含CVSS评分的字典
        """
        # 预定义不同漏洞类型的CVSS参数
        vuln_profiles = {
            'SQL注入': {
                'access_vector': AccessVector.NETWORK,
                'access_complexity': AccessComplexity.LOW,
                'authentication': Authentication.NONE,
                'confidentiality_impact': Impact.COMPLETE,
                'integrity_impact': Impact.COMPLETE,
                'availability_impact': Impact.PARTIAL,
                'exploitability': Exploitability.FUNCTIONAL,
                'remediation_level': RemediationLevel.WORKAROUND,
                'report_confidence': ReportConfidence.CONFIRMED,
            },
            'SQL注入（疑似）': {
                'access_vector': AccessVector.NETWORK,
                'access_complexity': AccessComplexity.MEDIUM,
                'authentication': Authentication.NONE,
                'confidentiality_impact': Impact.PARTIAL,
                'integrity_impact': Impact.PARTIAL,
                'availability_impact': Impact.NONE,
                'exploitability': Exploitability.PROOF_OF_CONCEPT,
                'remediation_level': RemediationLevel.WORKAROUND,
                'report_confidence': ReportConfidence.UNCORROBORATED,
            },
            'XSS（跨站脚本）': {
                'access_vector': AccessVector.NETWORK,
                'access_complexity': AccessComplexity.MEDIUM,
                'authentication': Authentication.NONE,
                'confidentiality_impact': Impact.PARTIAL,
                'integrity_impact': Impact.PARTIAL,
                'availability_impact': Impact.NONE,
                'exploitability': Exploitability.FUNCTIONAL,
                'remediation_level': RemediationLevel.WORKAROUND,
                'report_confidence': ReportConfidence.CONFIRMED,
            },
            'CSRF（跨站请求伪造）': {
                'access_vector': AccessVector.NETWORK,
                'access_complexity': AccessComplexity.MEDIUM,
                'authentication': Authentication.NONE,
                'confidentiality_impact': Impact.PARTIAL,
                'integrity_impact': Impact.PARTIAL,
                'availability_impact': Impact.PARTIAL,
                'exploitability': Exploitability.FUNCTIONAL,
                'remediation_level': RemediationLevel.WORKAROUND,
                'report_confidence': ReportConfidence.CONFIRMED,
            },
            'CSRF防护不足': {
                'access_vector': AccessVector.NETWORK,
                'access_complexity': AccessComplexity.MEDIUM,
                'authentication': Authentication.NONE,
                'confidentiality_impact': Impact.NONE,
                'integrity_impact': Impact.PARTIAL,
                'availability_impact': Impact.NONE,
                'exploitability': Exploitability.PROOF_OF_CONCEPT,
                'remediation_level': RemediationLevel.WORKAROUND,
                'report_confidence': ReportConfidence.CONFIRMED,
            },
        }
        
        # 获取漏洞配置文件，如果没有则使用默认值
        profile = vuln_profiles.get(vuln_type, {
            'access_vector': AccessVector.NETWORK,
            'access_complexity': AccessComplexity.MEDIUM,
            'authentication': Authentication.NONE,
            'confidentiality_impact': Impact.PARTIAL,
            'integrity_impact': Impact.PARTIAL,
            'availability_impact': Impact.PARTIAL,
            'exploitability': Exploitability.FUNCTIONAL,
            'remediation_level': RemediationLevel.WORKAROUND,
            'report_confidence': ReportConfidence.CONFIRMED,
        })
        
        # 计算基本评价分数
        base_score = cls.calculate_base_score(
            profile['access_vector'],
            profile['access_complexity'],
            profile['authentication'],
            profile['confidentiality_impact'],
            profile['integrity_impact'],
            profile['availability_impact']
        )
        
        # 计算生命周期评价分数
        temporal_score = cls.calculate_temporal_score(
            base_score,
            profile['exploitability'],
            profile['remediation_level'],
            profile['report_confidence']
        )
        
        # 计算环境评价分数（使用默认值）
        environmental_score = cls.calculate_environmental_score(
            temporal_score,
            collateral_damage_potential=0.3,  # 中等危害影响
            target_distribution=0.75  # 较高分布范围
        )
        
        # 获取严重性等级
        severity = cls.get_severity_rating(base_score)
        
        # 构造CVSS向量字符串
        cvss_vector = (
            f"AV:{profile['access_vector'].name[0]}/"
            f"AC:{profile['access_complexity'].name[0]}/"
            f"Au:{profile['authentication'].name[0]}/"
            f"C:{profile['confidentiality_impact'].name[0]}/"
            f"I:{profile['integrity_impact'].name[0]}/"
            f"A:{profile['availability_impact'].name[0]}"
        )
        
        return {
            'base_score': base_score,
            'temporal_score': temporal_score,
            'environmental_score': environmental_score,
            'severity': severity,
            'cvss_vector': cvss_vector
        }
