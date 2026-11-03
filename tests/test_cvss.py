"""CVSS 2.0 评分与任务级风险聚合的单元测试。

数值全部是跑出来的真值（不是从文档抄的）：文档里写的 "SQL 注入 7.5 分"
是旧版本口径，当前实现是 9.7 —— 测试锁的是代码，不是文档。
"""
import unittest

from evaluator.cvss_calculator import (
    AccessComplexity,
    AccessVector,
    Authentication,
    CVSSCalculator,
    Exploitability,
    Impact,
    RemediationLevel,
    ReportConfidence,
)
from evaluator.risk import aggregate_risk_scores


class BaseScoreTest(unittest.TestCase):
    """基本评分：Impact / Exploitability 两段公式。"""

    def test_sql_injection_profile_is_9_7(self):
        result = CVSSCalculator.calculate_vulnerability_score('SQL注入')
        self.assertEqual(result['base_score'], 9.7)
        self.assertEqual(result['severity'], 'critical')
        self.assertEqual(result['cvss_vector'], 'AV:N/AC:L/Au:N/C:C/I:C/A:P')

    def test_xss_profile_is_medium(self):
        # 扫描器内部把 XSS 标成 severity='high'，但落库用的是 CVSS 分级，
        # 结果是 medium —— 这个"两个 severity 打架"的行为在这里被固定下来。
        result = CVSSCalculator.calculate_vulnerability_score('XSS（跨站脚本）')
        self.assertEqual(result['base_score'], 5.8)
        self.assertEqual(result['severity'], 'medium')

    def test_csrf_profiles(self):
        csrf = CVSSCalculator.calculate_vulnerability_score('CSRF（跨站请求伪造）')
        weak = CVSSCalculator.calculate_vulnerability_score('CSRF防护不足')
        self.assertEqual(csrf['base_score'], 6.8)
        self.assertEqual(weak['base_score'], 4.3)
        self.assertEqual(weak['cvss_vector'], 'AV:N/AC:M/Au:N/C:N/I:P/A:N')

    def test_suspected_sqli_is_medium(self):
        result = CVSSCalculator.calculate_vulnerability_score('SQL注入（疑似）')
        self.assertEqual(result['base_score'], 5.8)
        self.assertEqual(result['severity'], 'medium')

    def test_unknown_type_falls_back_to_default_profile(self):
        result = CVSSCalculator.calculate_vulnerability_score('某种没见过的漏洞')
        self.assertEqual(result['base_score'], 6.8)

    def test_zero_impact_scores_zero(self):
        score = CVSSCalculator.calculate_base_score(
            AccessVector.NETWORK,
            AccessComplexity.LOW,
            Authentication.NONE,
            Impact.NONE,
            Impact.NONE,
            Impact.NONE,
        )
        self.assertEqual(score, 0.0)

    def test_manual_formula_matches(self):
        # Impact = 10.41*(1-(1-C)(1-I)(1-A))，Exploitability = 20*AV*AC*Au
        impact = 10.41 * (1 - (1 - 0.660) * (1 - 0.660) * (1 - 0.275))
        exploitability = 20 * 1.0 * 0.71 * 0.704
        expected = round((0.6 * impact + 0.4 * exploitability - 1.5) * 1.176, 1)
        actual = CVSSCalculator.calculate_base_score(
            AccessVector.NETWORK,
            AccessComplexity.LOW,
            Authentication.NONE,
            Impact.COMPLETE,
            Impact.COMPLETE,
            Impact.PARTIAL,
        )
        self.assertEqual(actual, expected)

    def test_vector_is_built_from_enum_initials(self):
        # 向量字符串靠 Enum 成员名的首字母拼出来（NETWORK -> N，COMPLETE -> C）。
        # 这条测试锁住这个隐含约定：谁改了枚举成员名，向量就废了。
        self.assertEqual(AccessVector.ADJACENT_NETWORK.name[0], 'A')
        self.assertEqual(AccessComplexity.HIGH.name[0], 'H')
        self.assertEqual(Authentication.SINGLE.name[0], 'S')
        self.assertEqual(Impact.PARTIAL.name[0], 'P')


class TemporalAndEnvironmentalTest(unittest.TestCase):
    """生命周期 / 环境评分：三层乘法链。"""

    def test_temporal_chain_for_sqli(self):
        temporal = CVSSCalculator.calculate_temporal_score(
            9.7,
            Exploitability.FUNCTIONAL,      # 0.95
            RemediationLevel.WORKAROUND,    # 0.95
            ReportConfidence.CONFIRMED,     # 1.00
        )
        self.assertEqual(temporal, 8.8)

    def test_environmental_chain_for_sqli(self):
        environmental = CVSSCalculator.calculate_environmental_score(
            8.8,
            collateral_damage_potential=0.3,
            target_distribution=0.75,
        )
        self.assertEqual(environmental, 6.9)

    def test_temporal_is_clamped_to_ten(self):
        self.assertEqual(
            CVSSCalculator.calculate_temporal_score(
                10.0,
                Exploitability.HIGH,
                RemediationLevel.UNAVAILABLE,
                ReportConfidence.CONFIRMED,
            ),
            10.0,
        )


class SeverityRatingTest(unittest.TestCase):
    """分级阈值：>=9 critical / >=7 high / >=4 medium / 其余 low。"""

    def test_thresholds(self):
        cases = [
            (10.0, 'critical'),
            (9.0, 'critical'),
            (8.9, 'high'),
            (7.0, 'high'),
            (6.9, 'medium'),
            (4.0, 'medium'),
            (3.9, 'low'),
            (0.0, 'low'),
        ]
        for score, expected in cases:
            with self.subTest(score=score):
                self.assertEqual(CVSSCalculator.get_severity_rating(score), expected)


class RiskAggregationTest(unittest.TestCase):
    """任务风险分 = 算术平均，等级用**未取整**的平均值判定。"""

    def test_no_vulnerabilities(self):
        self.assertEqual(aggregate_risk_scores([]), (0.0, 'low'))

    def test_single_vulnerability(self):
        self.assertEqual(aggregate_risk_scores([9.7]), (9.7, 'critical'))

    def test_average_dilutes_a_critical_finding(self):
        # 9.7 的 SQL 注入 + 4.3 的 Cookie 问题 -> 7.0 high。
        # 单看任务分就会低估那条注入，这是平均口径的已知缺陷。
        self.assertEqual(aggregate_risk_scores([9.7, 4.3]), (7.0, 'high'))

    def test_medium_findings_stay_medium(self):
        self.assertEqual(aggregate_risk_scores([5.8, 5.8]), (5.8, 'medium'))

    def test_level_uses_unrounded_average(self):
        # 平均 8.995 -> 展示成 9.0，但等级按 8.995 判成 high，
        # 于是会出现"分数 9.0 却显示高危"的不一致。行为如此，先锁住。
        score, level = aggregate_risk_scores([9.0, 8.99])
        self.assertEqual(score, 9.0)
        self.assertEqual(level, 'high')


if __name__ == '__main__':
    unittest.main()
