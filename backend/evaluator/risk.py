"""任务级风险聚合：把 N 个漏洞的 CVSS 基本分折成一个任务风险分。

原实现把这段逻辑内联在 ``routes/scan_routes.py`` 的 ``run_scan_task`` 里，
和数据库写入、线程、HTTP 请求缠在一起，既没法单测也看不出口径。抽出来之后
口径就一句话：

    risk_score = round(平均(base_score), 1)
    risk_level = get_severity_rating(risk_score)   # 9.0/7.0/4.0 三档

注意这是**算术平均**，不是 max，也不是加权平均。后果是：一个 9.7 的 SQL 注入
加一个 4.3 的 Cookie 配置问题，报告上的任务风险分是 7.0（high），单看分数
会低估那条 SQL 注入。README 的「已知局限」里写了这条。

本模块只依赖 ``cvss_calculator``（标准库 + enum），可离线单测。
"""
from typing import Iterable, List, Tuple

from .cvss_calculator import CVSSCalculator


def aggregate_risk_scores(base_scores: Iterable[float]) -> Tuple[float, str]:
    """把一组 CVSS 基本分聚合为 ``(风险分, 风险等级)``。

    Args:
        base_scores: 各条漏洞的 CVSS 基本分（0–10）。

    Returns:
        ``(risk_score, risk_level)``；没有漏洞时返回 ``(0.0, 'low')``。
    """
    scores: List[float] = [float(score) for score in base_scores]
    if not scores:
        return 0.0, 'low'
    average = sum(scores) / len(scores)
    return round(average, 1), CVSSCalculator.get_severity_rating(average)
