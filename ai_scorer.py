"""
ai_scorer.py - AI 智能决策引擎
核心差异化模块：进程意图识别 + 内存泄漏检测 + 置信度打分。

决策逻辑：
1. 进程行为画像（CPU 趋势、IO 频率、线程数变化）
2. 前台交互检测（进程是否有活跃的 CPU/IO 行为）
3. 内存泄漏检测（内存是否持续单调递增）
4. 综合置信度打分（0~1），超过阈值则触发清理
"""

import re
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from enum import Enum

from collector import ProcessSnapshot, SystemSnapshot


class Verdict(Enum):
    """AI 判决结果"""
    SAFE = "safe"                # 安全，不处理
    WATCH = "watch"              # 观察，不处理
    TERM = "term"                # 建议优雅终止
    KILL = "kill"                # 建议强制杀死
    PROTECTED = "protected"      # 受保护进程


@dataclass
class ScoreResult:
    """AI 打分结果"""
    pid: int
    name: str
    verdict: Verdict
    confidence: float            # 0.0 ~ 1.0
    is_leaking: bool             # 是否存在内存泄漏
    is_foreground: bool          # 是否前台交互进程
    mem_trend_mb_s: float        # 内存增长趋势 (MB/s)
    cpu_trend_p_s: float         # CPU 变化趋势 (%/s)
    reasons: List[str] = field(default_factory=list)

    @property
    def should_act(self) -> bool:
        return self.verdict in (Verdict.TERM, Verdict.KILL)


class AIScorer:
    """AI 智能决策引擎"""

    def __init__(self, config):
        self.config = config
        self._ignore_patterns = [re.compile(p, re.IGNORECASE)
                                  for p in config.protect.ignore_patterns]

    def is_protected(self, proc: ProcessSnapshot) -> bool:
        """检查进程是否在保护列表中"""
        for pattern in self._ignore_patterns:
            if pattern.search(proc.name) or pattern.search(proc.cmdline):
                return True
        return False

    def is_root_process(self, proc: ProcessSnapshot) -> bool:
        """检查是否是 root/system 用户进程"""
        if not self.config.protect.ignore_root:
            return False
        username = proc.username.lower()
        return any(u in username for u in ("root", "system", "nt authority"))

    def detect_foreground(self, proc: ProcessSnapshot) -> bool:
        """
        检测进程是否是前台交互进程。
        综合判断：CPU 活跃度 + IO 活动 + 线程数
        """
        cpu_active = proc.cpu_percent > self.config.ai.idle_cpu_threshold
        high_threads = proc.num_threads > 10
        recent_io = proc.io_read_mb + proc.io_write_mb > 1.0

        # CPU 持续有活动 = 很可能在交互
        if cpu_active and high_threads:
            return True

        # 有明显 IO = 用户可能在读写文件
        if recent_io and cpu_active:
            return True

        return False

    def detect_leak(self, proc: ProcessSnapshot) -> Tuple[bool, float]:
        """
        检测内存泄漏。
        返回 (is_leaking, leak_score)。
        判断标准：内存持续增长 + 增长斜率 > 0.5 MB/s
        """
        if proc.mem_trend is None or proc.mem_trend <= 0:
            return False, 0.0

        leak_rate = proc.mem_trend  # MB/s
        window = self.config.ai.leak_window_sec

        # 根据泄漏速率计算严重程度
        # 0.5 MB/s = 轻微, 2 MB/s = 中等, 5+ MB/s = 严重
        if leak_rate < 0.5:
            return False, 0.0
        elif leak_rate < 2.0:
            score = 0.3 + (leak_rate - 0.5) * 0.23  # 0.3 ~ 0.63
            return True, min(score, 1.0)
        elif leak_rate < 5.0:
            score = 0.6 + (leak_rate - 2.0) * 0.13  # 0.6 ~ 0.85
            return True, min(score, 1.0)
        else:
            return True, min(0.85 + leak_rate * 0.01, 1.0)

    def compute_idle_score(self, proc: ProcessSnapshot) -> float:
        """
        计算进程"空闲"得分（0~1），越高越空闲。
        综合考虑 CPU、IO、线程活动。
        """
        idle_score = 0.0

        # CPU 空闲贡献（0~0.4）
        if proc.cpu_percent < 1.0:
            idle_score += 0.4
        elif proc.cpu_percent < self.config.ai.idle_cpu_threshold:
            idle_score += 0.4 * (1 - proc.cpu_percent / self.config.ai.idle_cpu_threshold)

        # CPU 持续下降趋势贡献（0~0.2）
        if proc.cpu_trend is not None and proc.cpu_trend < -0.5:
            idle_score += min(0.2, abs(proc.cpu_trend) * 0.1)

        # IO 低贡献（0~0.2）
        total_io = proc.io_read_mb + proc.io_write_mb
        if total_io < 0.1:
            idle_score += 0.2
        elif total_io < 1.0:
            idle_score += 0.1

        # 线程少贡献（0~0.2）
        if proc.num_threads <= 1:
            idle_score += 0.2
        elif proc.num_threads <= 5:
            idle_score += 0.1

        return min(idle_score, 1.0)

    def score_process(self, proc: ProcessSnapshot, system: SystemSnapshot) -> ScoreResult:
        """
        对单个进程进行综合打分。

        决策权重：
        - 泄漏得分: 40%
        - 空闲得分: 30%
        - 内存占比: 20%
        - 进程年龄: 10%
        """
        reasons = []

        # 1. 保护检查
        if self.is_protected(proc):
            return ScoreResult(
                pid=proc.pid, name=proc.name,
                verdict=Verdict.PROTECTED, confidence=0.0,
                is_leaking=False, is_foreground=False,
                mem_trend_mb_s=proc.mem_trend or 0.0,
                cpu_trend_p_s=proc.cpu_trend or 0.0,
                reasons=["命中保护规则"]
            )

        if self.is_root_process(proc):
            return ScoreResult(
                pid=proc.pid, name=proc.name,
                verdict=Verdict.PROTECTED, confidence=0.0,
                is_leaking=False, is_foreground=False,
                mem_trend_mb_s=proc.mem_trend or 0.0,
                cpu_trend_p_s=proc.cpu_trend or 0.0,
                reasons=["系统/Root 进程"]
            )

        # 2. 前台检测
        is_fg = self.detect_foreground(proc)
        if is_fg and self.config.protect.protect_foreground:
            return ScoreResult(
                pid=proc.pid, name=proc.name,
                verdict=Verdict.PROTECTED, confidence=0.0,
                is_leaking=False, is_foreground=True,
                mem_trend_mb_s=proc.mem_trend or 0.0,
                cpu_trend_p_s=proc.cpu_trend or 0.0,
                reasons=["前台交互进程"]
            )

        # 3. 泄漏检测
        is_leaking, leak_score = self.detect_leak(proc)
        if is_leaking:
            reasons.append(f"内存泄漏趋势: {proc.mem_trend:.2f} MB/s")

        # 4. 空闲评分
        idle_score = self.compute_idle_score(proc)
        if idle_score > 0.5:
            reasons.append(f"进程空闲度: {idle_score:.0%}")

        # 5. 内存占比评分
        mem_score = min(proc.mem_percent / 10.0, 1.0)  # 占 10%+ 内存 = 满分
        if proc.mem_percent > 5.0:
            reasons.append(f"内存占用高: {proc.mem_percent:.1f}%")

        # 6. 进程年龄评分（越老越容易被清理，但权重低）
        age_score = 0.0
        if proc.create_time > 0:
            age_sec = time.time() - proc.create_time
            if age_sec > 3600:  # 1小时以上
                age_score = min(age_sec / 86400, 1.0)  # 24h 满分
                reasons.append(f"进程已运行: {age_sec / 3600:.1f}h")

        # 综合置信度
        confidence = (
            leak_score * 0.40 +
            idle_score * 0.30 +
            mem_score * 0.20 +
            age_score * 0.10
        )

        # 确定判决
        verdict = Verdict.SAFE
        if confidence < 0.3:
            verdict = Verdict.SAFE
            reasons.append("综合得分较低，安全")
        elif confidence < self.config.ai.term_confidence:
            verdict = Verdict.WATCH
            reasons.append(f"综合得分 {confidence:.0%}，继续观察")
        elif confidence < self.config.ai.kill_confidence:
            verdict = Verdict.TERM
            reasons.append(f"建议优雅终止（置信度 {confidence:.0%}）")
        else:
            verdict = Verdict.KILL
            reasons.append(f"建议强制终止（置信度 {confidence:.0%}）")

        return ScoreResult(
            pid=proc.pid, name=proc.name,
            verdict=verdict, confidence=confidence,
            is_leaking=is_leaking, is_foreground=is_fg,
            mem_trend_mb_s=proc.mem_trend or 0.0,
            cpu_trend_p_s=proc.cpu_trend or 0.0,
            reasons=reasons,
        )

    def evaluate_all(self, processes: List[ProcessSnapshot],
                     system: SystemSnapshot) -> List[ScoreResult]:
        """对所有进程进行 AI 评估，按置信度降序返回"""
        results = []
        for proc in processes:
            result = self.score_process(proc, system)
            results.append(result)

        # 按置信度降序排列
        results.sort(key=lambda r: r.confidence, reverse=True)
        return results
