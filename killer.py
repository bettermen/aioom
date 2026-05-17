"""
killer.py - 策略执行模块
负责实际的进程清理操作：SIGTERM、SIGKILL、降优先级等。
所有危险操作受 dryrun 模式保护。
"""

import os
import signal
import time
import platform
from dataclasses import dataclass
from typing import List, Optional

import psutil

from ai_scorer import ScoreResult, Verdict


@dataclass
class KillResult:
    """清理操作结果"""
    pid: int
    name: str
    action: str            # "term", "kill", "renice", "skip", "dryrun"
    success: bool
    message: str


class Killer:
    """进程清理执行器"""

    def __init__(self, dryrun: bool = False):
        self.dryrun = dryrun
        self.system = platform.system()

    def send_term(self, pid: int) -> bool:
        """发送 SIGTERM（优雅终止）"""
        try:
            proc = psutil.Process(pid)
            if self.system == "Windows":
                proc.terminate()
            else:
                os.kill(pid, signal.SIGTERM)
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, ProcessLookupError) as e:
            return False

    def send_kill(self, pid: int) -> bool:
        """发送 SIGKILL（强制终止）"""
        try:
            proc = psutil.Process(pid)
            proc.kill()
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, ProcessLookupError) as e:
            return False

    def renice(self, pid: int, nice: int = 10) -> bool:
        """降低进程优先级"""
        try:
            proc = psutil.Process(pid)
            if self.system == "Windows":
                proc.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
            else:
                proc.nice(nice)
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return False

    def is_alive(self, pid: int) -> bool:
        """检查进程是否存活"""
        try:
            return psutil.Process(pid).is_running()
        except (psutil.NoSuchProcess, ProcessLookupError):
            return False

    def execute(self, result: ScoreResult) -> KillResult:
        """
        根据 AI 评分结果执行对应操作。
        """
        if self.dryrun:
            if result.should_act:
                return KillResult(
                    pid=result.pid,
                    name=result.name,
                    action="dryrun",
                    success=True,
                    message=f"[DRYRUN] 将执行 {result.verdict.value} "
                            f"(置信度 {result.confidence:.0%})"
                )
            return KillResult(
                pid=result.pid, name=result.name,
                action="skip", success=True,
                message=f"[DRYRUN] 跳过：{result.verdict.value}"
            )

        # 根据判决执行
        if result.verdict == Verdict.KILL:
            success = self.send_kill(result.pid)
            return KillResult(
                pid=result.pid, name=result.name,
                action="kill", success=success,
                message=f"强制终止: {'成功' if success else '失败'}"
            )

        elif result.verdict == Verdict.TERM:
            success = self.send_term(result.pid)
            # 等 5 秒后检查是否已终止
            if success:
                time.sleep(5)
                if self.is_alive(result.pid):
                    # 仍然存活，升级为 KILL
                    self.send_kill(result.pid)
                    return KillResult(
                        pid=result.pid, name=result.name,
                        action="term_then_kill", success=True,
                        message="SIGTERM 5s 后未退出，已升级 SIGKILL"
                    )
            return KillResult(
                pid=result.pid, name=result.name,
                action="term", success=success,
                message=f"优雅终止: {'成功' if success else '失败'}"
            )

        else:
            return KillResult(
                pid=result.pid, name=result.name,
                action="skip", success=True,
                message=f"跳过（{result.verdict.value}）"
            )

    def execute_batch(self, results: List[ScoreResult],
                      max_kills: int = 3) -> List[KillResult]:
        """
        批量执行清理操作，每次最多清理 max_kills 个进程。
        从置信度最高到最低执行。
        """
        actionable = [r for r in results if r.should_act][:max_kills]
        outcomes = []

        for result in actionable:
            outcome = self.execute(result)
            outcomes.append(outcome)

            # 执行后短暂等待，观察内存是否恢复
            if outcome.success and not self.dryrun:
                time.sleep(2)

        return outcomes
