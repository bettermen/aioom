"""
notifier.py - 通知与日志模块
支持终端彩色输出、结构化日志文件、Webhook 告警。
"""

import json
import logging
import time
import urllib.request
import urllib.error
from datetime import datetime
from typing import Optional

from ai_scorer import ScoreResult, Verdict
from killer import KillResult


class TerminalFormatter:
    """终端彩色输出"""

    # ANSI 颜色码
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"
    BOLD = "\033[1m"

    @staticmethod
    def color(text: str, color_code: str) -> str:
        return f"{color_code}{text}{TerminalFormatter.RESET}"

    @staticmethod
    def bold(text: str) -> str:
        return TerminalFormatter.color(text, TerminalFormatter.BOLD)

    @staticmethod
    def verdict_color(verdict: Verdict) -> str:
        colors = {
            Verdict.SAFE: TerminalFormatter.GREEN,
            Verdict.WATCH: TerminalFormatter.YELLOW,
            Verdict.TERM: TerminalFormatter.YELLOW,
            Verdict.KILL: TerminalFormatter.RED,
            Verdict.PROTECTED: TerminalFormatter.CYAN,
        }
        return colors.get(verdict, TerminalFormatter.RESET)


class Notifier:
    """通知与日志管理器"""

    def __init__(self, config):
        self.config = config
        self.logger = self._setup_logger()

    def _setup_logger(self) -> logging.Logger:
        """配置结构化日志"""
        logger = logging.getLogger("aioom")
        logger.setLevel(logging.DEBUG)

        # 避免重复 handler
        if logger.handlers:
            return logger

        # 控制台 handler
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%H:%M:%S"
        )
        console.setFormatter(formatter)
        logger.addHandler(console)

        # 文件 handler（如果配置了）
        if self.config.notify.log_file:
            try:
                file_handler = logging.FileHandler(
                    self.config.notify.log_file,
                    encoding="utf-8"
                )
                file_handler.setLevel(logging.DEBUG)
                file_formatter = logging.Formatter(
                    "%(asctime)s [%(levelname)s] %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S"
                )
                file_handler.setFormatter(file_formatter)
                logger.addHandler(file_handler)
            except (IOError, OSError) as e:
                logger.warning(f"无法创建日志文件: {e}")

        return logger

    def print_banner(self, version: str, dryrun: bool = False):
        """打印启动横幅"""
        t = TerminalFormatter
        print()
        print(t.color(f"  aioom v{version}  -  AI-Powered OOM Guardian", t.BOLD + t.BLUE))
        mode = t.color("[DRYRUN 模式]", t.YELLOW) if dryrun else t.color("[LIVE]", t.GREEN)
        print(f"  模式: {mode}")
        print(f"  内存阈值: {self.config.threshold.mem_percent}%  "
              f"Swap 阈值: {self.config.threshold.swap_percent}%")
        print(f"  TERM 阈值: {self.config.ai.term_confidence:.0%}  "
              f"KILL 阈值: {self.config.ai.kill_confidence:.0%}")
        if self.config.protect.ignore_patterns:
            print(f"  保护规则: {', '.join(self.config.protect.ignore_patterns[:5])}")
        print(t.color("  " + "-" * 50, t.GRAY))
        print()

    def print_status(self, mem_percent: float, mem_available_mb: float,
                     swap_percent: float, process_count: int):
        """打印实时状态栏"""
        t = TerminalFormatter

        # 内存状态颜色
        if mem_percent > self.config.threshold.mem_percent:
            mem_color = t.RED
        elif mem_percent > self.config.threshold.mem_percent - 10:
            mem_color = t.YELLOW
        else:
            mem_color = t.GREEN

        swap_color = t.RED if swap_percent > self.config.threshold.swap_percent else t.GREEN

        mem_bar_len = 30
        filled = int(mem_bar_len * mem_percent / 100)
        bar = t.color("\u2588" * filled, mem_color) + t.color("\u2591" * (mem_bar_len - filled), t.GRAY)

        line = (f"  MEM [{bar}] {t.color(f'{mem_percent:.1f}%', mem_color)} "
                f"({mem_available_mb:.0f}MB)  "
                f"SWAP {t.color(f'{swap_percent:.1f}%', swap_color)}  "
                f"PROCS {process_count}")
        # 覆盖当前行
        print(f"\r{line}", end="", flush=True)

    def print_clear_line(self):
        """清除状态栏"""
        print(f"\r{' ' * 80}", end="")

    def log_score_result(self, result: ScoreResult, verbose: bool = False):
        """记录 AI 评分结果"""
        t = TerminalFormatter
        v_color = t.verdict_color(result.verdict)
        verdict_str = t.color(result.verdict.value.upper(), v_color)

        msg = (f"  PID {result.pid:>6}  {result.name:<20}  "
               f"{verdict_str}  置信度 {result.confidence:.0%}")

        if result.is_leaking:
            msg += f"  {t.color('LEAK!', t.RED)}"
        if verbose:
            msg += f"  MEM趋势 {result.mem_trend_mb_s:+.2f}MB/s"

        print(msg)

        if verbose and result.reasons:
            for r in result.reasons:
                print(f"    {t.color('>', t.GRAY)} {r}")

    def log_kill_result(self, result: KillResult):
        """记录清理操作结果"""
        t = TerminalFormatter
        action_colors = {
            "kill": t.RED,
            "term": t.YELLOW,
            "term_then_kill": t.RED,
            "dryrun": t.CYAN,
            "skip": t.GRAY,
            "renice": t.BLUE,
        }
        color = action_colors.get(result.action, t.RESET)
        action_str = t.color(f"[{result.action.upper()}]", color)
        print(f"  {action_str} PID {result.pid} {result.name}: {result.message}")

    def send_webhook(self, kill_results: list):
        """发送 Webhook 告警"""
        if not self.config.notify.webhook_url:
            return

        payload = {
            "timestamp": datetime.now().isoformat(),
            "tool": "aioom",
            "events": [
                {
                    "pid": r.pid,
                    "name": r.name,
                    "action": r.action,
                    "success": r.success,
                    "message": r.message,
                }
                for r in kill_results
            ]
        }

        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.config.notify.webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                self.logger.debug(f"Webhook 发送成功: {resp.status}")
        except (urllib.error.URLError, TimeoutError) as e:
            self.logger.warning(f"Webhook 发送失败: {e}")
