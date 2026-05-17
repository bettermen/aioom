"""
config.py - 配置加载模块
从 TOML 文件加载配置，支持命令行参数覆盖
"""

import os
import sys
from dataclasses import dataclass, field
from typing import List, Optional

try:
    import tomllib
except ImportError:
    import tomli as tomllib


@dataclass
class ThresholdConfig:
    """阈值配置"""
    mem_percent: float = 85.0
    swap_percent: float = 80.0
    mem_abs_mb: Optional[float] = None


@dataclass
class AIConfig:
    """AI 决策配置"""
    term_confidence: float = 0.8
    kill_confidence: float = 0.95
    leak_window_sec: int = 30
    idle_cpu_threshold: float = 5.0


@dataclass
class ProtectConfig:
    """保护规则配置"""
    ignore_patterns: List[str] = field(default_factory=lambda: [
        "sshd", "bash", "zsh", "powershell", "explorer", "python.*aioom"
    ])
    ignore_root: bool = True
    protect_foreground: bool = True


@dataclass
class NotifyConfig:
    """通知配置"""
    log_file: str = "aioom.log"
    webhook_url: str = ""
    desktop_notify: bool = False
    verbose: bool = True


@dataclass
class Config:
    """全局配置"""
    threshold: ThresholdConfig = field(default_factory=ThresholdConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    protect: ProtectConfig = field(default_factory=ProtectConfig)
    notify: NotifyConfig = field(default_factory=NotifyConfig)
    interval: float = 2.0
    dryrun: bool = False


def load_config(config_path: Optional[str] = None) -> Config:
    """
    从 TOML 文件加载配置。
    如果 config_path 为 None，尝试在当前目录和脚本目录查找 config.toml。
    """
    config = Config()

    search_paths = []
    if config_path:
        search_paths.append(config_path)
    else:
        search_paths.append("config.toml")
        search_paths.append(os.path.join(os.path.dirname(__file__), "config.toml"))

    for path in search_paths:
        if os.path.exists(path):
            with open(path, "rb") as f:
                data = tomllib.load(f)

            # 阈值
            if "threshold" in data:
                t = data["threshold"]
                config.threshold.mem_percent = t.get("mem_percent", 85.0)
                config.threshold.swap_percent = t.get("swap_percent", 80.0)
                config.threshold.mem_abs_mb = t.get("mem_abs_mb", None)

            # AI
            if "ai" in data:
                a = data["ai"]
                config.ai.term_confidence = a.get("term_confidence", 0.8)
                config.ai.kill_confidence = a.get("kill_confidence", 0.95)
                config.ai.leak_window_sec = a.get("leak_window_sec", 30)
                config.ai.idle_cpu_threshold = a.get("idle_cpu_threshold", 5.0)

            # 保护
            if "protect" in data:
                p = data["protect"]
                config.protect.ignore_patterns = p.get("ignore_patterns", config.protect.ignore_patterns)
                config.protect.ignore_root = p.get("ignore_root", True)
                config.protect.protect_foreground = p.get("protect_foreground", True)

            # 通知
            if "notify" in data:
                n = data["notify"]
                config.notify.log_file = n.get("log_file", "")
                config.notify.webhook_url = n.get("webhook_url", "")
                config.notify.desktop_notify = n.get("desktop_notify", False)
                config.notify.verbose = n.get("verbose", True)

            return config

    # 没找到配置文件，使用默认值
    return config
