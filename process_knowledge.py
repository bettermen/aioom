"""
process_knowledge.py - 进程智能百科
为常见进程提供用途描述、终止影响、分类信息。
从进程名和 cmdline 模糊匹配，返回百科条目。
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class KnowledgeEntry:
    """进程百科条目"""
    name: str              # 显示名称
    patterns: List[str]    # 匹配模式（正则）
    category: str          # 分类：system/browser/dev/communication/media/utility/game/ai/security/other
    description: str       # 进程用途
    kill_impact: str       # 终止影响
    recommendation: str    # 建议：safe/caution/danger
    emoji: str             # 分类图标


# 百科数据库
KNOWLEDGE_BASE: List[KnowledgeEntry] = [
    # ===== 系统核心 =====
    KnowledgeEntry(
        name="Windows 桌面管理器",
        patterns=["explorer\\.exe"],
        category="system",
        description="Windows 桌面外壳程序，管理任务栏、开始菜单、文件资源管理器。",
        kill_impact="桌面和任务栏会消失并重启，可能导致所有打开的文件资源管理器窗口关闭。",
        recommendation="danger",
        emoji="🖥️",
    ),
    KnowledgeEntry(
        name="Windows Desktop Window Manager",
        patterns=["dwm\\.exe"],
        category="system",
        description="Windows 桌面窗口管理器，负责窗口动画、透明效果和 3D 加速渲染。",
        kill_impact="屏幕会黑屏闪烁，然后自动重启。可能导致所有窗口的视觉效果暂时失效。",
        recommendation="danger",
        emoji="🖼️",
    ),
    KnowledgeEntry(
        name="Windows 服务主机",
        patterns=["svchost\\.exe"],
        category="system",
        description="Windows 服务宿主进程，承载大量系统服务（DNS、更新、网络等）。",
        kill_impact="可能导致网络断开、Windows 更新中断、蓝牙失效等功能异常。",
        recommendation="danger",
        emoji="⚙️",
    ),
    KnowledgeEntry(
        name="Windows 注册表",
        patterns=["regedit", "reg\\.exe"],
        category="system",
        description="Windows 注册表编辑器/命令行工具，管理系统配置。",
        kill_impact="无影响，仅关闭编辑器窗口。",
        recommendation="safe",
        emoji="📋",
    ),
    KnowledgeEntry(
        name="Windows Shell",
        patterns=["powershell", "pwsh", "cmd\\.exe", "conhost"],
        category="system",
        description="Windows 命令行环境（PowerShell/CMD），用于执行脚本和系统管理。",
        kill_impact="正在运行的脚本或命令会被中断，可能导致操作未完成。",
        recommendation="caution",
        emoji="💻",
    ),
    KnowledgeEntry(
        name="Windows 安全中心",
        patterns=["SecurityHealthService", "MsMpEng", "SecurityHealthSystray"],
        category="security",
        description="Windows Defender 安全中心服务，负责实时保护和恶意软件扫描。",
        kill_impact="实时病毒保护将暂时失效，系统安全风险增加。",
        recommendation="danger",
        emoji="🛡️",
    ),
    KnowledgeEntry(
        name="Windows Update",
        patterns=["wuauserv", "usoclient", "UpdateOrchestrator", "UsoClient"],
        category="system",
        description="Windows 自动更新服务，负责下载和安装系统更新。",
        kill_impact="正在进行的更新可能中断，下次启动时需重新下载。",
        recommendation="safe",
        emoji="📦",
    ),
    KnowledgeEntry(
        name="任务管理器",
        patterns=["Taskmgr"],
        category="system",
        description="Windows 任务管理器，用于查看和结束进程。",
        kill_impact="仅关闭任务管理器窗口，不影响其他进程。",
        recommendation="safe",
        emoji="📊",
    ),
    KnowledgeEntry(
        name="Windows 运行时",
        patterns=["runtimebroker", "sihost", "taskhostw", "ctfmon"],
        category="system",
        description="Windows 后台运行时进程，处理拖拽剪贴板、任务调度等。",
        kill_impact="少量 UI 功能可能暂时失效（如剪贴板、拖拽），会自动重启。",
        recommendation="caution",
        emoji="🔧",
    ),

    # ===== WSL / Linux =====
    KnowledgeEntry(
        name="WSL 主机进程",
        patterns=["wslhost", r"wsl\.exe", "wslservice"],
        category="system",
        description="Windows Subsystem for Linux 主机进程，运行 Linux 发行版。",
        kill_impact="WSL 中运行的所有 Linux 进程和容器将立即终止。",
        recommendation="caution",
        emoji="🐧",
    ),
    KnowledgeEntry(
        name="WSL 虚拟机",
        patterns=["vmmem", "vmmem-wsl"],
        category="system",
        description="WSL2 虚拟机内存管理进程，WSL 分配的所有内存都走这个进程。",
        kill_impact="等价于强制关机 WSL2 虚拟机，所有 Linux 进程和 Docker 容器会终止。",
        recommendation="caution",
        emoji="🐧",
    ),
    KnowledgeEntry(
        name="SSH 守护进程",
        patterns=["sshd"],
        category="system",
        description="SSH 服务器守护进程，允许远程安全登录。",
        kill_impact="所有 SSH 连接将断开，远程用户无法登录。",
        recommendation="danger",
        emoji="🔐",
    ),

    # ===== 浏览器 =====
    KnowledgeEntry(
        name="Google Chrome",
        patterns=["chrome", "chromium"],
        category="browser",
        description="Google Chrome 浏览器，多进程架构（每个标签页一个进程）。",
        kill_impact="所有打开的网页和未保存的表单数据将丢失。子进程可单独终止对应标签页。",
        recommendation="safe",
        emoji="🌐",
    ),
    KnowledgeEntry(
        name="Microsoft Edge",
        patterns=["msedge"],
        category="browser",
        description="Microsoft Edge 浏览器，基于 Chromium 内核。",
        kill_impact="所有打开的网页和未保存的表单数据将丢失。",
        recommendation="safe",
        emoji="🌐",
    ),
    KnowledgeEntry(
        name="Firefox",
        patterns=["firefox"],
        category="browser",
        description="Mozilla Firefox 浏览器。",
        kill_impact="所有打开的网页和未保存的表单数据将丢失。",
        recommendation="safe",
        emoji="🦊",
    ),

    # ===== 开发工具 =====
    KnowledgeEntry(
        name="Node.js",
        patterns=["node\\.exe", "node"],
        category="dev",
        description="Node.js JavaScript 运行时，用于运行前端开发服务器、CLI 工具等。",
        kill_impact="正在运行的 dev server 或脚本会停止，热重载中断，不影响代码文件。",
        recommendation="safe",
        emoji="🟢",
    ),
    KnowledgeEntry(
        name="Python",
        patterns=["python", "python3"],
        category="dev",
        description="Python 解释器，运行 Python 脚本、Jupyter、AI/ML 框架等。",
        kill_impact="正在运行的脚本中断，未保存的数据丢失。长期训练任务需注意。",
        recommendation="caution",
        emoji="🐍",
    ),
    KnowledgeEntry(
        name="Java",
        patterns=["java", "javaw"],
        category="dev",
        description="Java 运行时，运行 Spring Boot、Minecraft、IDEA 等应用。",
        kill_impact="JVM 进程终止，应用关闭。Spring Boot 等服务需重启。",
        recommendation="caution",
        emoji="☕",
    ),
    KnowledgeEntry(
        name="Docker Desktop",
        patterns=["Docker Desktop", "com\\.docker"],
        category="dev",
        description="Docker 桌面版，管理容器和镜像。",
        kill_impact="所有运行中的容器将停止，未 commit 的变更可能丢失。",
        recommendation="caution",
        emoji="🐳",
    ),
    KnowledgeEntry(
        name="Git",
        patterns=["git\\.exe", "git"],
        category="dev",
        description="Git 版本控制工具。",
        kill_impact="正在进行的 git 操作可能中断（如 push/pull/rebase），可能需要清理。",
        recommendation="safe",
        emoji="🌿",
    ),
    KnowledgeEntry(
        name="VS Code",
        patterns=["Code\\.exe", "code", "electron"],
        category="dev",
        description="Visual Studio Code 代码编辑器，基于 Electron。",
        kill_impact="所有未保存的文件修改可能丢失（取决于自动保存设置）。",
        recommendation="caution",
        emoji="📝",
    ),
    KnowledgeEntry(
        name="IDEA/WebStorm",
        patterns=["idea64", "webstorm64", "pycharm64"],
        category="dev",
        description="JetBrains IDE 系列，Java/Python/Web 开发。",
        kill_impact="IDE 关闭，未保存文件可能丢失，索引缓存保留。",
        recommendation="caution",
        emoji="💡",
    ),

    # ===== AI 工具 =====
    KnowledgeEntry(
        name="aioom (本工具)",
        patterns=["aioom"],
        category="ai",
        description="AI OOM Guardian 内存守护工具，正在保护你的系统内存。",
        kill_impact="内存守护功能停止，系统内存泄漏将不再被自动处理。",
        recommendation="danger",
        emoji="🤖",
    ),
    KnowledgeEntry(
        name="Ollama",
        patterns=["ollama"],
        category="ai",
        description="本地 LLM 推理引擎，加载模型后常驻内存。",
        kill_impact="已加载的模型被卸载，下次使用需重新加载。",
        recommendation="safe",
        emoji="🦙",
    ),
    KnowledgeEntry(
        name="CodeBuddy/WorkBuddy",
        patterns=["CodeBuddy", "WorkBuddy", "codebuddy"],
        category="ai",
        description="AI 编程助手桌面客户端。",
        kill_impact="AI 对话中断，需要重新启动应用。",
        recommendation="caution",
        emoji="🤖",
    ),

    # ===== 通讯工具 =====
    KnowledgeEntry(
        name="微信",
        patterns=["WeChat", "wechat", "WeChatApp"],
        category="communication",
        description="微信桌面客户端，通讯和支付工具。",
        kill_impact="微信退出，正在发送的消息可能丢失，需要重新登录。",
        recommendation="caution",
        emoji="💬",
    ),
    KnowledgeEntry(
        name="钉钉",
        patterns=["DingTalk", "dingtalk"],
        category="communication",
        description="钉钉桌面客户端，企业办公通讯。",
        kill_impact="钉钉退出，未发送的消息丢失。",
        recommendation="safe",
        emoji="📌",
    ),
    KnowledgeEntry(
        name="飞书",
        patterns=["Feishu", "lark"],
        category="communication",
        description="飞书桌面客户端，企业协作办公。",
        kill_impact="飞书退出，未发送消息丢失。",
        recommendation="safe",
        emoji="🐦",
    ),
    KnowledgeEntry(
        name="QQ",
        patterns=["QQ\\.exe", "qq"],
        category="communication",
        description="QQ 桌面客户端。",
        kill_impact="QQ 退出，未发送消息丢失。",
        recommendation="safe",
        emoji="🐧",
    ),
    KnowledgeEntry(
        name="腾讯会议",
        patterns=["TencentMeeting", "wemeet"],
        category="communication",
        description="腾讯会议桌面客户端。",
        kill_impact="正在进行的会议将断开连接。",
        recommendation="caution",
        emoji="📹",
    ),
    KnowledgeEntry(
        name="Slack",
        patterns=["slack"],
        category="communication",
        description="Slack 团队通讯工具。",
        kill_impact="Slack 退出，需重新登录。",
        recommendation="safe",
        emoji="💬",
    ),

    # ===== 媒体 =====
    KnowledgeEntry(
        name="Spotify",
        patterns=["Spotify"],
        category="media",
        description="Spotify 音乐播放客户端。",
        kill_impact="音乐停止播放，客户端退出。",
        recommendation="safe",
        emoji="🎵",
    ),
    KnowledgeEntry(
        name="网易云音乐",
        patterns=["cloudmusic", "NeteaseCloudMusic"],
        category="media",
        description="网易云音乐桌面客户端。",
        kill_impact="音乐停止播放。",
        recommendation="safe",
        emoji="🎶",
    ),

    # ===== 其他常见 =====
    KnowledgeEntry(
        name="OneDrive",
        patterns=["OneDrive"],
        category="utility",
        description="Microsoft OneDrive 云同步客户端。",
        kill_impact="文件同步暂停，下次启动时自动恢复。",
        recommendation="safe",
        emoji="☁️",
    ),
    KnowledgeEntry(
        name="NVIDIA 驱动",
        patterns=["nvidia", "nvcontainer", "NVIDIA"],
        category="system",
        description="NVIDIA 显卡驱动和服务进程。",
        kill_impact="可能导致显示器闪烁或黑屏，GPU 加速功能失效。",
        recommendation="danger",
        emoji="🎮",
    ),
    KnowledgeEntry(
        name="PostgreSQL",
        patterns=["postgres"],
        category="dev",
        description="PostgreSQL 数据库服务器。",
        kill_impact="数据库连接中断，未提交的事务回滚，应用报错。",
        recommendation="caution",
        emoji="🐘",
    ),
    KnowledgeEntry(
        name="Redis",
        patterns=["redis-server"],
        category="dev",
        description="Redis 内存数据库服务器。",
        kill_impact="缓存数据丢失（除非配置了持久化），依赖 Redis 的应用会报错。",
        recommendation="caution",
        emoji="🔴",
    ),
    KnowledgeEntry(
        name="Nginx",
        patterns=["nginx"],
        category="dev",
        description="Nginx Web 服务器/反向代理。",
        kill_impact="网站/服务不可访问。",
        recommendation="caution",
        emoji="🌐",
    ),
]


# 预编译正则
_COMPILED_PATTERNS: List[tuple] = []
for entry in KNOWLEDGE_BASE:
    compiled = [(re.compile(p, re.IGNORECASE), entry) for p in entry.patterns]
    _COMPILED_PATTERNS.extend(compiled)


def lookup(name: str, cmdline: str = "") -> Optional[KnowledgeEntry]:
    """
    查找进程百科信息。
    先按 name 精确匹配，再按 name 模糊匹配，最后按 cmdline 模糊匹配。
    """
    # 1. 精确匹配 name
    for entry in KNOWLEDGE_BASE:
        for p in entry.patterns:
            if p.startswith("^") and p.endswith("$"):
                if re.match(p, name, re.IGNORECASE):
                    return entry

    # 2. name 模糊匹配
    for regex, entry in _COMPILED_PATTERNS:
        if regex.search(name):
            return entry

    # 3. cmdline 模糊匹配
    if cmdline:
        for regex, entry in _COMPILED_PATTERNS:
            if regex.search(cmdline):
                return entry

    return None


def get_category_emoji(category: str) -> str:
    """获取分类图标"""
    emoji_map = {
        "system": "⚙️", "browser": "🌐", "dev": "💻",
        "communication": "💬", "media": "🎵", "utility": "🔧",
        "game": "🎮", "ai": "🤖", "security": "🛡️", "other": "📦",
    }
    return emoji_map.get(category, "📦")


def to_dict(entry: Optional[KnowledgeEntry]) -> dict:
    """将百科条目转为字典（用于 JSON 序列化）"""
    if entry is None:
        return {}
    return {
        "name": entry.name,
        "category": entry.category,
        "category_emoji": entry.emoji,
        "description": entry.description,
        "kill_impact": entry.kill_impact,
        "recommendation": entry.recommendation,
    }
