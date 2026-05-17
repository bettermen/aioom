# aioom — AI-Powered OOM Guardian

> 一个受 [earlyoom](https://github.com/rfjakob/earlyoom) 启发的跨平台 AI 内存守护进程，在内存耗尽前智能地终止最危险的进程。

## ✨ 特性

- 🧠 **AI 智能评分** — 结合内存占用、CPU 使用率、进程类型等多维度对每个进程打危险分
- 🔍 **实时监控** — 持续采集系统内存/Swap/CPU 状态
- 🎛️ **Web GUI** — 内置浏览器界面，实时仪表盘 + 进程管理 + 配置编辑
- 🔔 **告警通知** — 内存超阈值时发出系统/日志告警
- 🛡️ **白名单保护** — 支持进程名/模式匹配保护重要进程
- 📦 **单文件可执行** — PyInstaller 打包，无需安装 Python

## 🚀 快速开始

### 方式一：直接运行源码

```bash
pip install fastapi uvicorn psutil tomli
python aioom/web.py          # Web GUI 模式（默认 http://localhost:8866）
python aioom/aioom.py -v     # CLI 模式
```

### 方式二：运行打包好的 exe（Windows）

```
dist/aioom-web.exe   # Web GUI 版
dist/aioom.exe       # CLI 版
```

## 📁 项目结构

```
aioom/
├── aioom.py        # CLI 主入口
├── web.py          # Web GUI 后端 (FastAPI)
├── collector.py    # 系统信息采集 (psutil)
├── ai_scorer.py    # AI 危险度评分引擎
├── killer.py       # 进程终止执行器
├── notifier.py     # 告警通知模块
├── config.py       # TOML 配置加载器
├── config.toml     # 默认配置文件
└── static/
    └── index.html  # Vue 3 单页应用前端
```

## ⚙️ 配置说明

编辑 `aioom/config.toml`：

```toml
[thresholds]
mem_percent = 90.0      # 内存占用触发阈值（%）
swap_percent = 80.0     # Swap 占用触发阈值（%）

[ai]
enabled = true          # 是否启用 AI 评分

[protect]
patterns = ["python", "code", "explorer"]  # 保护进程名单

[notify]
enabled = true
desktop = true
```

## 🏗️ 技术栈

| 模块 | 技术 |
|------|------|
| 后端 | Python 3.10+ · FastAPI · uvicorn · psutil |
| 前端 | Vue 3 (CDN) · Chart.js (CDN) · 暗色科幻主题 |
| 打包 | PyInstaller (--onefile) |
| 配置 | TOML |

## 📄 许可证

MIT License
