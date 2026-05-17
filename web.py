"""
web.py - aioom Web GUI 后端
FastAPI + SSE 实时推送，浏览器访问 http://localhost:8866
"""

import asyncio
import json
import os
import sys
import time
import webbrowser
from contextlib import asynccontextmanager
from collections import deque
from dataclasses import asdict
from typing import List, Optional

from fastapi import FastAPI, Query
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# 确保能正确导入同级模块
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from collector import Collector, SystemSnapshot, ProcessSnapshot
from ai_scorer import AIScorer, Verdict, ScoreResult
from killer import Killer, KillResult
from config import load_config, Config, ThresholdConfig, AIConfig, ProtectConfig, NotifyConfig

VERSION = "0.2.0"
HOST = "127.0.0.1"
PORT = 8866


# ============================================================
# 静态文件路径处理（开发 vs 打包）
# ============================================================

def get_static_dir() -> str:
    """获取静态文件目录，兼容 PyInstaller 打包"""
    if getattr(sys, 'frozen', False):
        return os.path.join(sys._MEIPASS, 'static')
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')


# ============================================================
# 应用状态
# ============================================================

class AppState:
    """全局共享状态"""

    def __init__(self, config: Config):
        self.config = config
        self.collector = Collector(history_window_sec=config.ai.leak_window_sec)
        self.scorer = AIScorer(config)
        self.killer = Killer(dryrun=config.dryrun)

        # 缓存最新数据
        self.system: Optional[SystemSnapshot] = None
        self.processes: List[dict] = []
        self.scores: List[ScoreResult] = []

        # 历史数据
        self.history: deque = deque(maxlen=300)
        self.logs: deque = deque(maxlen=200)

        # 统计
        self.alert_count = 0
        self.kill_count = 0
        self.start_time = time.time()

        # 控制
        self.running = True
        self.paused = False

    def add_log(self, level: str, message: str, detail: str = ""):
        self.logs.append({
            "timestamp": time.strftime("%H:%M:%S"),
            "time_full": time.strftime("%Y-%m-%d %H:%M:%S"),
            "level": level,
            "message": message,
            "detail": detail,
        })


# ============================================================
# SSE 管理器
# ============================================================

class SSEManager:
    """管理 SSE 客户端连接，广播事件"""

    def __init__(self):
        self._clients: List[asyncio.Queue] = []

    async def add_client(self) -> asyncio.Queue:
        q = asyncio.Queue()
        self._clients.append(q)
        return q

    def remove_client(self, q: asyncio.Queue):
        if q in self._clients:
            self._clients.remove(q)

    async def broadcast(self, event_type: str, data: dict):
        msg = f"event: {event_type}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
        dead = []
        for q in self._clients:
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self.remove_client(q)


# ============================================================
# 创建 FastAPI 应用
# ============================================================

# 配置加载
_config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.toml")
config = load_config(_config_path)
state = AppState(config)
sse_manager = SSEManager()

@asynccontextmanager
async def lifespan(app):
    asyncio.create_task(guardian_loop())
    yield

app = FastAPI(title="aioom Web UI", version=VERSION, docs_url=None, redoc_url=None, lifespan=lifespan)


# ============================================================
# 静态文件
# ============================================================

@app.get("/")
async def index():
    return FileResponse(os.path.join(get_static_dir(), "index.html"))


# ============================================================
# REST API
# ============================================================

@app.get("/api/system")
async def api_system():
    """当前系统快照"""
    if state.system is None:
        return {}
    return asdict(state.system)


@app.get("/api/processes")
async def api_processes(
    sort: str = Query("confidence", pattern="^(confidence|mem_percent|cpu_percent|mem_mb|pid|name)$"),
    order: str = Query("desc", pattern="^(asc|desc)$"),
    limit: int = Query(100, ge=1, le=500),
):
    """进程列表 + AI 评分"""
    procs = list(state.processes)
    reverse = (order == "desc")

    if sort == "name":
        procs.sort(key=lambda p: p.get("name", ""), reverse=reverse)
    else:
        procs.sort(key=lambda p: p.get(sort, 0) or 0, reverse=reverse)

    return {"processes": procs[:limit], "total": len(state.processes)}


@app.get("/api/config")
async def api_get_config():
    """获取当前配置"""
    c = state.config
    return {
        "threshold": asdict(c.threshold),
        "ai": asdict(c.ai),
        "protect": {
            "ignore_patterns": list(c.protect.ignore_patterns),
            "ignore_root": c.protect.ignore_root,
            "protect_foreground": c.protect.protect_foreground,
        },
        "notify": asdict(c.notify),
        "interval": c.interval,
        "dryrun": c.dryrun,
    }


class ConfigUpdate(BaseModel):
    threshold: Optional[dict] = None
    ai: Optional[dict] = None
    protect: Optional[dict] = None
    notify: Optional[dict] = None
    interval: Optional[float] = None
    dryrun: Optional[bool] = None


@app.put("/api/config")
async def api_update_config(update: ConfigUpdate):
    """更新配置（即时生效）"""
    c = state.config

    if update.threshold:
        for k, v in update.threshold.items():
            if hasattr(c.threshold, k):
                setattr(c.threshold, k, v)
    if update.ai:
        for k, v in update.ai.items():
            if hasattr(c.ai, k):
                setattr(c.ai, k, v)
    if update.protect:
        if "ignore_patterns" in update.protect:
            c.protect.ignore_patterns = list(update.protect["ignore_patterns"])
        if "ignore_root" in update.protect:
            c.protect.ignore_root = update.protect["ignore_root"]
        if "protect_foreground" in update.protect:
            c.protect.protect_foreground = update.protect["protect_foreground"]
    if update.notify:
        for k, v in update.notify.items():
            if hasattr(c.notify, k):
                setattr(c.notify, k, v)
    if update.interval is not None:
        c.interval = update.interval
    if update.dryrun is not None:
        c.dryrun = update.dryrun
        state.killer = Killer(dryrun=c.dryrun)

    # 重建 AI Scorer（保护规则可能变了）
    state.scorer = AIScorer(c)
    state.collector = Collector(history_window_sec=c.ai.leak_window_sec)

    # 保存到 TOML
    _save_config(c, _config_path)

    state.add_log("config", "配置已更新并保存")
    await sse_manager.broadcast("config_changed", {"message": "配置已更新"})

    return {"status": "ok", "message": "配置已更新"}


@app.post("/api/kill/{pid}")
async def api_kill(pid: int, action: str = Query("term", pattern="^(term|kill)$")):
    """手动终止指定进程"""
    # 找到对应进程
    score = None
    for s in state.scores:
        if s.pid == pid:
            score = s
            break

    if score is None:
        # 手动构造一个
        score = ScoreResult(
            pid=pid, name="unknown",
            verdict=Verdict.KILL if action == "kill" else Verdict.TERM,
            confidence=1.0, is_leaking=False, is_foreground=False,
            mem_trend_mb_s=0.0, cpu_trend_p_s=0.0,
            reasons=["手动操作"],
        )
    else:
        if action == "kill":
            score.verdict = Verdict.KILL
        else:
            score.verdict = Verdict.TERM

    # 在线程池中执行（killer.execute 会 sleep）
    result = await asyncio.to_thread(state.killer.execute, score)
    state.kill_count += 1

    result_dict = asdict(result)
    state.add_log(
        "kill" if result.success else "error",
        f"{result.action}: PID {pid} {score.name}",
        result.message,
    )
    await sse_manager.broadcast("kill", result_dict)

    return result_dict


@app.post("/api/kill/batch")
async def api_kill_batch(max_kills: int = Query(3, ge=1, le=10)):
    """手动触发批量清理（取 AI top N）"""
    results = await asyncio.to_thread(
        state.killer.execute_batch, state.scores, max_kills=max_kills
    )
    for r in results:
        state.kill_count += 1
        state.add_log("kill" if r.success else "error", f"{r.action}: PID {r.pid} {r.name}", r.message)

    results_dict = [asdict(r) for r in results]
    await sse_manager.broadcast("kill", {"batch": results_dict})
    return {"results": results_dict}


@app.get("/api/history")
async def api_history():
    """历史系统数据点"""
    return {"history": list(state.history)}


@app.get("/api/logs")
async def api_logs(
    level: str = Query("", pattern="^(|alert|kill|config|error)$"),
    limit: int = Query(100, ge=1, max=200),
):
    """操作日志"""
    logs = list(state.logs)
    if level:
        logs = [l for l in logs if l["level"] == level]
    return {"logs": logs[-limit:], "total": len(logs)}


@app.get("/api/stats")
async def api_stats():
    """累计统计"""
    uptime = time.time() - state.start_time
    return {
        "uptime_sec": round(uptime),
        "alert_count": state.alert_count,
        "kill_count": state.kill_count,
        "log_count": len(state.logs),
        "process_count": len(state.processes),
        "paused": state.paused,
    }


@app.post("/api/pause")
async def api_pause():
    """暂停/恢复守护"""
    state.paused = not state.paused
    state.add_log("config", f"守护已{'暂停' if state.paused else '恢复'}")
    return {"paused": state.paused}


# ============================================================
# SSE 实时推送
# ============================================================

@app.get("/api/events")
async def api_events():
    """SSE 事件流"""
    queue = await sse_manager.add_client()

    async def event_stream():
        try:
            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=30)
                    yield msg
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            sse_manager.remove_client(queue)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ============================================================
# 守护循环（后台任务）
# ============================================================

def should_trigger(system: SystemSnapshot, cfg: Config) -> bool:
    if system.mem_percent >= cfg.threshold.mem_percent:
        return True
    if cfg.threshold.swap_percent > 0 and system.swap_percent >= cfg.threshold.swap_percent:
        return True
    if cfg.threshold.mem_abs_mb and system.mem_available_mb <= cfg.threshold.mem_abs_mb:
        return True
    return False


def merge_processes_scores(processes: List[ProcessSnapshot], scores: List[ScoreResult]) -> List[dict]:
    """将进程快照和 AI 评分合并为前端需要的 dict"""
    score_map = {s.pid: s for s in scores}
    result = []
    for p in processes:
        s = score_map.get(p.pid)
        result.append({
            "pid": p.pid,
            "name": p.name,
            "cmdline": p.cmdline,
            "username": p.username,
            "mem_mb": round(p.mem_mb, 1),
            "mem_percent": round(p.mem_percent, 2),
            "cpu_percent": round(p.cpu_percent, 1),
            "num_threads": p.num_threads,
            "status": p.status,
            "create_time": p.create_time,
            "io_read_mb": round(p.io_read_mb, 1),
            "io_write_mb": round(p.io_write_mb, 1),
            "verdict": s.verdict.value if s else "safe",
            "confidence": round(s.confidence, 3) if s else 0.0,
            "is_leaking": s.is_leaking if s else False,
            "is_foreground": s.is_foreground if s else False,
            "mem_trend_mb_s": round(s.mem_trend_mb_s, 2) if s else 0.0,
            "cpu_trend_p_s": round(s.cpu_trend_p_s, 2) if s else 0.0,
            "reasons": s.reasons if s else [],
        })
    return result


async def guardian_loop():
    """后台守护循环"""
    state.add_log("info", "aioom Web 守护已启动", f"v{VERSION}")

    # 预热采集 3 轮
    for i in range(3):
        await asyncio.to_thread(state.collector.collect)
        await asyncio.sleep(1)

    state.add_log("info", "基线预热完成，开始守护")

    while state.running:
        try:
            # 采集数据（在线程池中执行，避免阻塞事件循环）
            system, processes = await asyncio.to_thread(state.collector.collect)

            # AI 评估
            scores = await asyncio.to_thread(state.scorer.evaluate_all, processes, system)

            # 更新状态
            state.system = system
            state.processes = merge_processes_scores(processes, scores)
            state.scores = scores

            # 历史数据
            state.history.append({
                "t": time.strftime("%H:%M:%S"),
                "mem": round(system.mem_percent, 1),
                "swap": round(system.swap_percent, 1),
                "cpu": round(system.cpu_percent, 1),
            })

            # 推送系统快照
            await sse_manager.broadcast("system", {
                "mem_percent": round(system.mem_percent, 1),
                "mem_available_mb": round(system.mem_available_mb, 0),
                "mem_total_mb": round(system.mem_total_mb, 0),
                "mem_used_mb": round(system.mem_used_mb, 0),
                "swap_percent": round(system.swap_percent, 1),
                "swap_total_mb": round(system.swap_total_mb, 0),
                "cpu_percent": round(system.cpu_percent, 1),
                "proc_count": len(processes),
            })

            # 判断是否触发告警
            if not state.paused and should_trigger(system, state.config):
                state.alert_count += 1
                alert_data = {
                    "level": "warning",
                    "message": f"内存 {system.mem_percent:.1f}% (可用 {system.mem_available_mb:.0f}MB)",
                    "mem_percent": system.mem_percent,
                    "swap_percent": system.swap_percent,
                }
                state.add_log("alert", f"内存告警: MEM {system.mem_percent:.1f}%", f"可用 {system.mem_available_mb:.0f}MB")
                await sse_manager.broadcast("alert", alert_data)

                # 自动清理
                actionable = [s for s in scores if s.should_act]
                if actionable:
                    kill_results = await asyncio.to_thread(
                        state.killer.execute_batch, scores, max_kills=3
                    )
                    for kr in kill_results:
                        state.kill_count += 1
                        state.add_log(
                            "kill" if kr.success else "error",
                            f"{kr.action}: PID {kr.pid} {kr.name}",
                            kr.message,
                        )
                        await sse_manager.broadcast("kill", asdict(kr))

            await asyncio.sleep(state.config.interval)

        except asyncio.CancelledError:
            break
        except Exception as e:
            state.add_log("error", f"守护循环异常: {e}")
            await asyncio.sleep(state.config.interval)


# ============================================================
# TOML 配置保存
# ============================================================

def _save_config(cfg: Config, path: str):
    """将配置写回 TOML 文件"""
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib

    # 手动构建 TOML 字符串
    lines = [
        "# aioom 配置文件",
        "",
        "[threshold]",
        f"mem_percent = {cfg.threshold.mem_percent}",
        f"swap_percent = {cfg.threshold.swap_percent}",
        f"mem_abs_mb = {json.dumps(cfg.threshold.mem_abs_mb)}" if cfg.threshold.mem_abs_mb else "# mem_abs_mb = null",
        "",
        "[ai]",
        f"term_confidence = {cfg.ai.term_confidence}",
        f"kill_confidence = {cfg.ai.kill_confidence}",
        f"leak_window_sec = {cfg.ai.leak_window_sec}",
        f"idle_cpu_threshold = {cfg.ai.idle_cpu_threshold}",
        "",
        "[protect]",
        f'ignore_patterns = {json.dumps(cfg.protect.ignore_patterns, ensure_ascii=False)}',
        f"ignore_root = {json.dumps(cfg.protect.ignore_root)}",
        f"protect_foreground = {json.dumps(cfg.protect.protect_foreground)}",
        "",
        "[notify]",
        f"log_file = {json.dumps(cfg.notify.log_file)}",
        f"webhook_url = {json.dumps(cfg.notify.webhook_url)}",
        f"desktop_notify = {json.dumps(cfg.notify.desktop_notify)}",
        f"verbose = {json.dumps(cfg.notify.verbose)}",
        "",
        f"interval = {cfg.interval}",
        f"dryrun = {json.dumps(cfg.dryrun)}",
        "",
    ]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# ============================================================
# 启动
# ============================================================


def main():
    import argparse
    parser = argparse.ArgumentParser(description="aioom Web UI")
    parser.add_argument("--host", default=HOST, help="监听地址")
    parser.add_argument("--port", type=int, default=PORT, help="监听端口")
    parser.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    parser.add_argument("--dryrun", action="store_true", help="干跑模式")
    args = parser.parse_args()

    if args.dryrun:
        config.dryrun = True
        state.killer = Killer(dryrun=True)

    import uvicorn

    if not args.no_browser:
        import threading
        url = f"http://{args.host}:{args.port}"
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()

    print(f"""
  aioom v{VERSION} - Web UI
  http://{args.host}:{args.port}
  模式: {'DRYRUN' if config.dryrun else 'LIVE'}
""")

    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
