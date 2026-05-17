"""
collector.py - 数据采集模块
基于 psutil 实时采集系统内存、Swap、CPU、IO 和进程列表信息。
维护进程历史快照，为 AI 决策提供时序数据。
"""

import time
import platform
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from collections import deque

import psutil


@dataclass
class SystemSnapshot:
    """系统整体资源快照"""
    timestamp: float
    mem_total_mb: float
    mem_used_mb: float
    mem_available_mb: float
    mem_percent: float
    swap_total_mb: float
    swap_used_mb: float
    swap_percent: float
    cpu_percent: float
    io_read_mb: float = 0.0
    io_write_mb: float = 0.0

    @property
    def mem_available_percent(self) -> float:
        return 100.0 - self.mem_percent


@dataclass
class ProcessSnapshot:
    """单个进程快照"""
    pid: int
    name: str
    cmdline: str
    username: str
    mem_mb: float
    mem_percent: float
    cpu_percent: float
    num_threads: int
    status: str
    create_time: float
    io_read_mb: float = 0.0
    io_write_mb: float = 0.0
    # 衍生字段（由 AI 层填充）
    is_idle: Optional[bool] = None
    cpu_trend: Optional[float] = None  # CPU 30s 趋势
    mem_trend: Optional[float] = None  # 内存 30s 趋势
    is_foreground: Optional[bool] = None


class ProcessHistory:
    """进程历史数据，用于趋势分析"""

    def __init__(self, window_sec: int = 60, max_entries: int = 30):
        self._window = window_sec
        self._max = max_entries
        self._data: Dict[int, deque] = {}

    def add(self, pid: int, snapshot: ProcessSnapshot):
        """添加一个进程快照"""
        if pid not in self._data:
            self._data[pid] = deque(maxlen=self._max)
        self._data[pid].append((snapshot.timestamp, snapshot.mem_mb, snapshot.cpu_percent))

    def cleanup(self, alive_pids: set):
        """清理已死亡的进程历史"""
        dead = [pid for pid in self._data if pid not in alive_pids]
        for pid in dead:
            del self._data[pid]

    def get_trend(self, pid: int, window_sec: Optional[int] = None) -> Tuple[float, float]:
        """
        返回 (mem_trend_mb_per_sec, cpu_trend_percent)
        基于线性回归计算最近 window_sec 秒的趋势。
        """
        window = window_sec or self._window
        if pid not in self._data:
            return 0.0, 0.0

        entries = list(self._data[pid])
        if len(entries) < 2:
            return 0.0, 0.0

        now = entries[-1][0]
        filtered = [(t, m, c) for t, m, c in entries if now - t <= window]
        if len(filtered) < 2:
            return 0.0, 0.0

        # 简单线性回归：y = slope * x + b
        n = len(filtered)
        ts = [f[0] for f in filtered]
        mems = [f[1] for f in filtered]
        cpus = [f[2] for f in filtered]

        t_mean = sum(ts) / n
        mem_slope = sum((ts[i] - t_mean) * (mems[i] - sum(mems) / n) for i in range(n)) / \
                    max(sum((t - t_mean) ** 2 for t in ts), 1e-9)
        cpu_slope = sum((ts[i] - t_mean) * (cpus[i] - sum(cpus) / n) for i in range(n)) / \
                    max(sum((t - t_mean) ** 2 for t in ts), 1e-9)

        return mem_slope, cpu_slope


class Collector:
    """系统数据采集器"""

    def __init__(self, history_window_sec: int = 60):
        self.history = ProcessHistory(window_sec=history_window_sec)
        self._prev_io: Optional[Tuple[float, float]] = None

    def collect_system(self) -> SystemSnapshot:
        """采集系统整体资源数据"""
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        cpu = psutil.cpu_percent(interval=0.1)

        io_read, io_write = 0.0, 0.0
        try:
            disk_io = psutil.disk_io_counters()
            if disk_io:
                io_read = disk_io.read_bytes / (1024 * 1024)
                io_write = disk_io.write_bytes / (1024 * 1024)
        except Exception:
            pass

        return SystemSnapshot(
            timestamp=time.time(),
            mem_total_mb=mem.total / (1024 * 1024),
            mem_used_mb=mem.used / (1024 * 1024),
            mem_available_mb=mem.available / (1024 * 1024),
            mem_percent=mem.percent,
            swap_total_mb=swap.total / (1024 * 1024),
            swap_used_mb=swap.used / (1024 * 1024),
            swap_percent=swap.percent,
            cpu_percent=cpu,
            io_read_mb=io_read,
            io_write_mb=io_write,
        )

    def collect_processes(self) -> List[ProcessSnapshot]:
        """采集所有进程的快照"""
        processes = []
        system = platform.system()

        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username',
                                          'memory_info', 'cpu_percent',
                                          'num_threads', 'status', 'create_time']):
            try:
                info = proc.info
                mem_info = info.get('memory_info')
                if not mem_info:
                    continue

                mem_mb = mem_info.rss / (1024 * 1024)

                cmdline_str = ""
                if info.get('cmdline'):
                    cmdline_str = " ".join(str(c) for c in info['cmdline'] if c)

                username = info.get('username') or ""

                io_read, io_write = 0.0, 0.0
                try:
                    io = proc.io_counters()
                    io_read = io.read_bytes / (1024 * 1024)
                    io_write = io.write_bytes / (1024 * 1024)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                snap = ProcessSnapshot(
                    pid=info['pid'],
                    name=info['name'] or "",
                    cmdline=cmdline_str,
                    username=username,
                    mem_mb=mem_mb,
                    mem_percent=0.0,
                    cpu_percent=info.get('cpu_percent', 0.0) or 0.0,
                    num_threads=info.get('num_threads', 0) or 0,
                    status=info.get('status', ""),
                    create_time=info.get('create_time', 0.0) or 0.0,
                    io_read_mb=io_read,
                    io_write_mb=io_write,
                )
                processes.append(snap)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # 计算每个进程的内存百分比
        mem_total = psutil.virtual_memory().total
        for p in processes:
            p.mem_percent = (p.mem_mb * 1024 * 1024 / mem_total) * 100

        # 填充时间戳、趋势数据、写入历史
        now = time.time()
        alive_pids = set()
        for p in processes:
            p.timestamp = now
            mem_trend, cpu_trend = self.history.get_trend(p.pid)
            p.mem_trend = mem_trend
            p.cpu_trend = cpu_trend
            self.history.add(p.pid, p)
            alive_pids.add(p.pid)

        # 清理死亡进程
        self.history.cleanup(alive_pids)

        return processes

    def collect(self) -> Tuple[SystemSnapshot, List[ProcessSnapshot]]:
        """一次性采集全部数据"""
        system = self.collect_system()
        processes = self.collect_processes()
        return system, processes
