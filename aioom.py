"""
aioom.py - AI-Powered OOM Guardian 主入口
CLI 参数解析 + 守护进程主循环
"""

import argparse
import os
import signal
import sys
import time

# 确保能正确导入同级模块
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from collector import Collector
from ai_scorer import AIScorer, Verdict
from killer import Killer
from notifier import Notifier
from config import load_config, Config

VERSION = "0.1.0"


def parse_args():
    parser = argparse.ArgumentParser(
        prog="aioom",
        description="AI-Powered OOM Guardian - 比 earlyoom 更聪明的内存守护进程",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python aioom.py                    使用默认配置启动
  python aioom.py --dryrun           干跑模式（只分析不执行）
  python aioom.py --interval 5       每 5 秒检测一次
  python aioom.py --config my.toml   指定配置文件
  python aioom.py -v                 详细输出模式
        """,
    )
    parser.add_argument(
        "--config", type=str, default=None,
        help="指定配置文件路径（默认: config.toml）"
    )
    parser.add_argument(
        "--dryrun", action="store_true",
        help="干跑模式：只分析不执行清理操作"
    )
    parser.add_argument(
        "--interval", type=float, default=None,
        help="轮询间隔秒数（默认: 2）"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="详细输出：显示每个进程的评分详情"
    )
    parser.add_argument(
        "--version", action="version",
        version=f"aioom v{VERSION}"
    )
    return parser.parse_args()


def should_trigger(system, config: Config) -> bool:
    """判断是否触发 AI 评估"""
    # 内存阈值
    if system.mem_percent >= config.threshold.mem_percent:
        return True

    # Swap 阈值
    if config.threshold.swap_percent > 0 and system.swap_percent >= config.threshold.swap_percent:
        return True

    # 绝对值阈值
    if config.threshold.mem_abs_mb and system.mem_available_mb <= config.threshold.mem_abs_mb:
        return True

    return False


def main():
    args = parse_args()

    # 加载配置
    config = load_config(args.config)

    # 命令行参数覆盖配置文件
    if args.dryrun:
        config.dryrun = True
    if args.interval is not None:
        config.interval = args.interval
    if args.verbose:
        config.notify.verbose = True

    # 初始化模块
    collector = Collector(history_window_sec=config.ai.leak_window_sec)
    scorer = AIScorer(config)
    killer = Killer(dryrun=config.dryrun)
    notifier = Notifier(config)

    # 打印横幅
    notifier.print_banner(VERSION, dryrun=config.dryrun)

    # 优雅退出
    running = True

    def handle_signal(signum, frame):
        nonlocal running
        running = False
        print()
        print("  收到退出信号，正在关闭...")

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    # 预热：先采集几轮数据，建立历史基线
    notifier.logger.info("预热中，采集基线数据...")
    for i in range(3):
        collector.collect()
        time.sleep(1)

    notifier.logger.info("预热完成，开始守护循环")

    # 主循环
    trigger_count = 0
    while running:
        try:
            system, processes = collector.collect()
            proc_count = len(processes)

            # 打印实时状态
            notifier.print_status(
                system.mem_percent,
                system.mem_available_mb,
                system.swap_percent,
                proc_count
            )

            # 判断是否触发 AI 评估
            if should_trigger(system, config):
                trigger_count += 1
                notifier.print_clear_line()
                print()

                # 触发时间戳
                now_str = time.strftime("%H:%M:%S")
                notifier.logger.warning(
                    f"[{now_str}] 内存告警: "
                    f"MEM {system.mem_percent:.1f}% "
                    f"({system.mem_available_mb:.0f}MB 可用)  "
                    f"SWAP {system.swap_percent:.1f}%"
                )

                # AI 评估所有进程
                results = scorer.evaluate_all(processes, system)

                # 显示 TOP 10
                shown = 0
                for r in results:
                    if r.verdict in (Verdict.PROTECTED, Verdict.SAFE):
                        if config.notify.verbose:
                            notifier.log_score_result(r, verbose=True)
                        continue
                    notifier.log_score_result(r, verbose=config.notify.verbose)
                    shown += 1
                    if shown >= 10:
                        break

                if shown == 0:
                    print("  所有进程均安全，无需操作。")

                # 执行清理
                actionable = [r for r in results if r.should_act]
                if actionable:
                    print()
                    kill_results = killer.execute_batch(results, max_kills=3)
                    for kr in kill_results:
                        notifier.log_kill_result(kr)

                    # 发送 Webhook
                    if kill_results:
                        notifier.send_webhook(kill_results)

                print()

            time.sleep(config.interval)

        except KeyboardInterrupt:
            running = False
        except Exception as e:
            notifier.logger.error(f"循环异常: {e}")
            time.sleep(config.interval)

    # 退出
    notifier.print_clear_line()
    print()
    print(f"  aioom 已停止。共触发 {trigger_count} 次内存告警。")
    print()


if __name__ == "__main__":
    main()
