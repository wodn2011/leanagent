"""日志：python logging 模块，双 handler 分级。

- full_run.log：DEBUG 级（完整事件流：→GLM / ←GLM / →工具 / ←工具结果）
- 控制台：INFO 级（关键节点：各阶段启动/结束、submit 采纳、撞钟、报告路径）

用法：
    from leanagent.logging_setup import log, init_file_logging
    log.info("...")        # 关键节点（控制台 + 文件）
    log.debug("...")       # 详细事件流（只进文件）
    init_file_logging(ws)  # analyze_binary 开始时调用
"""
from __future__ import annotations

import logging
import sys

LOG = logging.getLogger("leanagent")


def init_file_logging(workspace: str, mode: str = "w") -> logging.Handler:
    """加一个 FileHandler 写 <workspace>/full_run.log（DEBUG 级，完整事件流）。

    mode="w"：analyze_binary 开始时（新任务覆盖）；mode="a"：后续追加（如主 agent 汇总补写）。
    """
    fh = logging.FileHandler(f"{workspace}/full_run.log", mode=mode, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s %(message)s", datefmt="%H:%M:%S"))
    fh.setLevel(logging.DEBUG)
    LOG.addHandler(fh)
    return fh


def setup_console_logging() -> None:
    """cli 入口调用：配置 leanagent logger 输出到 stderr（INFO 级，关键节点）。

    propagate=False：第三方库（deepagents 等）可能给 root logger 配了 handler，
    不关传播的话每条日志会被 root 的 handler 再打一遍（格式还不一样）。
    """
    if not any(isinstance(h, logging.StreamHandler) for h in LOG.handlers):
        h = logging.StreamHandler(sys.stderr)
        h.setFormatter(logging.Formatter("%(asctime)s %(message)s", datefmt="%H:%M:%S"))
        h.setLevel(logging.INFO)
        LOG.addHandler(h)
    LOG.setLevel(logging.DEBUG)
    LOG.propagate = False


# 便捷别名：log.info / log.debug 全项目统一入口
log = LOG
