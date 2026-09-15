"""BudgetMiddleware：墙钟（安全点）/ 工具预算 / 同参数重复调用检测。

超限时抛 BudgetExhausted → 编排层（_run_stage）捕获做 attempt 重试（带总结）。
不再用 jump_to end（终止与重试的决策权统一在编排层）。
"""
from __future__ import annotations

import time
from typing import Any

from langchain.agents.middleware.types import AgentMiddleware
from langchain_core.messages import ToolMessage

from leanagent.logging_setup import log
from leanagent.middleware.retry import BudgetExhausted


class BudgetMiddleware(AgentMiddleware):
    """预算三闸门。

    before_model 检查（模型下一轮调用前 = 安全点，工具已执行完毕）：
    - 墙钟超限 / 工具调用总数超预算 → 抛 BudgetExhausted（编排层 attempt 重试）
    - 同参数重复（recon 类 3 次 / 执行类 5 次）→ 工具层直接拦截（返回终止提示）
    """

    # 确定性 recon 工具：同一参数重复调用 = 死循环（输出不变）
    RECON_TOOLS = frozenset({
        "disassemble", "global_vars", "got_plt", "sections", "checksec", "identify_libc",
        "elf_plt_got", "probe_io", "cfg", "symbols", "elf_info", "libc_offsets",
    })
    # 执行类工具：同参数重调 = 无效重试死循环（gdb_run 断点未命中原样重调 70+ 次实测）
    EXEC_TOOLS = frozenset({"gdb_run", "gdb_run_crash", "run_binary", "find_offset"})
    EXEC_REPEAT_LIMIT = 5

    def __init__(self, max_tool_calls: int = 40, max_seconds: float = 600.0):
        super().__init__()
        self.max_tool_calls = max_tool_calls
        self.max_seconds = max_seconds
        self.stop_reason: str = ""  # 终止原因（_run_subagent 读）
        self.last_messages: list = []  # 最近一次见过的会话消息（异常路径总结轮用）
        self._wall_t0 = time.time()
        self._tool_calls = 0
        self._call_counts: dict[tuple, int] = {}

    def reset(self) -> None:
        """attempt 重试前重置状态（新会话新墙钟）。"""
        self.stop_reason = ""
        self.last_messages = []
        self._wall_t0 = time.time()
        self._tool_calls = 0
        self._call_counts = {}

    def before_model(self, state) -> dict[str, Any] | None:
        # 存一份消息（异常穿透 ainvoke 时 _run_subagent 拿不到 state，
        # 从这里恢复给总结轮——否则 attempt 冷启动）
        msgs = state.get("messages", [])
        if msgs:
            self.last_messages = msgs
        elapsed = time.time() - self._wall_t0
        if elapsed > self.max_seconds:
            log.warning(f"⚠ 墙钟超限({self.max_seconds:.0f}s)。")
            self.stop_reason = f"wallclock({elapsed:.0f}s)"
            raise BudgetExhausted(self.stop_reason)
        if self._tool_calls > self.max_tool_calls:
            log.warning(f"⚠ 超工具预算({self.max_tool_calls})。")
            self.stop_reason = f"tool_budget({self._tool_calls})"
            raise BudgetExhausted(self.stop_reason)
        return None

    async def awrap_tool_call(self, request, handler):
        tc = request.tool_call
        name = tc.get("name", "")
        inp = str(tc.get("args", ""))[:300]
        self._tool_calls += 1
        limit = 3 if name in self.RECON_TOOLS else (
            self.EXEC_REPEAT_LIMIT if name in self.EXEC_TOOLS else None)
        if limit:
            sig = (name, inp)
            self._call_counts[sig] = self._call_counts.get(sig, 0) + 1
            if self._call_counts[sig] >= limit:
                log.info(f"⚠ {name} 同参数重复调用 {self._call_counts[sig]} 次，终止。")
                return ToolMessage(
                    content=f"【系统终止】{name} 同参数重复调用 {self._call_counts[sig]} 次——"
                            "相同参数结果不会变，本轮已强制结束。下次修改参数后再调。",
                    tool_call_id=tc.get("id", "") or "",
                )
        return await handler(request)
