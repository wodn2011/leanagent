"""LogMiddleware：实时事件流日志（→GLM / ←GLM 响应 / →工具 / ←工具结果）。

详细事件流只进 full_run.log（log.debug）；控制台只保留关键节点（log.info 在编排层）。
"""
from __future__ import annotations

import json
import time

from langchain.agents.middleware.types import AgentMiddleware

from leanagent.logging_setup import log


class LogMiddleware(AgentMiddleware):
    """在 model/tool 调用前后记录事件流（带 prefix 标识子 agent）。

    - awrap_model_call：→ 调用GLM... / ← GLM 响应（耗时 + 工具调用名 or 文本预览）
    - awrap_tool_call：→ 工具名(参数摘要) / ← 工具结果(150 字符单行)
    """

    def __init__(self, prefix: str):
        super().__init__()
        self.prefix = prefix

    async def awrap_model_call(self, request, handler):
        log.debug(f"{self.prefix} → 调用 GLM...")
        t0 = time.time()
        result = await handler(request)
        dt = time.time() - t0
        # ★handler 返回 ModelResponse（langchain），真正消息在其 .result 列表里
        #   （首元素通常是 AIMessage；直接 getattr(result,'content') 拿到的是 None——
        #    这就是之前 GLM 文本预览一直为空的原因）
        msgs = getattr(result, "result", None)
        ai = msgs[0] if msgs else result
        content = getattr(ai, "content", "") or ""
        if not isinstance(content, str):
            content = str(content)
        tool_calls = getattr(ai, "tool_calls", None) or []
        head = content[:150].replace("\n", " ")
        if tool_calls:
            names = ", ".join(tc.get("name", "?") for tc in tool_calls)
            log.debug(f"{self.prefix} ← GLM({dt:.1f}s): 调工具[{names}]")
        else:
            log.debug(f"{self.prefix} ← GLM({dt:.1f}s)")
        if head:
            log.debug(f"{self.prefix} {head}")
        return result

    async def awrap_tool_call(self, request, handler):
        tc = getattr(request, "tool_call", None) or {}
        tool_name = tc.get("name", "?")
        args = tc.get("args", None) or {}
        try:
            args_str = json.dumps(args, ensure_ascii=False)[:150]
        except Exception:
            args_str = str(args)[:150]
        log.debug(f"{self.prefix}   → 工具 {tool_name}({args_str})")
        t0 = time.time()
        result = await handler(request)
        dt = time.time() - t0
        outp = getattr(result, "content", result)
        outp = outp if isinstance(outp, str) else str(outp)
        # 单行截断（多行结果压成一行，超长省略）
        outp = outp.replace("\n", " ⏎ ")
        if len(outp) > 150:
            outp = outp[:150] + f"...({len(outp)} chars)"
        log.debug(f"{self.prefix}   ← {tool_name}({dt:.1f}s): {outp}")
        return result
