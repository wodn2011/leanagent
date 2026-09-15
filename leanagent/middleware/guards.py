"""工具拦截 guard：InlineScriptGuard（防内联 pwntools hang）+ TruncatedWriteGuard（防截断写）。"""
from __future__ import annotations

import re

from langchain.agents.middleware.types import AgentMiddleware
from langchain_core.messages import ToolMessage

# 内联 `python -c` 脚本里用 pwntools 交互惯用语 → recv 无 timeout 会 stdin 死锁。
_INLINE_PYC_RE = re.compile(r"\bpython[23]?\s+-c\b", re.I)
_PWN_IDIOM_RE = re.compile(
    r"(\bfrom\s+pwn\b|\bimport\s+pwn\b|\bprocess\s*\(|\bremote\s*\(|\brecvuntil\b|"
    r"\bsendline\b|\binteractive\s*\(|\bp\.(send|recv)\b|\bpwntools\b)",
    re.I,
)


class InlineScriptGuard(AgentMiddleware):
    """拦截 execute：禁止内联 `python -c` 里的 pwntools 交互（hang 根因）。"""

    async def awrap_tool_call(self, request, handler):
        tc = request.tool_call
        if tc.get("name") == "execute":
            args = tc.get("args", {})
            cmd = args.get("command", "") if isinstance(args, dict) else (
                str(args) if isinstance(args, str) else ""
            )
            if cmd and _INLINE_PYC_RE.search(cmd) and _PWN_IDIOM_RE.search(cmd):
                return ToolMessage(
                    content=(
                        "【已被工具层拦截】禁止用 execute 跑内联 `python -c` 里的 pwntools 交互"
                        "（recv 无 timeout → stdin 死锁 → 烧墙钟）。"
                        "改用：① run_binary(stdin=, timeout=10)；"
                        "② write_file 完整脚本（内部 recv 必带 timeout≤3s）再 execute python3 <file>.py。"
                    ),
                    tool_call_id=tc.get("id", "") or "",
                )
        return await handler(request)


# 截断污染标记：GLM 工具调用参数被流式截断时框架会落成这种字面文本
_TRUNC_MARK = re.compile(r"\(argument truncated\)$")


class TruncatedWriteGuard(AgentMiddleware):
    """拦截 write_file/edit_file：内容尾部带截断污染标记时拒绝写入（防半截文件毁好文件）。"""

    _TARGETS = {"write_file", "edit_file"}

    async def awrap_tool_call(self, request, handler):
        tc = request.tool_call
        if tc.get("name") in self._TARGETS:
            args = tc.get("args", {}) if isinstance(tc.get("args"), dict) else {}
            for key in ("content", "new_string"):
                val = args.get(key)
                if isinstance(val, str) and _TRUNC_MARK.search(val.strip().splitlines()[-1] if val.strip() else ""):
                    return ToolMessage(
                        content=(
                            "【写入被拦截】内容以 '(argument truncated)' 结尾——工具调用参数被截断，"
                            "写入半截文件会毁掉磁盘上的完整版本。请重发完整的 write_file"
                            "（较长时分两次：先写前半，再 edit_file 追加后半）。"
                        ),
                        tool_call_id=tc.get("id", "") or "",
                    )
        return await handler(request)
