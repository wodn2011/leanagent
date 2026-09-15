"""RetryMiddleware：agent 级重试全在 middleware（无 submit 原地 retry / 连接异常重试）。

编排层（_run_stage）只做 attempt（BudgetExhausted 上抛后带总结 feedback 重开新会话）。
"""
from __future__ import annotations

import asyncio
from typing import Any

import httpx
from langchain.agents.middleware.types import AgentMiddleware, hook_config
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from leanagent.logging_setup import log


class BudgetExhausted(Exception):
    """撞钟/预算终止/多次无 submit/多次连接失败——抛给编排层做 attempt 重试（带总结）。"""


class RetryMiddleware(AgentMiddleware):
    """agent 内重试：

    - awrap_model_call：GLM 连接类异常原地重调 handler（≤ max_retries 次）；
      超限抛 BudgetExhausted
    - after_agent（agent 自然停止时）：检查【全消息列表】里是否曾调过 submit_final_result
      （不是只看最后一条——submit 成功后模型还会回复“收到”类纯文本，最后一条 AI 消息
      必然不含 tool_calls，只看最后一条会误判）。曾调过 submit 且已有采纳结果 → 正常结束；
      从未调过 → 追加提醒 jump_to model 原地重试（≤ max_retries 次）；超限抛 BudgetExhausted
    """

    _CONN_ERRORS = (httpx.ReadError, httpx.ConnectError, httpx.RemoteProtocolError)

    def __init__(self, max_retries: int = 2):
        super().__init__()
        self.max_retries = max_retries
        self.no_submit_count = 0
        self.conn_retry_count = 0

    # ---- 连接异常重试（模型调用层）----
    # 单次调用软超时：流式连接挂起时 httpx 读超时会被心跳重置、永不触发
    # （实测一次 GLM(32909.9s)——火山网关挂死 9 小时，墙钟在调用中不检查）。
    # asyncio.wait_for 强制中断，超时按连接异常同样重试。
    CALL_TIMEOUT_S = 600

    async def awrap_model_call(self, request, handler):
        for conn_try in range(self.max_retries):
            try:
                return await asyncio.wait_for(handler(request), timeout=self.CALL_TIMEOUT_S)
            except (self._CONN_ERRORS, asyncio.TimeoutError) as e:
                self.conn_retry_count += 1
                if conn_try == self.max_retries - 1:
                    raise BudgetExhausted(
                        f"connection_error({type(e).__name__}×{self.conn_retry_count})")
                log.warning(f"[retry] GLM 调用中断({type(e).__name__})，"
                            f"模型层重试 {conn_try + 1}/{self.max_retries}...")
        # unreachable

    # ---- 无 submit 原地重试（agent 停止层）----
    @hook_config(can_jump_to=["model"])
    def after_agent(self, state) -> dict[str, Any] | None:
        msgs = state.get("messages", [])

        # ① 检查全列表中是否有 submit tool_call 被采纳（收到【已采纳】ToolMessage = 成功提交）
        for m in reversed(msgs):
            if isinstance(m, ToolMessage) and "已采纳" in str(m.content):
                return None  # submit 成功，正常结束

        # ② 从未调过 submit → 原地重试
        self.no_submit_count += 1
        if self.no_submit_count > self.max_retries:
            raise BudgetExhausted(f"no_submit({self.no_submit_count - 1}次重试后仍未提交)")
        log.warning(f"[retry] 无 submit（{self.no_submit_count}/{self.max_retries}），原地重试...")
        return {
            "jump_to": "model",
            "messages": [HumanMessage(content=(
                "【系统提醒】你上次的输出既没有调用工具也没有提交报告。"
                "若分析/利用仍在进行：继续调用工具执行下一步，不要停在纯文本输出上。"
                "若已全部完成：调用 submit_final_result(result_json=报告 JSON) 提交。"
            ))],
        }

    def reset(self) -> None:
        self.no_submit_count = 0
        self.conn_retry_count = 0
