"""总结轮（独立功能模块）。

撞钟/异常后，把原会话历史消息直接喂给 LLM（单次调用，不走 agent 框架，
不挂任何 middleware），生成总结装进 BudgetExhausted 上抛——编排层
（_run_stage）的 attempt 重试带着总结 feedback 开新会话，不冷启动。

为什么不用 agent 框架：任何 agent（即使裸的）都可能被 middleware/loop
行为劫持（实测：总结输出无 submit 被 RetryMiddleware 误判 jump_to model，
总结轮变成继续干活，原 raise 永远执行不到）。总结就是一次纯 LLM 调用。
"""
from __future__ import annotations

from langchain_core.messages import AIMessage, HumanMessage

from leanagent import config
from leanagent.logging_setup import log
from leanagent.middleware.retry import BudgetExhausted

_SUMMARY_REQUEST = (
    "【系统通知】你在执行漏洞验证任务时被中断（{reason}）。"
    "请基于以上你自己的完整操作记录，输出总结（中文）：\n"
    "1. 已完成的进度（哪些 primitive/步骤验证了，结果如何，关键数值/地址/证据）\n"
    "2. 失败的尝试和原因\n3. 下次该试什么方向\n"
    "4. 末尾附上『已落盘的关键文件清单』及其验证状态"
    "（下次会话优先读取这些文件继续，不要重新评估）。\n"
    "只输出总结内容，不要再调用任何工具。"
)


def _history_text(msgs: list) -> str:
    """历史消息压成纯文本（保留角色标注 + 截断超长工具结果）。"""
    lines = []
    for m in msgs:
        role = type(m).__name__.replace("Message", "").upper()  # HUMAN/AI/TOOL
        content = getattr(m, "content", "")
        content = content if isinstance(content, str) else str(content)
        # 工具结果可能极长——截断保 token
        if len(content) > 1500:
            content = content[:1500] + f"...(truncated {len(content)} chars)"
        tool_calls = getattr(m, "tool_calls", None) or []
        tc = " ".join(f"[调工具 {c.get('name')}]" for c in tool_calls)
        lines.append(f"{role}: {content} {tc}".strip())
    return "\n".join(lines)


async def summarize_and_raise(exc: Exception, prefix: str,
                              budget_mw=None, msgs: list | None = None,
                              model=None) -> BudgetExhausted:
    """总结后返回带正文的 BudgetExhausted（调用方 raise 它）。

    消息来源优先级：显式传入 msgs > budget_mw.last_messages（middleware 抛
    异常时 ainvoke 拿不到 state，从 before_model 缓存的最新消息恢复）。
    """
    stop = str(exc).split("\n", 1)[0]
    if msgs is None:
        msgs = budget_mw.last_messages if budget_mw is not None else []
    log.warning(f"{prefix} ⚠ {stop}，转总结轮")
    if not msgs:
        return BudgetExhausted(f"{stop}\n[{stop}]（无会话记录）")

    log.info(f"{prefix} → 基于历史记录请求总结...")
    try:
        llm = model or config.MODEL
        r = await llm.ainvoke([
            HumanMessage(content=(
                f"以下是一个漏洞分析 agent 的完整会话记录（含它调用的工具与结果）：\n\n"
                f"{_history_text(msgs)}\n\n"
                + _SUMMARY_REQUEST.format(reason=stop)
            )),
        ])
        summary = r.content if isinstance(r.content, str) else str(r.content)
        if summary.strip():
            log.info(f"{prefix} ← LLM 总结完成 ({len(summary)} chars)")
            return BudgetExhausted(f"{stop}\n{summary}")
        return BudgetExhausted(f"{stop}\n[{stop}]（总结轮无输出）")
    except Exception as e:
        log.warning(f"{prefix} 总结轮失败({type(e).__name__})，用 fallback")
        last = ""
        for m in reversed(msgs):
            if isinstance(m, AIMessage) and m.content:
                last = m.content if isinstance(m.content, str) else str(m.content)
                break
        return BudgetExhausted(f"{stop}\n{last[:3000]}\n\n[{stop}]" if last else f"{stop}\n[{stop}]（fallback 无输出）")
