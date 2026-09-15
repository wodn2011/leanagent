"""子 agent 执行器（极薄）。

行为逻辑在 leanagent/middleware/（submit 校验 / retry / budget / log）
+ leanagent/summary.py（撞钟/异常后的总结轮，框架无异常 hook 只能捕获点调用）。

_run_subagent 只构建 agent + ainvoke + 提取 submit 报告：
- submit 成功 → 返回报告（middleware 校验过的 model_dump JSON）
- 其余一切（BudgetExhausted / GraphRecursionError / 无 submit）→
  summarize_and_raise 带总结正文上抛，编排层（_run_stage）attempt 重试用。
"""
from __future__ import annotations

from langchain_core.messages import HumanMessage

from deepagents import create_deep_agent
from langgraph.errors import GraphRecursionError

from leanagent import config
from leanagent.middleware import (
    RouteGateMiddleware,
    BudgetExhausted, BudgetMiddleware, LogMiddleware, RetryMiddleware,
    SubmitFinalMiddleware, submit_final_result,
)
from leanagent.summary import summarize_and_raise


async def _run_subagent(
    backend,
    msg: str,
    *,
    tools: list,
    system_prompt: str,
    schema_class=None,
    model=None,
    name: str = "subagent",
    max_tool_calls: int = 40,
    max_seconds: float = 600.0,
    middleware: list | None = None,
    skills: list[str] | None = None,
    log_prefix: str | None = None,
    no_summary: bool = False,
    route_gate_enabled: bool = False,
) -> str:
    """构建 agent → ainvoke → 返回 submit 报告文本（异常路径带总结上抛）。"""
    prefix = log_prefix or f"[{name}]"
    route_gate = None
    if route_gate_enabled:
        route_gate = RouteGateMiddleware()
    submit_mw = (SubmitFinalMiddleware(schema_class, prefix=prefix, gate=route_gate)
                 if schema_class is not None else None)
    retry_mw = RetryMiddleware(max_retries=5)
    budget_mw = BudgetMiddleware(max_tool_calls=max_tool_calls, max_seconds=max_seconds)
    log_mw = LogMiddleware(prefix)
    all_mw = ([submit_mw] if submit_mw else []) + [retry_mw, budget_mw, log_mw] + list(middleware or [])
    if route_gate is not None:
        # route_gate 放最外层：先于业务 middleware 拦截（InlineScriptGuard 等）
        all_mw = [route_gate] + all_mw
    agent = create_deep_agent(
        model=model or config.MODEL,
        tools=list(tools) + [submit_final_result]
             + ([route_gate.declare_route] if route_gate is not None else []),
        system_prompt=system_prompt,
        backend=backend,
        name=name,
        middleware=all_mw,
        skills=skills,
    )

    # 状态重置（middleware 实例可复用）
    if submit_mw is not None:
        submit_mw.report = ""
        submit_mw.rejected_count = 0
    retry_mw.reset()
    budget_mw.reset()

    try:
        result = await agent.ainvoke(
            {"messages": [HumanMessage(content=msg)]},
            # recursion_limit 必须覆盖 max_tool_calls：每轮 = model+tools 2 步，
            # 加 retry jump_to 重放/submit 收尾，工具预算 ×4 倍步数才够
            # （实测 80 工具预算撞过 200 上限 → GraphRecursionError 直接崩进程）
            config={"recursion_limit": max(600, max_tool_calls * 4)},
        )
    except (BudgetExhausted, GraphRecursionError) as e:
        # 终止异常：最后一次 attempt（no_summary）直接裸抛；否则总结后带正文重抛
        if no_summary:
            raise e if isinstance(e, BudgetExhausted) else BudgetExhausted(str(e))
        raise await summarize_and_raise(e, prefix, budget_mw, model=model)
    # submit 报告（middleware 校验过的 model_dump JSON）
    if submit_mw is not None and submit_mw.report:
        return submit_mw.report
    # ainvoke 正常返回但无 submit（异常被框架吞掉的路径）→ 同样总结后上抛
    stop = budget_mw.stop_reason or "no_submit"
    if no_summary:
        raise BudgetExhausted(stop)
    msgs = result.get("messages", []) if isinstance(result, dict) else budget_mw.last_messages
    raise await summarize_and_raise(BudgetExhausted(stop), prefix, budget_mw, msgs=msgs,
                                    model=model)
