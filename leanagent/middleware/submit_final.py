"""SubmitFinalMiddleware：拦截 submit_final_result → schema 校验 → 违约反馈重调（超限抛异常）。"""
from __future__ import annotations

import json

from langchain.agents.middleware.types import AgentMiddleware
from langchain_core.messages import ToolMessage
from langchain_core.tools import tool

from leanagent.logging_setup import log
from leanagent.middleware.retry import BudgetExhausted


@tool
def submit_final_result(result_json: str) -> str:
    """当完成所有调查、推理和工具调用后，调用此工具提交最终的结构化结果。

    result_json：最终报告的完整 JSON 字符串（严格符合本任务 System Prompt
    中定义的输出 Schema）。提交后任务结束——这是唯一的结束方式，
    不要以普通文本形式输出最终结果（那不会被采纳）。
    提交若被拒（Schema 不符）会收到具体错误，修正后重新调用本工具。
    """
    return "submitted"


class SubmitFinalMiddleware(AgentMiddleware):
    """拦截 submit_final_result tool_call（awrap_tool_call 层）：

    1. 解出 result_json → dict
    2. schema_class 校验（pydantic）：
       - 合法 → 报告暂存 self.report（_run_subagent 闭包读取），工具返回成功提示
       - 违约 → 返回具体错误 ToolMessage，LLM 看到错误修正后重新调用；
         违约超过 max_rejects 次 → 抛 BudgetExhausted（编排层 attempt 重试）
    3. route_gate 终检（gate 非 None 时，双保险）：
       - 未 declare_route → 拒绝（先声明路线）
       - 失败报告（result_status != EXPLOIT_SUCCESS）但从未 redeclare 换线
         → 拒绝："路线证伪必须先 redeclare_route 换路线，不允许直接交 FAILED"
         （实测 0013/0018 '提前放弃'病的闸门化）
    """

    def __init__(self, schema_class, max_rejects: int = 3, prefix: str = "",
                 gate=None):
        super().__init__()
        self.schema_class = schema_class
        self.max_rejects = max_rejects
        self.prefix = prefix
        self.gate = gate  # RouteGateMiddleware 实例（None = 不做路线终检）
        self.report: str = ""  # 校验通过的报告（model_dump JSON）；空 = 未提交
        self.rejected_count = 0  # 违约次数

    def _reject(self, reason: str, tid: str) -> ToolMessage:
        self.rejected_count += 1
        if self.rejected_count > self.max_rejects:
            raise BudgetExhausted(f"submit_rejected({self.rejected_count - 1}次重调后仍不符 Schema: {reason[:120]})")
        return ToolMessage(
            content=f"【提交被拒({self.rejected_count}/{self.max_rejects})】{reason}。"
                    "修正后重新调用 submit_final_result。",
            tool_call_id=tid,
        )

    async def awrap_tool_call(self, request, handler):
        tc = request.tool_call
        if tc.get("name") != "submit_final_result":
            return await handler(request)
        tid = tc.get("id", "") or ""
        args = tc.get("args") or {}
        raw = args.get("result_json", "")
        if isinstance(raw, dict):
            data, raw_str = raw, json.dumps(raw, ensure_ascii=False)
        else:
            raw_str = str(raw or "").strip()
            try:
                data = json.loads(raw_str)
            except json.JSONDecodeError as e:
                return self._reject(f"result_json 不是合法 JSON（{e}）", tid)
        if not isinstance(data, dict):
            return self._reject("result_json 必须是一个 JSON 对象（dict），不是数组/标量", tid)
        # schema 校验（延迟导入防循环依赖）
        from leanagent.schemas import validate_schema
        model, err = validate_schema(data, self.schema_class)
        if model is None:
            return self._reject(f"报告不符合 {self.schema_class.__name__} Schema：{err}", tid)
        # ---- route_gate 终检（gate 非 None 时）----
        if self.gate is not None:
            # ① 未声明路线 → 拒绝
            if not self.gate.declared:
                return self._reject(
                    "尚未 declare_route 声明利用路线（本会话必须先声明才能干活）。"
                    "先 read_file 读 skills/*/SKILL.md，再调 declare_route，"
                    "然后重新提交本报告（route_declaration 字段按声明填写）。", tid)
            # ② 失败结论但从未换线 → 拒绝（提前放弃闸门）
            exec_res = data.get("execution_result") or {}
            result_status = str(exec_res.get("result_status", "")).upper()
            n_decl = len(self.gate.declarations)
            if result_status not in ("EXPLOIT_SUCCESS", "") and n_decl < 2:
                return self._reject(
                    f"提交失败结论（{result_status or 'FAILED'}）但从未重新 "
                    "declare_route 换路线——当前路线被证伪时【必须】先重新声明"
                    "候选路线（declare_route，可先 read_file 新类别的 skill）继续"
                    "尝试，主路线 + 备选路线穷尽后才允许提交失败。修正：要么继续"
                    "利用，要么重新声明路线后再提交。", tid)
        # 合法：暂存规范化报告（model_dump 字段齐全）
        self.report = model.model_dump_json(ensure_ascii=False)
        log.info(f"{self.prefix} ✓ submit_final_result 收到最终报告"
                 f"（{self.schema_class.__name__} 校验通过，{len(self.report)} chars）")
        return ToolMessage(
            content="【已采纳】报告已通过 Schema 校验并提交。任务结束，不要再调用任何工具。",
            tool_call_id=tid,
        )
