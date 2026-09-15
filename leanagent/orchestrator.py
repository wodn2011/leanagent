"""确定性编排：make_runners（S1-S4 runner 工厂）+ run_stage（单阶段 1-4）。

主 agent 的 analyze_binary 工具调 run_stage×4（S1→S2→S3→S4）；每阶段产物 stage{N}.json（含 ctx_json 往返）。
"""
from __future__ import annotations

import asyncio
import json
import os

from langchain_core.messages import HumanMessage

from leanagent import config
from leanagent.agent_util import _run_subagent
from leanagent.logging_setup import log
from leanagent.middleware import BudgetExhausted, InlineScriptGuard, TruncatedWriteGuard
from leanagent.agents import (
    EXPLOIT_PROMPT, PRIMITIVE_PROMPT, S2_USER_TEMPLATE, S3_USER_TEMPLATE,
    S4_USER_TEMPLATE, SEMANTIC_PROMPT,
    base_prompt,
    make_exploit_tools, make_recon_tools, make_semantic_tools, make_verify_tools,
)
from leanagent.agents.recon import RECON_PROMPT
from leanagent.schemas import (
    ContextStore, ExploitReport, PrimitiveReport, ReconReport, StepResult,
    VulnerabilityReport, build_task_description, validate_schema,
)


async def _run_stage(
    name: str, backend, ctx: ContextStore, read_fields: list[str], binary: str,
    bug_id: str, task_desc: str, tools: list, system_prompt: str, schema_class,
    max_tool_calls: int = 30, max_seconds: float = 300, max_attempts: int = 3,
    middleware: list | None = None, msg_override: str | None = None,
    skills: list[str] | None = None, route_gate_enabled: bool = False,
) -> list:
    """通用 stage（薄编排）：_run_subagent → submit JSON 解析为 model。

    行为逻辑全在 middleware（submit 校验/retry/预算）；BudgetExhausted（撞钟/
    多次无 submit）由 _run_subagent 抛出 → 本层 attempt 重试（带总结 feedback）。
    """
    system_prompt = base_prompt(os.path.dirname(binary) or ".") + system_prompt
    feedback = ""
    for attempt in range(max_attempts):
        msg = (msg_override or build_task_description(ctx, read_fields, binary, bug_id, task_desc)) + feedback
        log.info(f"=== {name} (bug_id={bug_id or '-'})"
                 + (f" attempt {attempt + 1}/{max_attempts}" if attempt else "") + " ===")
        try:
            text = await _run_subagent(
                backend, msg, tools=tools, system_prompt=system_prompt, schema_class=schema_class,
                name=name, max_tool_calls=max_tool_calls, max_seconds=max_seconds,
                log_prefix=f"[{name}:{bug_id}]" if bug_id else None,
                middleware=middleware, skills=skills,
                route_gate_enabled=route_gate_enabled,
                no_summary=(attempt == max_attempts - 1),  # 最后一次：总结没人消费，直接判失败
            )
        except BudgetExhausted as e:
            if attempt == max_attempts - 1:
                break  # 最后一次 attempt 失败：不再总结（无 attempt 可带），直接判失败
            # 撞钟/多次无 submit → 带总结 attempt 重试
            log.warning(f"[{name}] ⚠ BudgetExhausted（总结全文）:\n{str(e)}")
            summary = str(e)
            if "\n" in summary:
                summary = summary.split("\n", 1)[1]  # 去掉 stop reason 头，取总结正文
            feedback = (
                f"\n\n## 上次会话被中断（本会话是新开的重新尝试）\n"
                f"### 上次会话总结（已验证的发现直接复用，不要重复 recon/gdb）：\n{summary}\n"
                f"→ 直接基于已有发现继续，完成必须调用 submit_final_result(result_json=报告 JSON) 提交。"
            )
            continue
        # submit 路径返回的已是 middleware 校验通过的 model_dump JSON → 直接信，不再重复校验
        return [schema_class.model_validate_json((text or "").strip())]
    return []


# ---------------------------------------------------------------------------
# S1-S4 runner 工厂（runner 直接写自己的 ctx namespace + 返回 StepResult）
# ---------------------------------------------------------------------------

def make_runners(backend, binary: str, vuln_desc: str):
    """返回 4 个 runner: recon/semantic/impact_validate/exploit（async ctx->StepResult）。"""

    async def recon(ctx: ContextStore) -> StepResult:
        # LLM 驱动侦察（RECON_PROMPT）→ 富 ReconReport
        reports = await _run_stage(
            "recon", backend, ctx, [], binary, "",
            "对 ## Binary 节的二进制做 S1 侦察：用 bin 工具（checksec/elf_info/identify_libc/sections/"
            "symbols/global_vars/got_plt/disassemble/cfg/probe_io/list_strings）收集事实，按 RECON_PROMPT "
            "的输出格式（stage/schema_version/status/binary/security/runtime/interface/memory/functions/"
            "attack_surfaces/facts/uncertainties/raw）返回 ReconReport JSON 单行。",
            make_recon_tools(backend), RECON_PROMPT, ReconReport, max_tool_calls=40, max_seconds=600,
        )
        if reports:
            ctx.recon_report = reports[0]
        return StepResult(
            success=bool(reports),
            error=None if reports else "recon LLM 无有效输出",
            output={"recon_report": reports[0].model_dump() if reports else None},
        )

    async def semantic(ctx: ContextStore) -> StepResult:
        # ★S2 User prompt 用 S2_USER_TEMPLATE 拼接（{BINARY_PATH}+{S1_JSON}=recon_report）
        s1_json = json.dumps(ctx.recon_report.model_dump() if ctx.recon_report else {}, ensure_ascii=False)
        msg = S2_USER_TEMPLATE.format(BINARY_PATH=binary, S1_JSON=s1_json)
        reports = await _run_stage(
            "semantic", backend, ctx, [], binary, "", "",
            make_semantic_tools(backend), SEMANTIC_PROMPT, VulnerabilityReport,
            max_tool_calls=40, max_seconds=600, msg_override=msg,
        )
        if reports:
            ctx.vulnerability_report = reports[0]
        return StepResult(
            success=bool(reports),
            output={"vulnerability_report": reports[0].model_dump() if reports else None},
            error="no vulnerability report" if not reports else None,
        )

    async def impact_validate(ctx: ContextStore) -> StepResult:
        """S3 = Primitive 分析+验证（PRIMITIVE_PROMPT，per target_bug_id）。读 vulnerability_report
        vulnerabilities[]（可按 ctx.target_bug 过滤），每 bug 推导 primitive→preconditions→生成+执行
        PoC→PrimitiveReport。"""
        verified_bug_ids: list[str] = []
        vr = ctx.vulnerability_report
        if not vr or not vr.vulnerabilities:
            return StepResult(success=False,
                              output={"primitive_reports": [], "verified_bug_ids": []},
                              error="ctx.vulnerability_report 为空（先 --stage 2）")
        vulns = vr.vulnerabilities
        if ctx.target_bug:
            vulns = [v for v in vulns if v.get("bug_id") == ctx.target_bug]
            if not vulns:
                return StepResult(success=False,
                                  output={"primitive_reports": [], "verified_bug_ids": []},
                                  error=f"target_bug={ctx.target_bug} 不在 vulnerability_report.vulnerabilities[]")
        for v in vulns:
            bug_id = v.get("bug_id") or "BUG-?"
            # ★S3 User prompt 用 S3_USER_TEMPLATE 拼接（S1 recon + S2 结果 + BUG_ID），
            # 给 LLM S1 事实省去重复 recon
            s1_json = json.dumps(ctx.recon_report.model_dump() if ctx.recon_report else {}, ensure_ascii=False)
            s2_json = json.dumps(vr.model_dump(), ensure_ascii=False)
            msg = S3_USER_TEMPLATE.format(
                BINARY_PATH=binary, S1_Recon_JSON=s1_json,
                S2_RESULT_JSON=s2_json, BUG_ID=bug_id,
            )
            reports = await _run_stage(
                "impact", backend, ctx, [], binary, bug_id, "",
                make_verify_tools(backend), PRIMITIVE_PROMPT, PrimitiveReport,
                max_tool_calls=80, max_seconds=1200,
                middleware=[InlineScriptGuard()],
                msg_override=msg,
            )
            ctx.primitive_reports.extend(reports)
            if any(p.get("status") == "VERIFIED" for r in reports for p in r.primitives):
                verified_bug_ids.append(bug_id)
        success = bool(verified_bug_ids)
        return StepResult(
            success=success,
            output={"primitive_reports": [{"target_bug_id": r.target_bug_id, "status": r.status,
                                           "primitives": r.primitives} for r in ctx.primitive_reports],
                    "verified_bug_ids": verified_bug_ids},
            error=None if success else "no verified primitive",
        )

    async def exploit(ctx: ContextStore) -> StepResult:
        # S4 Exploit：S4_USER_TEMPLATE 注入 S1 recon + S2 漏洞分析 + S3 全部 Primitive 报告。
        # 墙钟 20 分钟/attempt，重试 2 次（共 3 轮）；所有产物存 workspace（binary 所在目录）。
        verified = [r.target_bug_id for r in ctx.primitive_reports
                    if any(p.get("status") == "VERIFIED" for p in r.primitives)]
        if not verified:
            return StepResult(success=False, output={"final_exploit_path": ""}, error="no verified bug to exploit")
        workspace = os.path.dirname(binary) or "."
        exploit_path = f"{workspace}/exploit.py"
        s1_json = ctx.recon_report.model_dump_json(ensure_ascii=False) if ctx.recon_report else "{}"
        s2_json = ctx.vulnerability_report.model_dump_json(ensure_ascii=False) if ctx.vulnerability_report else "{}"
        s3_json = json.dumps([r.model_dump() for r in ctx.primitive_reports], ensure_ascii=False)
        # 任务数据（S1-S3 JSON + verified 列表）进 user msg；路径/产物规则进 system prompt
        # （_run_stage 会拼 _WS_DECL，这里把 exploit 专属规则也传进去）
        msg = S4_USER_TEMPLATE.format(
            BINARY_PATH=binary, S1_RECON_JSON=s1_json, S2_VULN_JSON=s2_json, S3_PRIMITIVES_JSON=s3_json,
        ) + f"\n\n## 已验证 bug\n{verified}。"
        # ★S4 与 S1-S3 统一走 _run_stage（attempt≤3 + BudgetExhausted 带总结重试都在里面）
        reports = await _run_stage(
            "exploit", backend, ctx, [], binary, "",
            "", make_exploit_tools(backend), EXPLOIT_PROMPT, ExploitReport,
            max_tool_calls=250, max_seconds=1800, max_attempts=8,
            middleware=[InlineScriptGuard(), TruncatedWriteGuard()],
            msg_override=msg,
            skills=[config.SKILLS_SOURCE],  # ★原生渐进披露：skill 路由表由框架注入
            route_gate_enabled=True,  # ★S4 强制 skill 路由（declare_route 前只放行 read_file）
        )
        # _run_stage 返回 [] = 3 次 attempt 全未提交；有报告 = submit 最终结论（成败都收下）
        if not reports:
            ctx.final_report = {"status": "failed", "summary": "exploit 3 次 attempt 均未提交"}
            return StepResult(success=False, output={"final_exploit_path": ""},
                              error="exploit not stable")
        r0 = reports[0].model_dump()
        status = (r0.get("status") or "").upper()
        exec_res = r0.get("execution_result") or {}
        result_status = (exec_res.get("result_status") or "").upper()
        # 判定严格按枚举值：result_status == EXPLOIT_SUCCESS 是唯一成功拼写
        if result_status == "EXPLOIT_SUCCESS":
            ctx.final_exploit_path = (r0.get("exploit_path")
                                      or r0.get("exploit_specification", {}).get("filename")
                                      or exploit_path)
            ctx.final_report = {"status": "ok", "summary": r0.get("summary") or "exploit success"}
            log.info(f"✅ Exploit 成功（status={status}, result_status={result_status}）。")
            return StepResult(success=True, output={"final_exploit_path": ctx.final_exploit_path})
        # 失败结论：收报告（含 failure_analysis），流程结束
        last_summary = (r0.get("summary") or exec_res.get("failure_analysis")
                        or r0.get("notes_and_limitations") or "(无 summary)")
        ctx.final_report = {"status": "failed", "summary": last_summary}
        log.info(f"[exploit] LLM 最终结论: {result_status or status}（收下失败报告，不重试）")
        return StepResult(success=False, output={"final_exploit_path": ""},
                          error="exploit not stable")

    return {"recon": recon, "semantic": semantic, "impact_validate": impact_validate,
            "exploit": exploit}


def run_stage(backend, binary: str, vuln_desc: str, stage: int,
              context_path: str = "", out_path: str = "", bug_filter: str = "") -> dict:
    """只跑指定 stage（1=recon,2=semantic,3=primitive,4=exploit）。

    从 --context 的 ctx_json 恢复 ctx，跑一个 runner，保存 stage{N}.json
    （含 ctx_json 供下一 stage --context 用）。S1-S4 统一走本入口。
    """
    workspace = os.path.dirname(binary) or "."
    key = {1: "recon", 2: "semantic", 3: "impact_validate", 4: "exploit"}.get(stage)
    if key is None:
        return {"error": f"stage={stage} 非法（1-4）"}

    # ---- 恢复 ctx ----
    if stage == 1:
        ctx = ContextStore()
    else:
        if not context_path:
            return {"error": f"--stage {stage} 需要 --context <prev.json>（先用 --stage {stage - 1} 产出）"}
        # 直接 open() 读全文件（backend.execute 受 max_output_bytes 截断，大 ctx_json 会被截坏）
        try:
            with open(context_path, "r", encoding="utf-8") as f:
                raw = f.read()
        except FileNotFoundError:
            return {"error": f"--context {context_path} 未找到"}
        except Exception as e:
            return {"error": f"读 --context {context_path} 失败: {e}"}
        if not raw.strip():
            return {"error": f"--context {context_path} 为空"}
        try:
            saved = json.loads(raw)
        except Exception as e:
            return {"error": f"--context {context_path} JSON 解析失败: {e}"}
        try:
            ctx = ContextStore.model_validate_json(saved.get("ctx_json", "{}"))
        except Exception as e:
            return {"error": f"--context ctx_json 解析失败: {e}"}

    # ---- 显式依赖检查 ----
    if stage >= 2 and ctx.recon_report is None:
        return {"error": "S2/S3/S4 需要 S1 侦察结果（recon_report）：先 --stage 1 并用其输出作 --context"}
    if stage >= 3 and ctx.vulnerability_report is None:
        return {"error": "S3/S4 需要 S2 漏洞报告（vulnerability_report）：先 --stage 2 并用其输出作 --context"}
    if stage >= 4 and not ctx.primitive_reports:
        return {"error": "S4 需要 S3 原语报告（primitive_reports 含 VERIFIED）：先 --stage 3 并用其输出作 --context"}
    if stage == 3 and bug_filter:
        ctx.target_bug = bug_filter  # S3 只处理该 bug_id（--bug 过滤）

    # ---- 跑单 stage ----
    # 日志 FileHandler 只挂一个：主链路时 analyze_binary 已挂（这里跳过）；
    # --stage 分步模式时这里挂（binary 所在目录 full_run.log，append）。
    # ★不再嵌套挂第二个——WSL drvfs 上多句柄写同一文件有竞态（实测部分轮
    #   full_run.log 全空，只有最后 cli 补写的汇总）。
    from leanagent.logging_setup import LOG, init_file_logging
    _target = os.path.abspath(os.path.join(os.path.dirname(binary) or ".", "full_run.log"))
    already = any(os.path.abspath(getattr(h, "baseFilename", "")) == _target for h in LOG.handlers)
    own_fh = None if already else init_file_logging(os.path.dirname(binary) or ".", mode="a")
    try:
        runners = make_runners(backend, binary, vuln_desc)
        result = asyncio.run(runners[key](ctx))
    finally:
        if own_fh is not None:
            LOG.removeHandler(own_fh)
            own_fh.close()

    # ---- 输出 JSON（含 ctx_json 供下一 stage --context）----
    out: dict = {
        "stage": stage,
        "binary": binary,
        "success": result.success,
        "error": result.error,
        "ctx_json": ctx.model_dump_json(ensure_ascii=False),
    }
    if stage == 1:
        out["recon_report"] = ctx.recon_report.model_dump() if ctx.recon_report else None
    elif stage == 2:
        out["vulnerability_report"] = ctx.vulnerability_report.model_dump() if ctx.vulnerability_report else None
    elif stage == 3:
        out["primitive_reports"] = [r.model_dump() for r in ctx.primitive_reports]
        out["verified_bug_ids"] = [r.target_bug_id for r in ctx.primitive_reports
                                   if any(p.get("status") == "VERIFIED" for p in r.primitives)]
    elif stage == 4:
        out["final_exploit_path"] = ctx.final_exploit_path
        out["final_report"] = ctx.final_report

    # ---- 保存（直接 open 写——backend.upload_files 走 docker exec 也行，但 open 简单可靠）----
    save_path = out_path or f"{workspace}/stage{stage}.json"
    try:
        with open(save_path, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
        out["_saved"] = save_path
        log.info(f"[stage{stage}] 保存 → {save_path}")
    except Exception as e:
        out["_save_error"] = f"{type(e).__name__}: {e}"
    return out
