"""主 agent 入口 + analyze_binary 工具（编排收进工具，cli 不再做编排）。

analyze_binary 工具：确定性 S1→S2→S3（所有 bug）→S4 + workspace 隔离 +
report.md 生成——编排逻辑集中在此（原 cli 的全链分支迁移过来）。
主 agent：识别任务 → 调 analyze_binary → 汇总输出（只做一次委派，不探索）。
"""
from __future__ import annotations

import asyncio
import json
import re as _re
import shutil as _shutil
import time as _time
from pathlib import Path

from langchain_core.tools import tool

from deepagents import create_deep_agent

from leanagent import config


def _make_task_workspace(binary: str) -> str:
    """为本任务创建隔离 workspace：<容器工作目录>/workspace/<父目录名>-<timestamp>/。

    绝对路径锚定（config.CONTAINER_WORKDIR）。题目目录的 target 若已 patchelf
    （rpath 绝对路径指回题目目录的题目 libc），workspace 拷贝自动继承该环境。
    """
    src = Path(binary).resolve()
    task_name = src.parent.name or "task"
    task_name = _re.sub(r"[^A-Za-z0-9._-]", "_", task_name)
    ts = _time.strftime("%Y%m%d-%H%M%S")
    ws = (Path(config.CONTAINER_WORKDIR) / "workspace" / f"{task_name}-{ts}").resolve()
    ws.mkdir(parents=True, exist_ok=True)
    _shutil.copy2(src, ws / src.name)
    from leanagent.logging_setup import log
    log.info(f"=== Task Workspace: {ws}（target 已拷入） ===")
    return str(ws / src.name)


def make_main_agent(backend):
    """构建主 agent（入口路由：识别 → analyze_binary → 汇总）。"""

    @tool
    def analyze_binary(binary_path: str, vuln_desc: str = "") -> str:
        """对二进制跑完整漏洞分析（S1 侦察 → S2 语义 → S3 原语验证 → S4 exploit）。

        传入二进制路径（容器内绝对路径如 /work/test/target），可选漏洞描述。
        自动创建隔离 workspace（workspace/<名>-<timestamp>/），跑完返回结果摘要
        （exploit 成功与否 / verified bug / 报告路径）。
        完整产物（stage1-4.json / exploit.py / report.md / full_run.log）都在
        binary 所在目录。
        """
        from leanagent.orchestrator import run_stage
        binary = _make_task_workspace(binary_path)
        ws = str(Path(binary).parent)

        # 日志双写：控制台 handler 一直在，这里加 FileHandler 写 full_run.log
        from leanagent.logging_setup import init_file_logging, log
        fh = init_file_logging(ws)
        try:
            log.info("=== Full Run: S1 → S2 → S3（所有 bug） → S4 ===\n")
            log.info("--- S1 Recon ---")
            s1 = run_stage(backend, binary, vuln_desc, 1)
            log.info("--- S2 Semantic ---")
            s2 = run_stage(backend, binary, vuln_desc, 2, context_path=f"{ws}/stage1.json")
            log.info("--- S3 Primitive（所有 bug） ---")
            s3 = run_stage(backend, binary, vuln_desc, 3, context_path=f"{ws}/stage2.json")

            s4 = {}
            if s3.get("verified_bug_ids"):
                log.info("--- S4 Exploit ---")
                s4 = run_stage(backend, binary, vuln_desc, 4, context_path=f"{ws}/stage3.json")
            else:
                log.warning("⚠ S3 无 verified bug，跳过 S4")

            # 最终报告
            try:
                from leanagent.report import generate_report
                report_path = generate_report(ws)
                if report_path:
                    log.info(f"📄 渗透报告：{report_path}")
            except Exception as e:
                log.warning(f"⚠ 报告生成失败：{type(e).__name__}: {e}")
        finally:
            from leanagent.logging_setup import LOG
            LOG.removeHandler(fh)
            fh.close()

        return json.dumps({
            "binary": binary,
            "exploit_success": s4.get("success"),
            "final_exploit_path": s4.get("final_exploit_path"),
            "error": s4.get("error"),
            "report": f"{ws}/report.md",
            "workspace": ws,
        }, ensure_ascii=False)

    MAIN_PROMPT = """\
你是 LeanAgent 主 agent。你只做一件事：**对用户给的二进制路径调用 analyze_binary 工具**。

## ★第一动作（必须，不探索）
用户给了二进制路径 → 立即调 analyze_binary(binary_path=<路径>)。
- 用户若附漏洞描述，作为 vuln_desc 参数传入。
- 不要 ls/grep/read_file 验证路径，不要自己分析二进制。

## 输出
工具返回 JSON 后，用中文简述结果（成功与否 / exploit 路径 / 报告路径）。
"""

    return create_deep_agent(
        model=config.MODEL,
        tools=[analyze_binary],
        system_prompt=MAIN_PROMPT,
        backend=backend,
        name="main",
    )
