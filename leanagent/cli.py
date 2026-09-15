"""CLI: leanagent run <binary> —— 主 agent → analyze_binary 工具（确定性 S1-S4）。

默认（无旗标）：主 agent 识别任务 → 调 analyze_binary 工具（内部确定性
S1→S2→S3 所有 bug→S4 + workspace 隔离 + report.md 生成）→ 汇总输出。
--stage N --context ...：只跑单阶段（分步调试用，直接在 binary 所在目录）。
--exploit-only：从 stage3.json 恢复只跑 S4。
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import click

import click


@click.group()
def main() -> None:
    """LeanAgent: 主 agent → analyze_binary 工具 → 确定性 S1-S4 全链路。"""


@main.command()
@click.argument("binary", type=click.Path(exists=True, dir_okay=False))
@click.option("--vuln-desc", "vuln_desc_path", type=click.Path(exists=True, dir_okay=False),
              default=None, help="漏洞描述 markdown（可选；不给则 agent 自主分析）")
@click.option("--stage", type=click.IntRange(1, 4), default=None,
              help="只跑指定 stage：1=S1 Recon,2=S2 Semantic,3=S3 Primitive,4=S4 Exploit。打印输出 JSON 并保存。")
@click.option("--context", "context_path", type=click.Path(), default=None,
              help="上一步的 JSON 文件路径（--stage 2/3 需要，内含 ctx_json）。")
@click.option("--out", "out_path", type=click.Path(), default=None,
              help="本 stage JSON 保存路径（默认 <binary_dir>/stage<N>.json）。")
@click.option("--bug", "bug_filter", default=None,
              help="S3 只处理该 bug_id（如 BUG-001；空=全部）。仅 --stage 3 生效。")
def run(binary: str, vuln_desc_path: str | None,
        stage: int | None, context_path: str | None, out_path: str | None,
        bug_filter: str | None) -> None:
    """跑 PoC agent：默认主 agent → analyze_binary 全链；--stage N 单阶段（1-4）。"""
    vuln_desc = Path(vuln_desc_path).read_text(encoding="utf-8") if vuln_desc_path else ""
    from leanagent.backends import make_local_backend
    from leanagent.logging_setup import log, setup_console_logging
    setup_console_logging()
    # ★pwntools 必须在主线程首次 import（terminal init 要在主线程 signal），
    # 否则工具在 executor 线程里首次 import 会 ValueError: signal only works in main thread。
    # 同时全局静音 pwntools 自身日志（Starting local process 等），不污染 agent 控制台。
    import pwnlib.args  # noqa: F401  触发 pwnlib.term 在主线程初始化
    from pwn import context
    context.log_level = "critical"
    backend = make_local_backend()

    if stage is not None:
        from leanagent.orchestrator import run_stage
        result = run_stage(backend, binary, vuln_desc, stage,
                           context_path or "", out_path or "", bug_filter or "")
        click.echo(json.dumps(result, indent=2, ensure_ascii=False))
        return

    # 默认：主 agent → analyze_binary 工具（内部确定性 S1-S4 + workspace + report）
    # 主 agent 不套子 agent middleware（submit/retry/budget 是子 agent 行为层）
    from leanagent.agent import make_main_agent
    agent = make_main_agent(backend)
    user_msg = (
        f"分析二进制漏洞：{binary}"
        + (f"\n\n漏洞描述：\n{vuln_desc}" if vuln_desc else "")
        + "\n\n请调 analyze_binary 工具跑完整 S1-S4 漏洞分析，返回结果。"
    )
    click.echo(f"=== LeanAgent 主 agent：分析 {binary} ===\n")
    result = asyncio.run(agent.ainvoke({"messages": [{"role": "user", "content": user_msg}]}))
    # 最后一条 AI 消息 = 汇总
    final = ""
    for m in reversed(result.get("messages", [])):
        content = getattr(m, "content", "")
        if getattr(m, "type", "") == "ai" and content:
            final = content if isinstance(content, str) else str(content)
            break
    log.info("=== 主 agent 汇总 ===")
    click.echo(final or "(无汇总)")
    # 汇总直接 append 进 full_run.log（不走 logger——console handler 还挂着会重复打控制台）
    ws = ""
    for m in reversed(result.get("messages", [])):
        if getattr(m, "type", "") == "tool" and "analyze_binary" in str(getattr(m, "name", "")):
            try:
                ws = json.loads(str(m.content)).get("workspace", "")
            except Exception:
                pass
            break
    if ws:
        try:
            with open(f"{ws}/full_run.log", "a", encoding="utf-8") as f:
                f.write(f"=== 主 agent 汇总 ===\n{final or '(无汇总)'}\n")
        except OSError:
            pass


if __name__ == "__main__":
    main()
