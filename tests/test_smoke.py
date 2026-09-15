"""端到端冒烟：复用常驻容器 → 容器内编译样本 + 跑 agent + 验证。

容器 leanagent-pwn 常驻，不每次 start/stop。直接跑：python tests/test_smoke.py
"""
from __future__ import annotations

from leanagent.backends import ensure_container, exec_in_container


def run_smoke() -> None:
    name = ensure_container()  # 幂等复用常驻容器（挂载项目 + 传 GLM key）
    print(f"[smoke] container: {name}")
    # 确保依赖（click/rich/python-dotenv）容器内装好
    print("[smoke] pip install -e /work in container...", flush=True)
    out, _ = exec_in_container(name, "pip install -e /work -q 2>&1 | tail -5", timeout=900)
    print("[smoke] pip:", out[-400:] if out else "(no output)")

    # 工具链
    out, _ = exec_in_container(
        name,
        "gdb --version 2>&1 | head -1; python3 -c 'import pwn; print(\"pwn ok\")' 2>&1",
        timeout=60,
    )
    print("[smoke] toolchain:", out.strip())

    # 编译样本到 /tmp/vuln
    out, rc = exec_in_container(
        name,
        "cd /work/tests/fixtures && gcc -fno-stack-protector -no-pie -o /tmp/vuln vuln.c 2>&1 "
        "&& chmod +x /tmp/vuln && file /tmp/vuln",
        timeout=120,
    )
    print("[smoke] compile:", out.strip()[-300:])
    assert "ELF" in (out or ""), f"compile failed: {out}"

    # 容器内跑 agent (cli)
    out, rc = exec_in_container(
        name,
        "python3 -m leanagent.cli run /tmp/vuln "
        "--vuln-desc /work/tests/fixtures/vuln_stack.md --type stack_overflow",
        timeout=1800,
    )
    print("[smoke] agent run (tail):\n" + (out or "")[-2500:])

    # 客观二次验证：容器内跑 verify_poc_runs
    vcmd = (
        "python3 -c \""
        "from leanagent.tools.verify import _VERIFY_RUNS_SCRIPT;"
        "from leanagent.tools._util import run_py;"
        "from leanagent.backends import make_local_backend;"
        "b=make_local_backend();"
        "r=run_py(b,_VERIFY_RUNS_SCRIPT,'/work/poc.py','3');"
        "print(r.output)\""
    )
    vout, _ = exec_in_container(name, vcmd, timeout=120)
    print("[smoke] verify_poc_runs:\n" + (vout or ""))
    stable = "STABLE=True" in (vout or "")
    print("[smoke] RESULT:", "PASS" if stable else "FAIL")
    print(f"[smoke] container kept running (常驻): {name}")


def test_stack_overflow_smoke() -> None:
    run_smoke()


if __name__ == "__main__":
    run_smoke()
