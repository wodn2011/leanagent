"""复用常驻容器检查工具链 + 挂载 + 编译 + cli 可启动。

容器 leanagent-pwn 常驻（ensure_container 幂等），不每次 start/stop。
pull / docker / exec 全在 Python subprocess 内，绕过外部命令分类器。
"""
from __future__ import annotations

import subprocess

from leanagent import config
from leanagent.backends import CONTAINER_NAME, ensure_container, exec_in_container


def main() -> None:
    # 1) 确保镜像在
    print(f"[check] pulling {config.IMAGE} ...", flush=True)
    p = subprocess.run(["wsl", "docker", "pull", config.IMAGE],
                       capture_output=True, timeout=900)
    print("[check] pull rc:", p.returncode)
    if p.stderr:
        print("[check] pull stderr (tail):", p.stderr.decode("utf-8", "replace")[-300:])
    if p.returncode != 0:
        return

    # 2) 幂等起/复用常驻容器
    print("[check] ensuring container (常驻) ...", flush=True)
    name = ensure_container()
    print("[check] container:", name)
    try:
        # 3) 工具链检查
        out, _ = exec_in_container(
            name,
            "echo '== gdb =='; gdb --version 2>&1 | head -1; "
            "echo '== python =='; python3 --version 2>&1; "
            "echo '== pwn =='; python3 -c 'import pwn; print(\"ok\")' 2>&1; "
            "echo '== deepagents =='; python3 -c 'import deepagents; print(\"ok\")' 2>&1; "
            "echo '== langchain_openai =='; python3 -c 'import langchain_openai; print(\"ok\")' 2>&1; "
            "echo '== gcc =='; gcc --version 2>&1 | head -1; "
            "echo '== mount /work =='; ls /work 2>&1 | head -8",
            timeout=120,
        )
        print(out)

        # 4) 编译样本到 /tmp/vuln（容器内可靠执行）
        print("[check] == compile vuln ==", flush=True)
        out, rc = exec_in_container(
            name,
            "cd /work/tests/fixtures && gcc -fno-stack-protector -no-pie -o /tmp/vuln vuln.c 2>&1 "
            "&& chmod +x /tmp/vuln && file /tmp/vuln",
            timeout=120,
        )
        print("[check] compile rc:", rc)
        print(out[-500:] if out else "(no output)")

        # 5) 确认 leanagent + 依赖容器内可装、cli 可启动
        print("[check] == pip install + cli --help ==", flush=True)
        out, rc = exec_in_container(
            name,
            "pip install -e /work -q 2>&1 | tail -3; echo '---'; "
            "python3 -m leanagent.cli --help 2>&1 | tail -10",
            timeout=600,
        )
        print("[check] cli rc:", rc)
        print(out[-600:] if out else "(no output)")
    finally:
        print(f"[check] container kept running (常驻): {name}  (复用: wsl docker exec {name} ...)")


if __name__ == "__main__":
    main()
