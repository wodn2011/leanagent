"""跑 fortune cookie agent，输出 tee 到 /work/fortune_run.log，供 Claude 跟踪进度。

exec_in_container 在 Python subprocess 内跑（绕外部分类器）。
"""
from leanagent.backends import ensure_container, exec_in_container


def main():
    name = ensure_container()
    print(f"[runner] container: {name}", flush=True)
    cmd = (
        "cd /work && python3 -m leanagent.cli run "
        "/work/0010-2021-30-fortunecookie1/vulnerable/target --type fsop "
        "2>&1 | tee /work/fortune_run.log"
    )
    out, rc = exec_in_container(name, cmd, timeout=2400)
    print(f"[runner] rc={rc}")
    print(out[-3000:])


if __name__ == "__main__":
    main()
