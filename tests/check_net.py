"""诊断常驻容器 leanagent-pwn 的外网连通性 + DNS。

容器内调 dashscope 失败（APIConnectionError），宿主侧成功——定位容器网络问题。
"""
from leanagent.backends import ensure_container, exec_in_container


def main() -> None:
    name = ensure_container()
    print(f"[net] container: {name}")
    cmd = (
        "echo '== dashscope =='; "
        "curl -s -o /dev/null -w '%{http_code} %{time_total}s\\n' --max-time 10 "
        "https://dashscope.aliyuncs.com 2>&1; "
        "echo '== baidu =='; "
        "curl -s -o /dev/null -w '%{http_code} %{time_total}s\\n' --max-time 10 "
        "https://www.baidu.com 2>&1; "
        "echo '== dns dashscope =='; "
        "getent hosts dashscope.aliyuncs.com 2>&1 | head -3; "
        "echo '== dns baidu =='; "
        "getent hosts www.baidu.com 2>&1 | head -3; "
        "echo '== resolv.conf =='; "
        "cat /etc/resolv.conf 2>&1 | head -5"
    )
    out, _ = exec_in_container(name, cmd, timeout=90)
    print(out)


if __name__ == "__main__":
    main()
