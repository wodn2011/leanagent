"""容器内完整 build_agent + 带 rubric 的简单 invoke，隔离 test_smoke 的 APIConnectionError。

check_agent（无 RubricMiddleware/response_format）成功；test_smoke（完整）失败。
本测试用完整 build_agent + 带 rubric 的简单 invoke（小 transcript），快速判定：
- 通 → 完整配置在简单 invoke 下 OK，test_smoke 失败是大 payload/多轮瞬态。
- 不通 → 完整配置本身触发连接问题。
"""
import base64

from leanagent.backends import ensure_container, exec_in_container

SCRIPT = r'''
from leanagent.agent import build_agent
from langchain_core.messages import HumanMessage
agent = build_agent()
try:
    r = agent.invoke({
        "messages": [HumanMessage(content="Reply with just the word OK.")],
        "rubric": "the assistant reply contains the word OK",
    })
    print("OK last:", str(r["messages"][-1].content)[:300])
except Exception as e:
    print("ERR:", type(e).__name__, str(e)[:800])
'''


def main() -> None:
    name = ensure_container()
    print(f"[full] container: {name}")
    b64 = base64.b64encode(SCRIPT.encode("utf-8")).decode("ascii")
    out, _ = exec_in_container(name, f"echo {b64} | base64 -d | python3 -", timeout=180)
    print(out)


if __name__ == "__main__":
    main()
