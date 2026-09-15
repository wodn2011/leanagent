"""容器内最小 agent 测试：create_deep_agent + invoke，隔离 test_smoke 的 APIConnectionError。

直接 ChatOpenAI.invoke 成功，但 test_smoke 的 agent.invoke 报 APIConnectionError。
本测试复现 agent loop 路径，快速确认是否复现。
"""
import base64

from leanagent.backends import ensure_container, exec_in_container

SCRIPT = r'''
import os
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage
from langchain_openai import ChatOpenAI
from deepagents import create_deep_agent

@tool
def echo(text: str) -> str:
    """echo back the text."""
    return f"ECHO::{text}"

m = ChatOpenAI(
    model=os.environ.get("GLM_MODEL", "glm-5.2"),
    base_url=os.environ.get("GLM_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1"),
    api_key=os.environ.get("DASHSCOPE_API_KEY", ""),
    max_retries=0,
)
agent = create_deep_agent(model=m, tools=[echo], system_prompt="test agent", name="t")
try:
    r = agent.invoke({"messages": [HumanMessage(content="use echo to repeat: hello")]})
    print("OK last:", str(r["messages"][-1].content)[:200])
    saw = any(getattr(m, "tool_calls", None) for m in r["messages"])
    print("SAW_TOOL_CALL:", saw)
except Exception as e:
    print("ERR:", type(e).__name__, str(e)[:800])
'''


def main() -> None:
    name = ensure_container()
    print(f"[agent] container: {name}")
    b64 = base64.b64encode(SCRIPT.encode("utf-8")).decode("ascii")
    out, _ = exec_in_container(name, f"echo {b64} | base64 -d | python3 -", timeout=120)
    print(out)


if __name__ == "__main__":
    main()
