"""GLM 经 DashScope OpenAI 兼接口的 tool-calling 连通测试。

全链路前提：glm-5.2 经兼容接口必须能稳定发起 tool call。
不依赖 docker 镜像（用 StateBackend + 一个纯函数 echo 工具）。
"""
from langchain_core.messages import HumanMessage
from langchain_core.tools import tool

from leanagent import config


@tool
def echo(text: str) -> str:
    """回显给定文本。用于连通性测试。"""
    return f"ECHO::{text}"


def main() -> None:
    from deepagents import create_deep_agent

    agent = create_deep_agent(
        model=config.MODEL,
        tools=[echo],
        system_prompt="你是测试 agent。用户让你回显文本时，必须调用 echo 工具。",
        name="glm-toolcall-test",
    )
    result = agent.invoke({
        "messages": [HumanMessage(content="请用 echo 工具回显：hello from glm")],
    })
    saw_tool_call = False
    echo_output = None
    for m in result["messages"]:
        if getattr(m, "tool_calls", None):
            saw_tool_call = True
            print("TOOL_CALLS:", m.tool_calls)
        tc = getattr(m, "tool_call_chunks", None) or []
        if tc:
            saw_tool_call = True
        if m.type == "tool":
            echo_output = m.content
    print("SAW_TOOL_CALL:", saw_tool_call)
    print("ECHO_OUTPUT:", echo_output)
    print("LAST_MSG:", str(result["messages"][-1].content)[:300])
    print("RESULT:", "PASS" if saw_tool_call else "FAIL")


if __name__ == "__main__":
    main()
