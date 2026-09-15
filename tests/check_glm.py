"""在容器内复现 GLM 调用，定位 APIConnectionError 根因。

容器内 curl dashscope 通（404），但 langchain_openai ChatOpenAI 调用报错。
经 exec_in_container 在容器内跑 SCRIPT（base64），打印 env/版本/IPv4 curl/SDK 错误。
"""
import base64

from leanagent.backends import ensure_container, exec_in_container

SCRIPT = r'''
import os, subprocess
print("env DASHSCOPE_API_KEY:", "set" if os.environ.get("DASHSCOPE_API_KEY") else "MISSING")
print("env GLM_BASE_URL:", os.environ.get("GLM_BASE_URL", "<unset>"))
print("env GLM_MODEL:", os.environ.get("GLM_MODEL", "<unset>"))
import openai; print("openai", openai.__version__)
import langchain_openai; print("langchain_openai", langchain_openai.__version__)
import httpx; print("httpx", httpx.__version__)

r = subprocess.run(
    ["curl", "-4", "-s", "-o", "/dev/null", "-w", "%{http_code} %{time_total}s\n",
     "--max-time", "10", "-X", "POST",
     "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions"],
    capture_output=True, text=True)
print("curl -4 chat endpoint:", r.stdout.strip(), (r.stderr or "")[:150])

from langchain_openai import ChatOpenAI
m = ChatOpenAI(
    model=os.environ.get("GLM_MODEL", "glm-5.2"),
    base_url=os.environ.get("GLM_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1"),
    api_key=os.environ.get("DASHSCOPE_API_KEY", ""),
    max_retries=0,
)
try:
    r = m.invoke("say hi")
    print("OK:", str(r.content)[:100])
except Exception as e:
    print("ERR:", type(e).__name__, str(e)[:800])
'''


def main() -> None:
    name = ensure_container()
    print(f"[glm] container: {name}")
    b64 = base64.b64encode(SCRIPT.encode("utf-8")).decode("ascii")
    out, _ = exec_in_container(name, f"echo {b64} | base64 -d | python3 -", timeout=60)
    print(out)


if __name__ == "__main__":
    main()
