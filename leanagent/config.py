"""集中配置：GLM 接入、路径、轮次上限。

GLM 经 DashScope 的 OpenAI 兼容接口接入。deepagents 的 `resolve_model`
（`deepagents/_models.py`）对 `BaseChatModel` 实例**原样放行**——所以这里
直接传 `ChatOpenAI` 实例给 `create_deep_agent(model=...)`，**不要**用
`"dashscope:glm-5.2"` 字符串（框架无 dashscope provider profile，会报错）。
"""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

# 从 .env 读，但不覆盖已存在的真实环境变量
load_dotenv()

_BASE_DIR = Path(__file__).resolve().parent.parent


def _glm_key() -> str:
    """按候选顺序探测 GLM API key（.env 里 DASHSCOPE_API_KEY 存的是火山网关 key）。"""
    for k in ("HUOSHAN_KEY", "DASHSCOPE_API_KEY", "ZHIPU_API_KEY", "GLM_API_KEY", "OPENAI_API_KEY"):
        v = os.environ.get(k)
        if v:
            return v
    raise RuntimeError(
        "未找到 GLM API key。请设置环境变量 DASHSCOPE_API_KEY（或在 .env 中填写）。"
    )


def _glm_base() -> str:
    # 火山网关直连（OpenAI 兼容 /v1/chat/completions，容器内可达，不走本地代理）
    return os.environ.get(
        "GLM_BASE_URL",
        "https://st8tp3ajl0df3n8b8l8qu.apigateway-cn-beijing.volceapi.com/v1",
    )


def _glm_model() -> str:
    return os.environ.get("GLM_MODEL", "glm-5.2")


MODEL = ChatOpenAI(
    model=_glm_model(),
    base_url=_glm_base(),
    api_key=_glm_key(),
    temperature=0.2,  # PoC 构造偏确定，低温度
    # ★glm-5.2 关 thinking（火山网关用 thinking.type=disabled；enable_thinking:false
    #   会致 content 全空——实测 glm-5.3/5.2 均如此）。关掉后响应快、token 全给正文。
    # 最终报告格式由 submit_final_result 工具保证（工具调用层序列化 JSON），
    # 不用 API 层 response_format 强制（实测会致中间状态汇报被误判为最终答案）。
    max_tokens=16384,
    timeout=300,        # 请求超时（秒）
    max_retries=5,      # 兼接口瞬态连接断重试
    extra_body={"thinking": {"type": "disabled"}},
)

# grader 用同一模型；省钱可换更轻量（设 GRADER_MODEL 环境变量）
GRADER_MODEL = ChatOpenAI(
    model=os.environ.get("GRADER_MODEL", _glm_model()),
    base_url=_glm_base(),
    api_key=_glm_key(),
    temperature=0.0,
    max_tokens=16384,
    timeout=300,
    max_retries=5,
    extra_body={"thinking": {"type": "disabled"}},
)

# 宿主侧产出目录（PoC 脚本落盘处）
WORKDIR_HOST: Path = Path(os.environ.get("LEANAGENT_WORKDIR", _BASE_DIR / "workspace"))
WORKDIR_HOST.mkdir(parents=True, exist_ok=True)

# bind mount：把宿主目录挂到容器 /work，文件宿主/容器共享（测试用，省 docker cp）
MOUNT_HOST: Path = Path(os.environ.get("LEANAGENT_MOUNT", _BASE_DIR))

# 容器内工作目录（= 挂载点）
CONTAINER_WORKDIR = "/work"

# 利用方法论技能库源路径（deepagents 原生渐进披露：create_deep_agent(skills=...) 传 backend 相对路径，
# frontmatter 路由表自动进 system prompt，LLM 匹配后框架自动加载 SKILL.md 全文——prompt 不写死路径）
SKILLS_SOURCE = os.environ.get("LEANAGENT_SKILLS", "leanagent/skills")

# Reflexion 上限（RubricMiddleware 的 max_iterations）
MAX_POC_ITERATIONS = int(os.environ.get("LEANAGENT_MAX_ITERATIONS", "15"))

# pwn 容器镜像（现成镜像，不本地构建）
IMAGE = os.environ.get(
    "LEANAGENT_IMAGE",
    "swr.cn-north-4.myhuaweicloud.com/securityllm/harvester:latest",
)
