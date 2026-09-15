"""子 agent 模块（Contract-First 确定性编排用）。

cli 一键全链路 → orchestrator 确定性 S1-S4（make_runners）：
S1 recon / S2 semantic / S3 primitive（per bug，submit_final_result 提交 PrimitiveReport）/ S4 exploit。
LLM 子 agent 用分阶段工具集 + deepagents 内置 execute/filesystem 自主操作。
"""
from leanagent.agents.exploit import EXPLOIT, EXPLOIT_PROMPT, S4_USER_TEMPLATE, make_exploit_tools
from leanagent.agents.recon import make_recon_tools
from leanagent.agents.semantic import SEMANTIC, SEMANTIC_PROMPT, S2_USER_TEMPLATE, make_semantic_tools
from leanagent.agents.verify import VERIFY, PRIMITIVE_PROMPT, S3_USER_TEMPLATE, make_verify_tools

# 所有子 agent 共用的 system prompt 头（行为规则 + workspace 约束）。
# workspace 路径由编排层 format 注入（{WORKSPACE}）。
BASE_PROMPT = """\
## 行为要求
- **每次调工具前简述意图**，不要盲目连续调同一工具。
- 工具返回后先判断是否有用，再决定下一步。
- ★最终报告必须通过调用 **submit_final_result** 工具提交
（result_json 参数 = 完整报告 JSON 字符串，严格符合 Schema）——
这是唯一的结束方式，普通文本输出的报告不会被采纳；
提交被拒时会收到具体错误，按错误修正后重新调用。

## Workspace（硬性约束）
你的 workspace 是 `{WORKSPACE}`（目标二进制所在目录）。
【所有】读写文件操作（write_file / read_file / PoC 脚本 / exploit.py /
调试脚本 / payload / 中间产物）都限制在这个目录内。
禁止写到或读取其他路径（如 /work 根目录、/tmp、家目录、/root）。
二进制本身、技能库（skills）除外（只读）。

"""


def base_prompt(workspace: str) -> str:
    """BASE_PROMPT 填入 workspace 路径，子 agent system prompt 的统一头部。"""
    return BASE_PROMPT.format(WORKSPACE=workspace)


__all__ = [
    "make_recon_tools", "base_prompt",
    "SEMANTIC", "SEMANTIC_PROMPT", "S2_USER_TEMPLATE", "make_semantic_tools",
    "VERIFY", "PRIMITIVE_PROMPT", "S3_USER_TEMPLATE", "make_verify_tools",
    "EXPLOIT", "EXPLOIT_PROMPT", "S4_USER_TEMPLATE", "make_exploit_tools",
]
