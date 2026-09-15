"""LeanAgent: 二进制漏洞 PoC 编写 agent（Contract-First 确定性编排，基于 deepagents + GLM-5.2）。

给定有漏洞的二进制（+ 可选漏洞描述），产出经客观验证的漏洞 Primitive（Benchmark 截止 VERIFIED=True），
加分拿 shell。设计：cli 确定性编排（维护 ContextStore，不经 LLM 主 agent）+ 6 标准 Schema +
validate_schema 校验 + verify_primitive 客观判定 + 子 agent（semantic/primitive/verify/exploit）。
"""

__version__ = "0.2.0"
