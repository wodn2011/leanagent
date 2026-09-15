"""RouteGateMiddleware：S4 强制 skill 路由 + 路线声明闸门。

解决的问题（实测 0018/0023）：skill 库有正确方法论但 LLM 自由裁量不读
（0018 六个 attempt 零检索）——知识在库里 ≠ 知识被用。

机制：
1. 闸门——declare_route 之前，除 read_file 外的所有工具调用一律拒绝
   （拒绝消息引导先读 skills/*/SKILL.md 再声明）；
2. declare_route 工具（schema 强约束）：
   - categories：粗粒度利用链类别（枚举，可多选）
   - skills_read：声称已读的 skill 名列表——middleware 校验【调用序事实】：
     每个 skill 名必须在本会话 read_file 过对应 SKILL.md 路径，否则拒绝
     （用工具调用记录当证据，不信任 LLM 自报）；
   - rationale：一句话路线依据（应引用 skill 内容）
   通过 → 记录声明 + 返回匹配 skill 全文（推送兜底）+ 之后全放行；
3. 重复 declare_route（路线被证伪后换线）：同一工具再调一次即可，
   middleware 记录声明历史（declarations），无类别变化限制；
4. SubmitFinalMiddleware 终检（在 submit_final.py 加）：
   - 未声明 → 拒绝
   - 失败报告但只有一次声明（路线证伪了却没换路线就交失败）→ 拒绝：
     "路线不可行必须重新 declare_route 换路线继续，不允许直接交 FAILED"
     ——这正是实测 0013/0018 的'提前放弃'病的闸门化。
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from langchain.agents.middleware.types import AgentMiddleware
from langchain_core.messages import ToolMessage
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from leanagent.logging_setup import log


# ---- 粗粒度利用链类别 → skill 目录映射（skills/ 下的目录名）----
# HEAP/FSOP 也挂 blind-oracle-leak：盲扫是堆/FSOP 执行中常见的中途分支
# （官方解模式：堆漏洞入场 → 负 size 下溢 → 盲扫定位），开局声明 HEAP 时
# 一并推送，避免"中途显形的类别"漏推。
ROUTE_SKILLS: dict[str, list[str]] = {
    "STACK": ["rop-ret2libc", "got-overwrite"],
    "HEAP": ["glibc-version-routing", "tcache-poisoning", "fsop",
             "blind-oracle-leak"],
    "FORMAT_STRING": ["format-string", "partial-brute-format-string"],
    "FSOP": ["fsop", "glibc-version-routing", "blind-oracle-leak"],
    "BLIND_LEAK": ["blind-oracle-leak"],
    "GOT_OVERWRITE": ["got-overwrite"],
    "DATA_ONLY": ["data-only"],
}
VALID_CATEGORIES = list(ROUTE_SKILLS.keys())


class _DeclareArgs(BaseModel):
    """declare_route / redeclare_route 的参数 schema（强约束）。"""

    categories: list[str] = Field(
        ...,
        description="粗粒度利用链类别（可多选）：" + " | ".join(VALID_CATEGORIES),
    )
    skills_read: list[str] = Field(
        ...,
        description="已 read_file 读过全文的 skill 名列表（须与 categories 匹配的"
                    " skills/ 子目录名一致）。每个列出的 skill 必须真实读过，"
                    "middleware 会核对调用记录。",
    )
    rationale: str = Field(
        ...,
        min_length=20,
        description="路线依据（≥20 字符）：为什么选这条路线——应引用所读 skill "
                    "的关键内容（如'SKILL fsop：2.39 无 hook 走 House of Apple 2，"
                    "与本题 ARB_WRITE+Full RELRO 匹配'）。",
    )


def _gate_message() -> str:
    return (
        "【路线闸门】尚未声明利用路线。在调用任何分析/执行工具之前，必须先：\n"
        "1. read_file 读 skills/ 下与本题相关的 SKILL.md 全文（至少读你判断"
        "适用的那几个；read_file 是当前唯一可用的工具）；\n"
        "2. 调用 declare_route(categories=[...], skills_read=[...], rationale=...) 声明路线。\n"
        f"类别枚举：{' | '.join(VALID_CATEGORIES)}。\n"
        "声明通过后所有工具解锁，且匹配 skill 的全文会自动附上。"
    )


class RouteGateMiddleware(AgentMiddleware):
    """declare_route 前只放行 read_file；声明强校验 skills_read 真实性。

    状态（实例属性，编排层每个 attempt 新建实例则天然重置）：
    - declared: 是否已声明（最后一次）
    - declarations: 全部声明历史（含 redeclare）
    - read_skills: 本会话真实 read_file 过的 skill 名集合（调用序证据）
    """

    def __init__(self, skills_root: str = ""):
        super().__init__()
        # skills 根目录：优先显式传参 → 环境变量 → config 默认。
        # 注意 config.SKILLS_SOURCE 是 backend 相对路径（cwd=/work 时即
        # "leanagent/skills"），绝对化处理保证从任何 cwd 读到。
        if not skills_root:
            from leanagent import config
            skills_root = config.SKILLS_SOURCE
        if not os.path.isabs(skills_root):
            # 相对路径：依次尝试 cwd 与 /work（容器内项目根）
            for base in (os.getcwd(), "/work"):
                cand = os.path.join(base, skills_root)
                if os.path.isdir(cand):
                    skills_root = cand
                    break
        self.skills_root = skills_root
        self.declared = False
        self.declarations: list[dict[str, Any]] = []
        self.read_skills: set[str] = set()

    # ---- 工具调用记录：read_file 到 SKILL.md 时登记 skill 名 ----
    def _record_read(self, tool_args: dict[str, Any]) -> None:
        path = str(tool_args.get("file_path", "") or tool_args.get("path", ""))
        # 匹配 <skills_root>/<skill-name>/SKILL.md
        norm = path.replace("\\", "/")
        parts = norm.split("/")
        if len(parts) >= 2 and parts[-1] == "SKILL.md":
            self.read_skills.add(parts[-2])

    # ---- skill 全文推送 ----
    def _load_skill_fulltext(self, names: list[str]) -> str:
        """推送匹配 skill 全文——已 read_file 过的只推一行提示（防双份占用上下文）。

        实测：LLM 声明前已主动 read_file 过的 skill，全文已在上下文里；
        再推一遍全文 = 同一内容双份（~10K tokens 白占）。这里对已读的
        只标注"已在上下文"，未读的才推全文。
        """
        chunks: list[str] = []
        root = Path(self.skills_root)
        for n in names:
            p = root / n / "SKILL.md"
            if n in self.read_skills:
                chunks.append(f"===== SKILL {n}：你已 read_file 读过全文（在上下文里），不重复推送 =====")
                continue
            try:
                text = p.read_text(encoding="utf-8")
                chunks.append(f"===== SKILL {n} 全文 =====\n{text}")
            except OSError as e:
                chunks.append(f"===== SKILL {n} 读取失败：{e} =====")
        return "\n\n".join(chunks) if chunks else "(无匹配 skill)"

    # ---- declare 参数校验（含调用序事实核对）----
    def _validate_declare(self, args: dict[str, Any], tid: str) -> ToolMessage:
        """返回声明结果 ToolMessage（拒绝原因 / 通过+全文推送）。"""
        try:
            parsed = _DeclareArgs.model_validate(args)
        except Exception as e:
            return ToolMessage(
                content=f"【声明被拒】参数不符合 schema：{e}\n"
                        "要求：categories（枚举多选）+ skills_read（真实读过的 "
                        "skill 名）+ rationale（≥20 字符，引用 skill 内容）。",
                tool_call_id=tid)
        # 类别合法性
        bad = [c for c in parsed.categories if c not in VALID_CATEGORIES]
        if bad:
            return ToolMessage(
                content=f"【声明被拒】非法类别 {bad}；合法枚举：{VALID_CATEGORIES}",
                tool_call_id=tid)
        # 匹配 skill 集合（去重）
        matched = []
        for c in parsed.categories:
            for s in ROUTE_SKILLS[c]:
                if s not in matched:
                    matched.append(s)
        # 调用序事实核对：声称读过的必须真读过
        unread = [s for s in parsed.skills_read if s not in self.read_skills]
        if unread:
            return ToolMessage(
                content=f"【声明被拒】skills_read 里的 {unread} 尚未真实 read_file "
                        f"读过（本会话工具调用记录里没有这些 SKILL.md 的读取）。"
                        "先 read_file 读它们的全文（路径 skills/<name>/SKILL.md，"
                        "传 limit=1000），再重新声明。",
                tool_call_id=tid)
        # 至少读过 1 个匹配 skill（防止零阅读声明）
        read_matched = [s for s in matched if s in self.read_skills]
        if not read_matched:
            return ToolMessage(
                content=f"【声明被拒】你声明走 {'/'.join(parsed.categories)} 路线，"
                        f"但还没读过该类别匹配的任何 skill（{matched}）。"
                        "至少 read_file 其中的一个（建议全读），再声明。",
                tool_call_id=tid)
        # 通过：记录 + 推送全文
        record = {
            "categories": parsed.categories,
            "skills_read": parsed.skills_read,
            "rationale": parsed.rationale,
            "matched_skills": matched,
        }
        self.declarations.append(record)
        self.declared = True
        fulltext = self._load_skill_fulltext(matched)
        log.info(f"[route-gate] 路线声明#{len(self.declarations)}："
                 f"{parsed.categories}，已读 {parsed.skills_read}")
        return ToolMessage(
            content=f"【声明通过】路线 {parsed.categories} 已记录"
                    f"（第 {len(self.declarations)} 次声明"
                    f"{'，换线' if len(self.declarations) > 1 else ''}）。\n"
                    f"全部工具已解锁。下面是匹配 skill 的全文（已附入上下文，"
                    f"无需再 read_file）：\n\n{fulltext}",
            tool_call_id=tid)

    # ---- 闸门 ----
    async def awrap_tool_call(self, request, handler):
        tc = request.tool_call
        name = tc.get("name", "")
        args = tc.get("args") or {}
        tid = tc.get("id", "") or ""

        if name == "read_file":
            result = await handler(request)
            # 登记 skill 读取记录（按参数判断，不依赖结果成功）
            try:
                self._record_read(args)
            except Exception:
                pass
            return result

        if name == "declare_route":
            return self._validate_declare(args, tid)

        # 其他所有工具：未声明 → 拒绝
        if not self.declared:
            return ToolMessage(content=_gate_message(), tool_call_id=tid)
        return await handler(request)

    # ---- 注册给 agent 的工具 ----
    @tool
    def declare_route(self, categories: list[str], skills_read: list[str],
                      rationale: str) -> str:
        """声明本次利用路线（S4 第一步；声明前只有 read_file 可用）。

        路线被证伪后可再次调用本工具换路线。

        Args:
            categories: 粗粒度利用链类别（可多选）：STACK | HEAP | FORMAT_STRING |
                FSOP | BLIND_LEAK | GOT_OVERWRITE | DATA_ONLY
            skills_read: 你已 read_file 读过全文的 skill 名（须与 categories
                匹配的 skills/ 子目录名一致；middleware 按调用记录核对真实性）
            rationale: 路线依据（≥20 字符，应引用所读 skill 的关键内容）
        """
        return "declared"
