"""Contract-First Schema + ContextStore + Schema 校验。

每个 SubAgent 只输出一个固定 Schema（字段固定 + version），通过 submit_final_result
工具提交（JSON 在 tool_call 参数里天然合法）。cli 维护唯一 ContextStore，
每阶段产物 stage{N}.json（含 ctx_json 往返）。Schema 校验违约 → 反馈重发。

多 bug：primitive_reports 是 list，按 target_bug_id 关联。最终 exploit.py（LLM 自主）。
"""
from __future__ import annotations

import json
import warnings
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

# 消噪：各 Schema 的 `schema: str` 字段名与 BaseModel 内置属性同名，每次 import 刷十几行
# UserWarning。字段名是 LLM 契约的一部分（改不了），警告无信息量——静默。
warnings.filterwarnings("ignore", message='Field name "schema" in .* shadows')

# 统一 model_config：禁止未知字段（防 field drift "type" vs "bug_type"）
_SCHEMA_CONFIG = ConfigDict(extra="forbid", protected_namespaces=())


# ===========================================================================
# 6 标准 Schema（固定字段 + version）
# ===========================================================================

class ReconReport(BaseModel):
    """S1 LLM 侦察富报告（RECON_PROMPT 输出）。

    extra=ignore：RECON_PROMPT 输出 schema_version/stage/status/binary/security/... 富字段，
    与 codebase 的 schema/version 约定并存（schema/version 有默认值，validate_schema 自动补）；
    LLM 额外的 schema_version 等不匹配字段被忽略，不报 extra_forbidden。
    """
    model_config = ConfigDict(extra="ignore", protected_namespaces=())
    schema: str = "ReconReport"
    version: str = "1.0"
    stage: str = "S1"
    status: str = ""  # COMPLETED | PARTIAL | FAILED
    binary: dict[str, Any] = Field(default_factory=dict)
    security: dict[str, Any] = Field(default_factory=dict)
    runtime: dict[str, Any] = Field(default_factory=dict)
    interface: dict[str, Any] = Field(default_factory=dict)
    memory: dict[str, Any] = Field(default_factory=dict)
    functions: list[dict[str, Any]] = Field(default_factory=list)
    attack_surfaces: list[dict[str, Any]] = Field(default_factory=list)
    facts: list[dict[str, Any]] = Field(default_factory=list)
    uncertainties: list[dict[str, Any]] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class VulnerabilityReport(BaseModel):
    """S2 LLM 漏洞语义报告（新 SEMANTIC_PROMPT 输出）。

    extra=ignore：LLM 输出 schema_version 等富字段，与 codebase 的 schema/version 约定并存
    （schema/version 有默认值，validate_schema 自动补）。vulnerabilities[] 每项含
    root_cause/attack_surface/security_check/vulnerable_operation/impact[]/evidence[] 等；
    impact 是 Candidate（THEORETICAL|CANDIDATE|UNKNOWN），不冒充 Verified（验证交给 S3）。
    """
    model_config = ConfigDict(extra="ignore", protected_namespaces=())
    schema: str = "VulnerabilityReport"
    version: str = "4.0"
    status: str = ""  # COMPLETED | PARTIAL | FAILED
    summary: dict[str, Any] = Field(default_factory=dict)  # {total_bugs, high/medium/low_severity}
    vulnerabilities: list[dict[str, Any]] = Field(default_factory=list)  # [{bug_id,title,root_cause{type,description},affected_functions,affected_objects,attack_surface,security_check,vulnerable_operation,impact[{type,status,reason}],evidence[{id,type,function,address,description}],confidence,verification_required}]
    non_vulnerabilities: list[dict[str, Any]] = Field(default_factory=list)  # [{function,description,reason}]
    unresolved: list[dict[str, Any]] = Field(default_factory=list)  # [{description,reason,required_next_step}]


class PrimitiveReport(BaseModel):
    """S3 LLM Primitive 分析+验证报告（PRIMITIVE_PROMPT 输出，per target_bug_id）。

    extra=ignore：LLM 输出 stage/schema_version 等富字段。primitives[] 每项含 type/status
    (THEORETICAL|CANDIDATE|VERIFIED|UNKNOWN)/kind(DIRECT|INDIRECT)/chain[]/preconditions[]/
    verification_result{executed,poc_path,written_value,read_value,fault_address,return_code,details} 等。
    VERIFIED 必须有 DYNAMIC 证据 + 落盘 poc-<bug_id>.py（PRIMITIVE_PROMPT 原则 5 自约束）。
    """
    model_config = ConfigDict(extra="ignore", protected_namespaces=())
    schema: str = "PrimitiveReport"
    version: str = "1.2"
    stage: str = "S3"
    target_bug_id: str = ""
    status: str = ""  # COMPLETED | PARTIAL | FAILED
    summary: dict[str, Any] = Field(default_factory=dict)  # {analyzed_bug_id,total_primitives,verified,theoretical,candidate,unknown}
    primitives: list[dict[str, Any]] = Field(default_factory=list)  # [{primitive_id,type,status,kind,source,chain,controlled_element,preconditions,alias_key_findings,verification_plan,mitigations,evidence,verification_result{executed,poc_path,written_value,read_value,fault_address,return_code,details},confidence,notes}]
    non_primitives: list[dict[str, Any]] = Field(default_factory=list)  # [{primitive_id,candidate_type,source_bug,reason}]
    unresolved: list[dict[str, Any]] = Field(default_factory=list)  # [{description,reason,required_next_step}]


class ExploitReport(BaseModel):
    """S4 LLM 利用报告（EXPLOIT_PROMPT 输出）。与 S1-S3 同走 submit_final_result 校验。

    extra=ignore；result_status 是唯一成功判定（EXPLOIT_SUCCESS），status 三态。
    execution_result.evidence 含 shell_obtained/flag_recovered/leaked_addresses 等。
    route_declaration：RouteGate 声明记录（categories/skills_read/rationale，
    与 declare_route 调用一致；换线后按最后一次 redeclare 填写）。
    """
    model_config = ConfigDict(extra="ignore", protected_namespaces=())
    schema: str = "ExploitReport"
    version: str = "1.0"
    stage: str = "S4"
    status: str = ""  # COMPLETED | PARTIAL | FAILED
    route_declaration: dict[str, Any] = Field(default_factory=dict)
    target_summary: dict[str, Any] = Field(default_factory=dict)
    route_planning: dict[str, Any] = Field(default_factory=dict)
    exploit_specification: dict[str, Any] = Field(default_factory=dict)
    exploit_script: dict[str, Any] = Field(default_factory=dict)
    execution_result: dict[str, Any] = Field(default_factory=dict)  # {executed,result_status,evidence{...},failure_analysis}
    notes_and_limitations: str = ""


# ===========================================================================
# Context Store（唯一 JSON Store, 主 agent 维护）
# ===========================================================================

class ContextStore(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    """唯一 Context Store——主 agent 维护，子 agent 只读指定 namespace + 写自己的。

    多 bug：primitive_reports 是 list，按 target_bug_id 关联。
    最终利用脚本：final_exploit_path（exploit.py）。
    """
    recon_report: ReconReport | None = None  # S1 LLM 侦察富报告（RECON_PROMPT 产物）
    vulnerability_report: VulnerabilityReport | None = None  # S2 LLM 漏洞报告（SEMANTIC_PROMPT 产物）
    primitive_reports: list[PrimitiveReport] = Field(default_factory=list)  # ★S3 产物（PRIMITIVE_PROMPT，per target_bug_id）
    target_bug: str = ""  # 运行时过滤器：S3 只处理该 bug_id（--bug 指定，空=全部）；非持久语义，仅本 run 用
    final_exploit_path: str = ""  # <workspace>/exploit.py
    final_report: dict[str, Any] = Field(default_factory=dict)  # S4 exploit 汇总报告


class StepResult(BaseModel):
    """SubAgent/runner 的统一返回格式（success + output dict + error + evidence）。"""
    model_config = ConfigDict(protected_namespaces=())
    success: bool
    schema_version: str = "1.0"
    output: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    evidence: list[dict[str, Any]] = Field(default_factory=list)


# ===========================================================================
# Schema 校验 + task description 构建
# ===========================================================================

SCHEMA_MAP: dict[str, type[BaseModel]] = {
    "ReconReport": ReconReport,
    "VulnerabilityReport": VulnerabilityReport,
    "PrimitiveReport": PrimitiveReport,
    "ExploitReport": ExploitReport,
}


def validate_schema(raw: dict, schema_class: type[BaseModel]) -> tuple[BaseModel | None, str]:
    """校验子 agent 返回的 JSON dict 是否符合 Schema。

    返回 (validated_model, error_msg)。成功 error_msg=""，失败 error_msg=缺字段/类型错误/空必填字段描述。
    extra="forbid" 拒绝未知字段（防 field drift "type" vs "bug_type"）。
    """
    try:
        # 兼容子 agent 返回缺 schema/version 字段——自动补
        schema_name = schema_class.model_fields.get("schema", {}).default or ""
        if "schema" not in raw:
            raw["schema"] = schema_name
        if "version" not in raw:
            raw["version"] = "1.0"
        validated = schema_class(**raw)

        # 关键字段非空校验（防所有字段空但 schema 通过）
        empty_required: list[str] = []
        for name in _REQUIRED_NON_EMPTY.get(schema_class.__name__, []):
            val = getattr(validated, name, None)
            if not val and val != 0 and val is not False:
                empty_required.append(name)
        if empty_required:
            return None, f"必填字段为空: {', '.join(empty_required)}"

        return validated, ""
    except ValidationError as e:
        parts: list[str] = []
        extra_fields = [err["loc"][0] for err in e.errors() if err["type"] == "extra_forbidden"]
        missing = [err["loc"][0] for err in e.errors() if err["type"] == "missing"]
        wrong_type = [f"{err['loc'][0]}({err['type']})" for err in e.errors()
                       if err["type"] not in ("missing", "extra_forbidden")]
        if extra_fields:
            parts.append(f"未知字段(可能 field drift): {', '.join(extra_fields)}")
        if missing:
            parts.append(f"缺字段: {', '.join(missing)}")
        if wrong_type:
            parts.append(f"类型错: {', '.join(wrong_type)}")
        return None, "; ".join(parts) if parts else str(e)[:200]
    except Exception as e:
        return None, f"解析错误: {type(e).__name__}: {str(e)[:200]}"


# 各 Schema 的必填非空字段（防所有字段空但 schema 通过）
_REQUIRED_NON_EMPTY: dict[str, list[str]] = {
    # ★LLM 富报告：全字段有默认值——空壳（VulnerabilityReport() 全默认）也能过 schema 校验。
    # 至少要求 status 非空，防"多 JSON 混输出时空骨架被误存"（full_stab_2 实测：reports[0] 是空壳）。
    "ReconReport": ["status"],
    "VulnerabilityReport": ["status"],
    "PrimitiveReport": ["status"],
    "ExploitReport": ["status"],
}


def build_task_description(
    ctx: ContextStore,
    read_fields: list[str],
    binary_path: str,
    bug_id: str = "",
    task_desc: str = "",
) -> str:
    """生成结构化 task description：## Binary + ## Bug ID + ## Task。

    上游模板路径（S2/S3/S4 的 msg_override）不走本函数；S1 走（read_fields 传 []，
    上下文注入由模板完成）。保留 read_fields 形参兼容签名，但不再做 ctx 切片
    （旧 bug_report/impact_report namespace 已随旧架构删除）。
    """
    lines = ["## Binary", binary_path]
    if bug_id:
        lines += ["", "## Bug ID", bug_id]
    if task_desc:
        lines += ["", "## Task", task_desc]
    return "\n".join(lines)


def ctx_to_json(ctx: ContextStore) -> str:
    """ContextStore → JSON 字符串（注入 user_msg / 显示）。"""
    return ctx.model_dump_json(ensure_ascii=False)
