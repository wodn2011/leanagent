"""LLM 渗透报告生成：把 S1-S4 全部结果 + 报告模板喂给 LLM → report.md。

一次无工具 LLM 调用（轻量，数据已齐，纯写作任务）。
"""
from __future__ import annotations

import json
from pathlib import Path

from leanagent import config
from langchain_core.messages import HumanMessage

REPORT_TEMPLATE = """\
# 渗透测试报告：<目标名>

（以下为参考模板结构，实际内容以你手里的数据为准，如实呈现）

## 1. 任务概述
- 目标：<一句话任务目标>
- 目标文件：<路径>
- 文件类型：<ELF 类型/架构>
- 安全防护：<RELRO/Canary/NX/PIE/libc 版本>
- 分析结果：<已验证的最高级别后果（如任意代码执行/任意地址读写/
  信息泄露/仅拒绝服务）——按实际验证到的能力定级>

## 2. 已确认漏洞
漏洞 <BUG 编号>：<一句话漏洞名>
- CWE 分类：<CWE-xxx（名称）——按根因对号>
- 严重程度：<严重/高/中/低——结合漏洞类别与已验证原语能力判断>
- 漏洞位置：<函数名（地址）>
- 漏洞详情：<2-4 句根因：什么检查缺失、攻击者能做什么>
- 已验证原语：<该 bug 的已验证原语（类型/验证方式/关键证据）>
- 关键别名发现：<该 bug 相关的别名/索引关系（如有）>
- 修复建议：<该 bug 的一条具体建议>

## 3. 利用链与后果
<若完成端到端利用：编号步骤（从初始泄露到最终效果）+ 关键偏移；
若无：已验证原语可组合出的最高后果评估 + 当前卡点>

## 4. 方法论
<分析路径：文件识别 → 防护分析 → 逆向 → 原语验证 → 利用构造>

## 5. 产物路径
<表格：exploit/PoC/stage json/日志 的实际路径>
"""

REPORT_PROMPT = """\
你是渗透测试报告撰写人。基于以下已完成的全链路分析数据，写一份中文渗透测试报告（Markdown）。

要求：
- 按下面的模板结构组织（章节可按实际内容微调）；
- 简洁：每节只写关键信息，漏洞详情 2-4 句，利用链每步一行；
- 如实：结论以实际验证到的证据为准——分析结果反映【已验证的最高级别后果】
  （如仅验证到任意地址读写就写任意地址读写，不要拔高到"远程代码执行"，
  shell/命令执行只是可能后果之一，不要默认以拿 shell 为目标表述）；
- 产物路径用实际路径；
- 严重程度结合漏洞类别与已验证原语能力判断；
- ★已验证原语【按 bug 归属】写进每个漏洞的条目里
  （S3 的 primitive_reports 有 target_bug_id 字段对应）；
- ★每个漏洞标注【bug 编号】（S2 的 bug_id）和【CWE 分类】（按根因对号）；
- ★【修复建议】也放进每个漏洞的条目里（不单列章节）；
- 只输出 Markdown 报告本体，不要输出其他解释。

报告模板参考：

""" + REPORT_TEMPLATE + """

## 分析数据

### 目标二进制
{BINARY_PATH}

### S1 侦察结果（安全防护/架构/libc）
{S1_JSON}

### S2 漏洞分析（bug 列表/根因/影响）
{S2_JSON}

### S3 已验证原语（primitive/证据/别名发现）
{S3_JSON}

### S4 利用结果（成功与否/利用链/证据）
{S4_JSON}
"""


def generate_report(workspace: str) -> str:
    """从 workspace 的 stage json 数据喂给 LLM 生成 report.md。返回报告路径。"""
    ws = Path(workspace)

    # ---- 收集各阶段数据 ----
    s1_json = s2_json = s3_json = s4_json = "{}"
    binary_path = ""
    for name in ("stage1.json", "stage2.json", "stage3.json", "stage4.json"):
        p = ws / name
        if not p.exists():
            continue
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        if name == "stage1.json":
            binary_path = d.get("binary", "")
            s1_json = json.dumps(d.get("recon_report") or {}, ensure_ascii=False)
        elif name == "stage2.json":
            s2_json = json.dumps(d.get("vulnerability_report") or {}, ensure_ascii=False)
        elif name == "stage3.json":
            s3_json = json.dumps({
                "primitive_reports": d.get("primitive_reports") or [],
                "verified_bug_ids": d.get("verified_bug_ids") or [],
            }, ensure_ascii=False)
        elif name == "stage4.json":
            s4_json = json.dumps({
                "success": d.get("success"),
                "error": d.get("error"),
                "final_exploit_path": d.get("final_exploit_path"),
                "final_report": d.get("final_report"),
                "summary": d.get("summary"),
            }, ensure_ascii=False)

    if not binary_path:
        # 从 stage2/3 兜底
        for name in ("stage2.json", "stage3.json"):
            p = ws / name
            if p.exists():
                try:
                    binary_path = json.loads(p.read_text(encoding="utf-8")).get("binary", "")
                    if binary_path:
                        break
                except Exception:
                    pass

    # ---- 数据截断保护（S3 报告可能很大）----
    def _cap(s: str, n: int = 12000) -> str:
        return s if len(s) <= n else s[:n] + f"\n...（截断，原 {len(s)} 字符）"

    prompt = REPORT_PROMPT.format(
        BINARY_PATH=binary_path,
        S1_JSON=_cap(s1_json, 8000),
        S2_JSON=_cap(s2_json, 12000),
        S3_JSON=_cap(s3_json, 15000),
        S4_JSON=_cap(s4_json, 4000),
    )

    try:
        resp = config.MODEL.invoke([HumanMessage(content=prompt)])
        content = resp.content if hasattr(resp, "content") else str(resp)
    except Exception:
        return ""

    # 剥可能的 ```markdown 围栏
    s = content.strip()
    if s.startswith("```"):
        nl = s.find("\n")
        if nl > 0:
            s = s[nl + 1:]
        if s.rstrip().endswith("```"):
            s = s.rstrip()[:-3]
        s = s.strip()

    out = ws / "report.md"
    out.write_text(s, encoding="utf-8")
    return str(out)
