# LeanAgent 设计方案与验证报告

> 最后更新：2026-09-02 | 验证状态：10/10 全链路稳定成功（root shell）

## 一、系统概览

LeanAgent 是 GLM 驱动的多阶段二进制漏洞 PoC 自动生成系统：给定一个 pwn 二进制（无任何先验知识、无参考答案），自主完成侦察→漏洞分析→原语验证→写出稳定拿 shell 的 exploit。

```
leanagent run <binary>
    ↓ 一键全链路（确定性编排，无 LLM 调度层）
S1 Recon（LLM 侦察）→ ReconReport
    ↓ stage1.json
S2 Semantic（静态语义分析）→ VulnerabilityReport（所有 bug）
    ↓ stage2.json
S3 Primitive（逐 bug 推导+动态验证）→ PrimitiveReport（per bug）
    ↓ stage3.json
S4 Exploit（skill 库辅助写 exploit）→ root shell + EXPLOIT_SUCCESS
```

- 模型：glm-5.2（thinking disabled），火山网关直连
- 框架：deepagents 0.7.5（LangGraph），backend 文件系统隔离
- 部署：容器（bind mount /work），每轮干净 workspace

## 二、最终验证结果

10 轮全链路稳定性测试（每轮干净 workspace、独立从零分析、无参考答案）：

| 轮 | 结果 | 耗时 | 工具调用 | GLM 调用 |
|---|---|---|---|---|
| 1 | ✅ root shell | 84m | 277 | 252 |
| 2 | ✅ | 77m | 245 | 228 |
| 3 | ✅ | 69m | 235 | 215 |
| 4 | ✅ | 80m | 327 | 287 |
| 5 | ✅ | 80m | 226 | 202 |
| 6 | ✅ | 90m | 334 | 300 |
| 7 | ✅ | 60m | 231 | 211 |
| 8 | ✅ | 28m | 128 | 107 |
| 9 | ✅ | 102m | 411 | 389 |
| 10 | ✅ | 30m | 164 | 142 |

**10/10 = 100% 成功率**（对照：旧架构宽容抽取时代 ≈45%）。第 1 轮甚至完整推出 ARB_WRITE 两步写原语（9/9 primitive VERIFIED）。

## 三、问题→解决方案全记录（按层组织）

### 3.1 输出契约层（最重要的演进）

**问题链**：
1. 模型从不遵守"只输出 JSON"的 prompt 指令——历史所有成功都靠宽容抽取（`_extract_json_objects` 括号配平从 prose+JSON 混合文本里抠出 JSON）
2. 严格契约（`_is_pure_json`）后模型 100% 违约——prose+JSON 混合是它的固有输出习惯
3. API 层 `response_format: json_object`（服务端强制）引入新问题：中间状态汇报被迫 JSON 化，`{"error": ...}` 被误判为 final answer，S2/S3 严重缩水
4. 模型还会"写文件躲避"——把报告 write_file 到磁盘、回答里只给摘要

**最终方案：`submit_final_result` 工具**（根治）
- final answer 的交付变成显式 tool_call：`submit_final_result(result_json="<报告 JSON>")`
- JSON 在 `tool_call.function.arguments` 里**天然合法**（框架/网关在工具调用层保证序列化）
- 中间轮任何输出（JSON 或 prose）都不会终结回合——只有显式 submit 才结束
- 事件循环拦截：检测到该 tool_call 即取 args 设为 final_answer，干净返回
- 实测：S1 自测一次通过（23886 chars 完整报告）、10/10 轮零格式失败

**辅助机制**（仍保留作兜底）：
- `_is_pure_json` 机器判定 + 轻量重发（违约时原文回喂一次调用修复）
- schema 严格校验：空壳拒绝（status 必填非空——全默认值对象过不了校验）、多对象违约反馈重发

### 3.2 S3 Primitive 分析层

**问题链**（六轮回归暴露的渐进认知缺口，每个补丁解决一层）：
1. **定级拔高**：LLM 把"固定目标写"标成 ARB_WRITE → 第四章验收标准（地址可控才叫 ARB；宽度截断法：4 字节 size 别名 8 字节指针的高半=小正数活路/低半=死路）
2. **枚举截断**：负索引只扫到最后一组 FILE 指针就停 → 枚举深度锚点（必须贯穿整个 .data/.bss 到段边界）
3. **自引用形态没见过** → 虚构 buf/len 教学示例（通用、非题目化）演示"别名+两步写"组合，含自引用指针槽位形态
4. **否定性结论无证据**：纯推理否定（"应该没有自引用"）不复查 → 否定性结论证据标准与肯定性对等（必须实测 dump 槽位值）
5. **过度求证**：PoC 已 VERIFIED 还 gdb 逐指令复核烧光预算 → 两级完成模型（单 primitive 定案标准 + BUG 级收工闸门）

**关键设计**：
- 两级完成模型：第四章=单 primitive 完成标准（VERIFIED 定案/死路证毕），第十七章=BUG 级收工（所有 primitive 定案才准 COMPLETED）
- 两步写升级法（RELATIVE→ARB）：写 *P 的原语 + P 可写 → 第一次改 P 为 Y、第二次写 *P=Y
- 工具纪律 7 条：同参数重复检测、参数微调死循环、精确断点（ignore 跳过禁堆 c）、PIE 地址坑、pwntools 禁令（禁 interactive）、零等待（不等 alarm）、单脚本原则

### 3.3 S4 Exploit 层

**问题链**：
1. 卡点不是利用知识而是 FILE 泄露 NUL 截断 → skill 补两步法（先写 8 字节去 NUL 再 %s 泄指针）
2. 泄露 I/O 竞态 → 全 I/O 禁 recvuntil 顺序假设（recvrepeat+find(marker)）、base 双检查（页对齐且>0x10000）、分级重试
3. "验证稳定性"烧预算 → shell 一次即定案 + 脚本内重试循环
4. 证据被摘要截断 → run_script 最小过滤 + key evidence 前置
5. skill 不读 → 任务说明第一步必读（跳过=违反流程）
6. 写大 payload 踩写后检查 → check_byte 预检工具 + 缓冲区搬迁技巧

**skill 渐进披露**：deepagents 原生 `create_deep_agent(skills=[...])`——frontmatter 路由表自动进 system prompt，按需加载匹配分册（路径 config 驱动，不写死）。六分册：fsop（含 House of Apple 2 完整字段表、NUL 截断两步法、分级重试、写后检查坑）/tcache-poisoning/got-overwrite/rop-ret2libc/format-string/data-only

**判定语义**：schema 严格枚举（EXPLOIT_SUCCESS 是唯一成功拼写）；失败报告也是最终结论（收下不重试，LLM 应在会话内自己换路线）

### 3.4 基础设施层

| 问题 | 解决 |
|---|---|
| 墙钟切在 write_file 中间，"(argument truncated)" 半截落盘毁好文件 | 安全点终止（in_flight_tool 时不打断，on_tool_end 后复查）+ _TruncatedWriteGuard 双保险 |
| 撞钟总结截断/丢失 | 完整 progress_log 生成总结，[INTERRUPTED_SUMMARY] 标记注入 attempt N+1（唯一总结来源，无弱兜底），总结含已落盘文件清单 |
| force-JSON 出半成品被误收 | in_progress/无 VERIFIED 不收，带总结重试 |
| 长输出截断丢证据 | run_script 输出最小过滤（只滤 [x]/[DEBUG]/curses）+ key evidence（uid=/LEANAGENT_SUCCESS/flag{）前置 |
| backend.execute 12K 截断 | _result.json 直接 open() 读写 |
| 容器旧 DASHSCOPE key 抢先 | key 候选 HUOSHAN_KEY 第一 |
| 容器无终端 curses 噪音 | run_script 自动 TERM=xterm + PWNLIB_NOTERM |
| 每轮残留污染 | 每轮 find 清空 workspace（只留 target） |

### 3.5 模型接入层

- glm-5.2 + `thinking: {type: disabled}`（enable_thinking:false 会致 content 全空——实测陷阱）
- 不用 response_format（中间状态误判问题，见 3.1）
- GLM 行为特性应对：过度求证→完成即收工；prose 收尾→submit 工具；行为方差大→关键约束写成硬闸门而非建议

## 四、总体设计思路

1. **确定性编排**：流程顺序由 Python（cli/orchestrator）保证，LLM 只在每个 stage 内自主；无"主 agent 决定下一步"的不可控跳转层
2. **Contract-First**：每阶段一个固定 Schema（pydantic 校验），违约即反馈重发，不宽容抽取、不猜语义；submit 工具让契约在工具调用层天然满足
3. **知识分层**：通用纪律进 system prompt（每轮可见），领域方法论进 skill（按需加载），题目事实只来自 S1 现场侦察（prompt 零题目化）
4. **证据驱动**：VERIFIED 必须有 DYNAMIC 证据+落盘 PoC；否定性结论同样需要实测证据；成功率优先于 primitive 强度（短链 > 强原语长链）
5. **预算纪律**：工具预算/墙钟/attempt 三层上限；安全点终止防数据损坏；撞钟带完整总结续命
6. **竞态容错**：承认 I/O 竞态不可彻底消除——脚本内重试 + 一次 shell 即定案 + 分级重试（读失败同进程重抓 < 重开进程）

## 五、架构组件清单

```
leanagent/
├── cli.py              # 一键全链 / --stage 分步 / --exploit-only
├── orchestrator.py     # run_stage（S1-S3）+ exploit runner（S4）；重试/总结/判定逻辑
├── agent_util.py       # _run_subagent（submit 拦截/安全点墙钟/死循环检测）+ submit_final_result + guards
├── config.py           # 模型/网关/skills 源（环境变量可覆盖）
├── schemas.py          # 6 个报告 Schema + 校验（空壳拒绝）
├── agents/             # 四个 stage 的 System Prompt（零题目化）+ User 模板
│   ├── recon.py / semantic.py（静态化：13 纯静态工具）/ verify.py / exploit.py
└── skills/             # 六分册方法论（fsop 最全）
└── tools/bintools.py   # 23 工具（run_script/check_byte 输出摘要与证据前置等）
```

## 六、经验沉淀

- **prompt 例子会把规则圈死在例子的领域**：写规则先提炼本质再举例，例子领域覆盖要对称（虚构 buf/len 示例的教训）
- **skill 是工具结果，隔几十轮调用后注意力衰减**：关键铁律必须进 system prompt
- **兼容性设计会掩盖根因**：宽容抽取让"模型从不守约"隐藏了 20+ 轮；严格契约才暴露真相，倒逼出 submit 工具的正解
- **给模型留合规出口比堵死更有效**：submit 工具顺应"模型想用工具表达"的天性
- **观察方式会造成误判**：日志 300 字符截断、多 driver 并行写日志，都产生过"问题在 X"的错误结论——先核实现场再动手

## 七、HKCERT CTF 12 题 Batch 实测（2026-09-05/06，11/12）

**模式**：全流程逐题（每题只跑 1 次，无论成败），主链路 analyze_binary（workspace 隔离），S4 = 30min 墙钟 × 8 attempt × 250 工具预算。

| # | 题目 | 结果 | 路线 |
|---|------|------|------|
| 0001 | ROP | ✅ | （早前） |
| 0002 | Signature (II) | ✅ | LD_LIBRARY_PATH 依赖链劫持 |
| 0003 | Babyheap | ✅ | 盲注 oracle 泄堆/libc → tcache poisoning → __free_hook |
| 0004 | Heap | ❌ | 8 attempt 耗尽 |
| 0005 | Cage | ✅ | seccomp 过滤器反转 → CODE_EXECUTION |
| 0006-0010 | help-you-2 / seccomp2 / warmup / cooldown / fortunecookie1 | ✅ | 其中 3 题 40 分钟一次过 |
| 0011 | fortunecookie2 | ❌ | S4 判定两 bug 无可行路线 |
| 0012 | leaking | ✅ | |

**本批沉淀的关键能力**（详见对应实现）：
- **题目原生 libc 还原**：带 vulnerable/libc.so 的题 patchelf（--force-rpath 必须：DT_RUNPATH 不传导间接依赖）→ 0003/0005 攻克的前提
- **依赖链劫持路线**：S1 必查清单（RPATH/解析链）→ S2 劫持分类 → S3 CODE_EXECUTION 原语（0002）
- **盲注 oracle 泄露**（skill: blind-oracle-leak）：第一原则——盲注不读内存、不经过任何输出过滤；信号源是边界检查的通过/拒绝（0003）
- **tcache 自指循环陷阱**（skill: tcache-poisoning）：double-free 后 fd 自指环的三个修法（0003）
- **环境层漏洞类别**：seccomp 配置错误（SCMP_ACT_ALLOW 反转）、库加载顺序（0002/0005）——S2 跨边界审查原则覆盖
- **失败 2 题共性**：分析正确但利用链走不通（能力边界，非机制故障）
