# LeanAgent S3 稳定性优化记录

目标：S4 不跑，S3 连续 5 把稳定输出**可独立验证**的 PoC。任意一把失败→优化→重计数。
纪律：优化点必须通用，不得出现题目特化指令（cookie/msg/具体 idx 值不进 prompt）。

## 独立验证协议（不靠 LLM 自判）
对每个 `poc_BUG-*.py`：`python3 poc_BUG-XXX.py`，看 `=== PRIM: X ===` 段 + 原始 rc/hex：
- CRASH：rc=139/-11(SIGSEGV)/134(abort) 才算。
- INFO_LEAK：3 次跑泄 ≥2 个不同值才算。
- ARB_READ：泄出受控地址非空字节且非 `(null)` 才算（已预验：idx=-8 泄 stdout FILE* `87 28 ad fb`）。
- ARB_WRITE：同进程 写前读→写→写后读，内容变了才算；仅 hang/timeout/crash/写 NULL 不算。
门槛：≥1 个 primitive 独立验证通过 = 该把“稳定输出 PoC”成立。

## 运行批次（streak 计数，失败即清零重来）

| streak# | 结果 | 独立验证 | 问题 | 优化应用 |
|---------|------|----------|------|----------|
| 1-a | ❌ 失败 | — | S3 BUG-001 attempt1 墙钟超 600s；LLM 用 `execute` 跑内联 `python3 -c "from pwn...process()...recvuntil"` → stdin 死锁 → execute timeout 124 反复 → 烧 600s + 不落盘 poc | ①加 `run_binary` 工具(stdin 管道,服务端 kill,不 hang) ②`_InlineScriptGuard` 中间件(工具层拦截 execute 的内联 `python -c` pwn) ③S3 prompt:跑二进制一律 run_binary/write_file 独立 poc.py/禁内联 pwn/ARB_WRITE 同进程回读通用对策 ④s3_desc 去 msg_size/create_cookie 特化词 |
| 1-b | ✅ 成功(streak=1) | BUG-001: CRASH✓(rc=-11)/ARB_READ✓(8728adfb)/ARB_WRITE✓(同进程回读内容变)/INFO_LEAK✓(3值不同,略乱)；BUG-002: ARB_READ✓(真) / ARB_WRITE✗(LLM误判,我推翻:timeout+10MB无限输出≠回读) / INFO_LEAK✗(正确) / CRASH✗(正确) | BUG-002 LLM 仍把 timeout/无限输出当 ARB_WRITE verified（违反"单独 hang/timeout 不算"）；BUG-002 的 ARB_READ 实为 BUG-001 的 OOB-read 机制（primitive 归属混淆） | 暂不优化——BUG-001 4/4 干净 + BUG-002 因 ARB_READ 真验通过，run 整体成功。观察 #2 记录，若后续 run 出现"仅 ARB_WRITE(timeout) 为唯一 primitive"则优化 |

## 观察（未达优化阈值，跟踪）

### #2 [streak 1-b] BUG-002 ARB_WRITE 误判：LLM 把 timeout/无限输出当 verified
- **现象**：BUG-002 PoC 的 ARB_WRITE：rc=-124 + stdout_len=10MB（写坏 stdout FILE→printf 无限输出→hang→timeout）。LLM 自判 verified=True，但按强信号标准"单独 hang/timeout 不算 ARB_WRITE（需回读比对）"应判 False。我独立验证推翻为 ✗。
- **影响**：本轮未致失败（BUG-002 有真 ARB_READ 兜底）。但若某 run 的 BUG-002 唯一 verified 是此 timeout-ARB_WRITE，则 orchestrator 闸门（信 LLM verified）会假通过 → 我独立验会判失败。latent 风险。
- **暂不优化理由**：prompt 已明文"单独 hang/timeout 不算 ARB_WRITE"，LLM 对 BUG-001 遵守了（真做了回读）；BUG-002 是个例越界。先看 streak 2-5 是否复现，复现且成唯一 primitive 再加工具层/校验层强制（如校验 ImpactReport 的 ARB_WRITE evidence 必须含"回读比对"字样才认）。
### #3 [streak 1-b] BUG-002 primitive 归属混淆
- BUG-002（int-underflow 堆溢出）的 PoC 实际验证的是 BUG-001 的 OOB-read（idx=-8→stdout）。BUG-002 自身 primitive（size=0→read(,-1) 堆溢出）未真验。当前"≥1 primitive/bug"门槛下仍算通过，但质量偏弱。跟踪。

---

## streak 2 = ❌ 失败 → 重置计数为 0，优化后重来
- **现象**：S2 只识别 1 个 bug（int-underflow，难的）；S3 BUG-001 两 attempt 全 600s 墙钟超限 → 返 prose（无 JSON）→ `impact_reports=[]` → verified_bug_ids=[] → run 失败。
- **根因（通用）**：
  1. S2 把同函数（edit_cookie）的两个不同根因（signedness 比较 vs size±1 下溢）合并/漏报，只交 1 个难 bug 给 S3 → S3 无易证目标。
  2. S3 在不可证的 primitive 上死磕，烧满 600s×2 返 prose（违反"≤2 PoC 跑后返 JSON"，且"返 JSON 哪怕全 false 优于 prose"未落实）。
  3. ARB_WRITE 指引只覆盖 OOB-指针写，没覆盖**堆溢出写相邻对象**（int-underflow 的可证路径：size=0→read(,-1) 越界写相邻 chunk→读相邻对象回读比对）。
- **通用修复**：
  1. `semantic.py`：S2 加强"逐函数枚举所有不同 root_cause"+通用 bug 类清单（输入解析/算术/边界/解引用/生命周期）+ 明确"同函数不同根因是不同 bug，别合并"。
  2. `verify.py`：S3 加"别死磕一个 primitive（3 次失败→verified=false 转下一个/返 JSON，返 JSON 优于 prose）"；ARB_WRITE 覆盖堆溢出写相邻对象（写后读相邻对象回读比对）。
  3. `orchestrator.py`：S3 墙钟 600s→360s（防烧，配合"别死磕"收敛；可证 bug ~3min，360s 够）。
- **验证**：compile OK。streak 重置为 0，重跑 streak 1。

---

## streak 1(re-run) = ❌ 失败 → 再优化
- **现象**：S2 这次找到 4 个 BugReport（find-all 生效，但过报——真 bug 2 个）。S3 处理 4 bug：BUG-001 两 attempt 全 360s 墙钟超限返 prose（即便已证 CRASH rc=-11！），BUG-002 attempt1 同样超限返 prose。`impact_reports` 空 → run 失败。
- **根因（通用，主导）**：**S3 不在预算内吐 JSON——返 prose**。LLM 证出 CRASH 后不立即返 JSON（违反"跑出任意 SUCCESS 立即返"），继续死磕 ARB_WRITE → 墙钟切 → `_summarize_progress` 返 prose → `_parse_json_lines` 空 → impact_reports 空 → 整轮失败。**已证的 primitive 因没吐 JSON 而全丢**。prompt 规则被 LLM 忽略。
- **通用修复**：`orchestrator._force_json_emit`——`_run_subagent` 返 prose 时，用一次**无工具** LLM 调用强制吐 schema JSON：把 prose 里的发现作上下文 + `_schema_shape`（递归 model_fields 生成精确 JSON 形状，防 LLM 自创 `primitives:{dict}` 等被 extra=forbid 拒）→ 已证 primitive `verified=true` 落进 JSON。在 `_run_stage` 里 subagent 无 JSON 后立即调（先于 prose-retry，省第 2 次满血重试）。
- **验证**：compile OK；单测 prose→force-emit→`validate_schema` 通过，CRASH/ARB_READ verified=true 正确落 JSON，ARB_WRITE/INFO_LEAK verified=false/theoretical=true。FORCE_JSON_OK=True。
- **保留**：run_binary + guard + find-all + don't-burn + heap-overflow ARB_WRITE + 360s 墙钟（force-JSON 作 prose 兜底，墙钟可不必再降）。streak 重置为 0，重跑。

---

## streak 1(re-run 2) = ❌ 失败 → 再优化（force-JSON 副作用）
- **现象**：run 跑完，3 bug 全报 verified=true，**但 PoC 路径=N/A（仅 poc_BUG-003.py 落盘，BUG-001/002 无 poc 文件）**。force-JSON 把 prose 里"CRASH 已证 rc=-11"等 claim 落进 JSON `verified=true`，但 LLM 没写独立 poc.py（墙钟切前没 write_file）。→ 2/3 bug 无可独立验证的 PoC = 不"稳定输出 poc"。独立验 poc_BUG-003.py：CRASH✓(rc=-11)/ARB_READ✓(8728adfb)/INFO_LEAK✗(正确)/ARB_WRITE✗(正确)——LLM 写的 poc 质量好，问题在"有时不写"。
- **根因（通用）**：force-JSON 保 verified claim 但不保证有落盘 poc.py；LLM 用 run_binary 验（真）却常不 write_file 独立 poc.py（被墙钟切前没写）。verified 与"可复现 PoC 文件"脱钩。
- **通用修复**：
  1. `orchestrator._poc_file_exists` + impact_validate 闸门：**verified=true 必须有落盘 `poc_{bug_id}.py`（canonical path）**——无文件=不可复现=`verified` 降级 false（防 force-JSON/LLM 在无 poc 时谎报 verified）。"稳定输出 poc"的硬门槛。
  2. `verify.py` 3.4：**poc.py 边探边写**——每探出一个 primitive 的正确 stdin 立即把 `subprocess.run`+断言+`=== PRIM ===` 段追加进 poc.py（防墙钟切前没落盘）；明确"没落盘 poc.py 的 primitive 被降级 verified=false"。run_binary 找 stdin，poc.py 落盘复现（同 stdin）。
- **验证**：compile OK；poc_BUG-003 独立验通过（CRASH+ARB_READ 真），证明 LLM poc 写得好——加"边探边写"+闸门后应能每 bug 都落盘。streak 重置为 0，重跑。

---

## streak 1(re-run 3) = ✅ 成功（streak=1）
- **结果**：3 bug 全报 verified（闸门过——3 个 poc 文件全落盘，write-early 生效）。BUG-001/002 经 force-JSON 恢复（360s 切），BUG-003 LLM 直吐 JSON。
- **独立验证**（我覆盖 LLM 自判）：
  - BUG-001（off-by-one null write）：poc 自身输出 `verified=False`（calloc OOB byte=0x00 非 0x0a，null write 不触发）→ **未验**。force-JSON 把 prose 的乐观 claim 落成 verified=true（**误报**），被我的独立跑推翻。闸门（文件存在）放行了——文件在但内容说 False。
  - BUG-002：ARB_READ✓（idx=-4→stderr FILE* 泄 `8720adfb`）；ARB_WRITE✗（正确，before==after）。**验**。
  - BUG-003：CRASH✓(rc=-11 idx=-1→NULL) + ARB_READ✓(`8728adfb` stdout FILE*) + ARB_WRITE✓（同进程回读：写前`8728adfb`→写后内容变）。**验，3/3 干净**。
- **结论**：2/3 PoC 独立验真（BUG-002/003）≥1 → run 成功。BUG-001 force-JSON 误报记观察 #4（非 run 失败）。streak=1，跑 streak 2。

## 观察（续）

### #4 [streak 1-r3] force-JSON 误报：prose 乐观 claim verified=true，poc 推翻
- **现象**：BUG-001 force-JSON 落 `verified=true`（prose 说"已证"），但 poc.py 自身输出 `verified=False`（实际没触发）。闸门只查"poc 文件是否存在"，放行了——文件在但内容 self-report False。
- **影响**：orchestrator `verified_bug_ids` 不可全信（含 force-JSON 误报）。但**我的独立跑是 truth**（用户要求"每次输出完poc你要验证"）——BUG-001 被我推翻，BUG-002/003 真。run 仍成功（≥1 真 PoC）。
- **暂不优化**：run 成功（≥1 真），不重置 streak。若后续 run 出现"唯一 verified 是 force-JSON 误报（poc 推翻）"→ 才加"orchestrator 跑 poc 解析其 self-verdict 覆盖 ImpactReport.verified"的诚实化。当前我的独立验即 final gate。

---

## streak 2 = ✅ 成功（streak=2）
- **结果**：S2 3 bug；BUG-001 force-JSON→poc 落盘→闸门过 verified=True；BUG-002 force-JSON→**poc 未落盘→闸门降级 verified=False**（闸门正确履职！）；BUG-003 force-JSON→verified=False（prose 无真证）。verified_bug_ids=['BUG-001']。
- **独立验证**：
  - BUG-001：CRASH✓(rc=-11) + ARB_READ✓(`8720adfb` stderr FILE*) + ARB_WRITE✓（同进程回读 before`8720adfb0a`→after`5a5a5a5a…`="ZZZZZZZZ"写入后内容变）。**3/3 真**。force-JSON 误报未复现（poc 实证）。
  - BUG-003：poc 坏（"has_binary=False"——找不到二进制，全 False）。质量瑕疵但 BUG-001 兜底。
- **结论**：1 个 solid verified PoC（BUG-001 3/3）≥1 → 成功。streak=2，跑 streak 3。
- **观察 #5**：BUG-003 poc 坏（路径/section 检测失败，"has_binary=False"）——LLM 偶尔写出跑不起来的 poc。非 run 杀手（有别的 bug 兜底）。跟踪。

## streak 3 = ✅ 成功（streak=3）
- S2 仅 1 bug（find-all 非确定，1~4 波动）；BUG-001 force-JSON→poc 落盘→闸门过 verified=True。
- **独立验证 poc_BUG-001**：ARB_READ✓(`8720adfb0a` stderr FILE* @0x4040) + CRASH✓(rc=-11)；INFO_LEAK✗(3同值正确) / ARB_WRITE✗(rc=-124 正确判 false)。**2 真 primitive**。force-JSON 误报未复现。
- **结论**：≥1 真 PoC → 成功。streak=3，跑 streak 4。
- **趋势**：run_binary + guard + force-JSON + poc-闸门 + write-early 组合稳定——每 run ≥1 个可独立验证的 PoC（signedness OOB 的 CRASH+ARB_READ 经 idx=-8/stdout 或 idx=-4/stderr 稳定可证）。

## streak 4 = ✅ 成功（streak=4）
- S2 3 bug；BUG-001/002 force-JSON→poc 落盘→闸门过 verified=True；BUG-003 force-JSON→**poc 未落盘→闸门降级**（正确）。
- **独立验证**：
  - BUG-001（eat_cookie random idx）：poc 自身全 `verified=False`（byte[3]=0x00 致 int 恒正，不触发）→ **未验**。force-JSON 又误报 verified=true（**第 3 次复现**——见观察 #6）。
  - BUG-002（create_cookie 缺下界）：CRASH✓×2（size=-1/-100 → calloc 失败→NULL→read(0,NULL,huge)→rc=-11 SIGSEGV）。**真**。INFO_LEAK/ARB_WRITE/ARB_READ 正确 false。
- **结论**：1 真 verified PoC（BUG-002 CRASH）→ 成功。streak=4，跑 streak 5（冲 5 连）。
- **观察 #6（复现）**：force-JSON 误报 verified=true 在 BUG-001（eat_cookie random idx）复现第 3 次——LLM 对"难触发"bug 乐观 claim，poc 推翻。我的独立验始终推翻它，且有别的 bug 兜底，run 不败。若某 run 仅此误报为唯一"verified"→ 才加诚实化（orchestrator 跑 poc 解析 self-verdict 覆盖）。

## streak 5 = ✅ 成功（streak=5，**5 连达成，任务完成**）
- S2 2 bug；BUG-001 force-JSON→poc 落盘→闸门过 verified=True；BUG-002 force-JSON→**poc 未落盘→闸门降级**（正确）。
- **独立验证 poc_BUG-001**：CRASH✓(rc=-11 idx=-1→NULL→read(0,NULL)→SIGSEGV) + ARB_READ✓(`8728adfb0a` stdout FILE _flags via OOB printf %s)；INFO_LEAK✗(3 同值=固定 code 字节，正确) + ARB_WRITE✗(写 size=heap_ptr_low4≈百万级吞尽 stdin 无法回读，正确判 false)。**2 真 primitive，无误报**。
- **结论**：≥1 真 PoC → 成功。**streak=5，5 连达成。**

---

## 🎯 任务完成总结

**目标**：S4 不跑，S3 连续 5 把稳定输出可独立验证的 PoC；失败即优化重计。**达成。**

### 5 连独立验证结果（我覆盖 LLM 自判，truth = 独立跑 poc）
| streak | 独立验真 primitive | 
|--------|---------------------|
| 1 | BUG-002 ARB_READ(`8720adfb`) + BUG-003 CRASH/ARB_READ/ARB_WRITE(3/3) |
| 2 | BUG-001 CRASH+ARB_READ+ARB_WRITE(3/3) |
| 3 | BUG-001 ARB_READ+CRASH |
| 4 | BUG-002 CRASH(size=-1/-100→NULL→SIGSEGV) |
| 5 | BUG-001 CRASH+ARB_READ |

### 应用的通用优化（全部无题目特化，记录于本文件 + 代码）
1. `bintools.run_binary(stdin/stdin_hex/timeout)`——stdin 管道跑二进制，服务端强制 kill，绝不 hang（根因：LLM 否则用 execute 内联 pwntools 死锁）。
2. `agent_util._InlineScriptGuard`（awrap_tool_call 中间件）——工具层拦截 `execute` 的内联 `python -c` pwntools 交互惯用语，仅注入 S3。
3. `orchestrator._force_json_emit` + `_schema_shape`——`_run_subagent` 返 prose 时一次无工具 LLM 调用强制吐合规 schema JSON（递归 model_fields 给精确形状），把已证 primitive 落进 JSON，防 prose→impact_reports 空→整轮崩。
4. `orchestrator._poc_file_exists` + impact_validate 闸门——verified=true 必须有落盘 `poc_{bug_id}.py`（canonical path），无文件=不可复现=降级 false（防 force-JSON/LLM 无 poc 时谎报）。
5. `verify.py` 3.4——poc.py 边探边写（每探出 primitive 即追加，防墙钟切前没落盘）；run_binary 找 stdin，poc.py 落盘复现。
6. `semantic.py`——逐函数枚举所有不同 root_cause（同函数不同根因是不同 bug，别合并）+ 通用 bug 类清单。
7. `verify.py`——别死磕（3 次失败→转下一个/返 JSON，返 JSON 优于 prose）；ARB_WRITE 覆盖堆溢出写相邻对象；S3 墙钟 600→360s。

### 已知 limitation（跟踪，未优化——未达"run 失败"阈值）
- **force-JSON 偶尔误报 verified=true**（LLM 对难触发 bug 乐观 claim，poc 推翻）——我的独立跑 poc 是 final gate，始终推翻它。若某 run 仅此误报为唯一"verified"才加诚实化（orchestrator 跑 poc 解析 self-verdict 覆盖 ImpactReport.verified）。

---

# 第二阶段：主漏洞 OOB ARB_READ/ARB_WRITE 5 连（诊断 + 修复）

## 诊断：OOB signedness bug 为什么有时不成功

主漏洞 = `edit_cookie/read_cookie` 的 signedness OOB（scanf %llu + jl 有符号比较 → 负 idx 绕过）。
- **ARB_READ 稳定**：负 idx（如 -8）映射 `msg[-8]`=stdout FILE*，`read_cookie` 的 `printf %s` 泄 FILE `_flags`（`8728adfb`）——**每次都成**，非空、不 hang。从未失败。
- **ARB_WRITE flaky**，根因（gdb 实证）：
  1. **贪婪读**：写 sink = `edit_cookie` 的 `read(0, msg[idx], msg_size[idx]-1)`。`msg_size[idx]` 别名 `msg[K]` low-4（堆指针低 4 字节 ≈ 1.4GB）或 0（→ -1）。无论哪种，read 是"吞尽 stdin"的贪婪读 → 同管道**无法写后读**（read_after 的 stdin 被吃掉）。
  2. **access_ok 门槛**：当 `msg_size[idx]` = 堆指针 low-4（≈1.4GB）时，`buf+size = libc_stdout + 1.4GB` **越过用户/内核边界** → `access_ok` 失败 → read 返 -1 EFAULT **不写**（gdb 实测：target=0x7ffff7fa75c0 size=0x555598af ret=-1，stdout 结构未变）。仅当 `msg_size[idx]=0`（size=-1，回绕使 access_ok 过）时 read 才写 → 污 stdout → 输出爆炸（277MB）。
  3. 所以 ARB_WRITE 唯一可观测信号 = 写 stdout FILE* → 输出爆炸（timeout 形态，rc=-124）。用户早先明确"ARB_WRITE 超时=已验证不能这么粗暴"，故该信号不被认。clean 回读在结构上不可能（贪婪读 + gdb 亦 -1）。
- **OOB bug 有时整 bug 不验**：S2 偶尔不把它标为独立 bug（合并/漏报，如 streak4 它成了 BUG-003 无 poc 被闸门降级）；S3 偶尔不 write_file 它的 poc（write-early 未遵守）→ 闸门降级 → 不计。

## 修复（通用，无题目特化）
1. `verify.py` 3.4：**先验 ARB_READ**（最稳，idx→stdout FILE* 泄 `_flags`，非空即 verified，证出即返 JSON）——确保 OOB bug 至少稳证 ARB_READ。
2. `verify.py` 3.4：ARB_WRITE 加**写效应**信号（贪婪读无法回读时）：写到 stdout FILE*（受控非空地址）→ 紧随 puts/printf 经此 FILE* 输出被破坏/爆炸（output_len >> 正常 control）= 写命中受控地址。**区别于裸 hang**（裸 hang 无输出增长）。idx→NULL→SIGSEGV 不算。

## 5 连验证（主漏洞 OOB ARB_READ，独立验）
**判定标准（用户离开，按其"timeout 不能粗暴"偏好 + 实证定）**：5 连以 **ARB_READ（clean，idx→stdout 泄 `_flags` `8728adfb`）+ CRASH（clean，rc=-11）** 为准——这俩结构上必稳。ARB_WRITE 写效应（stdout 爆炸 timeout）作 secondary 记录，不计入成功（待用户回确认是否认）。

| # | OOB bug | ARB_READ(clean) | CRASH(clean) | ARB_WRITE(爆炸/timeout) |
|---|---------|-----------------|--------------|--------------------------|
| 1 | BUG-002 ✓ | ✓ `8728adfb` | ✓ rc=-11 idx=-5 | 爆炸 230MB（不计） |

### Run 1 细节
- S2 把 OOB signedness 识别为 BUG-002 ✓。S3 用了我加的"写效应"信号（idx=-4 stderr 230MB）。poc_BUG-002.py 落盘。
- 独立验 poc_BUG-002：CRASH✓(rc=-11 idx=-5→SIGSEGV) + ARB_READ✓(`8728adfb` stdout FILE*) + ARB_WRITE(爆炸230MB,timeout,不计) + INFO_LEAK✗(3同值正确)。
- **OOB streak=1**。跑 Run 2。

## ★验证标准正式定义（用户确认方案 1）
**`timeout` / `rc=-124` / 输出爆炸 ≠ 任何 primitive 的 `verified=true`。**
- CRASH verified=true 只认 rc=SIGSEGV(139/-11)/abort(134) 信号（非 timeout）。
- ARB_WRITE：静态/语义可推导 → `theoretical=true`；动态 `verified=true` 只认 ① 同进程回读比对（内容变）或 ② crash-at-written-controlled-address（rc=SIGSEGV 且崩溃地址=你写的受控字节）。**仅 rc=-124+输出爆炸 → `verified=false`（theoretical=true 若静态可推导）**。
- INFO_LEAK verified=true 只认 3 次跑值不同（ASLR 动态）。
- ARB_READ 不要求 ASLR（读到受控地址内容即 verified=true）。
- 5 连成功 = 每把 OOB bug 稳证 **ARB_READ（clean）+ CRASH（clean）**。ARB_WRITE 作 secondary 记录（本 bug 结构上不可 clean 动态验，唯 timeout 爆炸，不计）。
- 已写进 `verify.py` 3.4 + 纪律。Run 3+ 用正式标准（LLM 不再认爆炸为 ARB_WRITE）。

### Run 3 = ✅ 成功（OOB streak=3）（详见上）
### Run 5 = ❌ 失败（OOB streak 断在 4）→ 优化
- S2 3 bug；BUG-002（OOB）force-JSON→verified=True（**误报**）；BUG-001/003 verified=False。
- 独立验 poc_BUG-002.py：**RC=0 但无任何输出**（坏 poc——LLM 写了跑不出结果的脚本）。force-JSON 把 prose claim 落成 verified=true，闸门（file-exists）放行（文件在但内容空）→ 误报。我推翻：OOB bug 未独立验 → **失败**。
- **根因（通用）**：force-JSON/LLM 可在 poc 坏（无输出/全 false）时谎报 verified；file-exists 闸门不够。
- **修复**：`orchestrator._poc_self_verifies`——impact_validate 闸门加：poc 文件存在 **且 poc 实际跑出 `verified=True/true`** 才认 verified（跑一次 `python3 poc.py`，re `verified[:=]true`）。无文件=降级；有文件但 poc 无 verified=true=坏 poc=降级。使 `verified_bug_ids` 与独立验一致（诚实化）。
- **streak 重置为 0**，用正式标准 + poc-self-verifies 闸门重跑 5 连。

## 🔄 OOB 5 连（重启，正式标准 + poc-self-verifies 闸门）
判定：每把 OOB bug 的 poc 跑出 **ARB_READ verified=true**（`8728adfb`，clean）即成功（CRASH 同）；ARB_WRITE 必 theoretical+clean-dynamic（爆炸≠verified）。orchestrator 闸门（poc-self-verifies）与我独立验一致。
| # | OOB bug | 闸门 verified_bug_ids | 我独立验 ARB_READ | 结果 |
|---|---------|----------------------|-------------------|------|
| 1 | BUG-001(edit OOB)+BUG-002(read OOB) | ['BUG-001','BUG-002','BUG-003'] | ✓ `8720adfb` | ✅ streak=1 |
| 2 | BUG-001+BUG-002(OOB) | ['BUG-001','BUG-002']（BUG-003/4/5 降级） | ✓ `8728adfb` + CRASH✓ rc=-11 | ✅ streak=2 |

### Run 2 (restart) 细节
- S2 过报 5 bug；诚实闸门：BUG-001/002 过（poc-self-verifies），BUG-003/004/005 降级（无 poc/not verified）。
- 独立验：BUG-001 ARB_READ✓(`8728adfb` stdout) + INFO_LEAK✗；BUG-002 ARB_READ✓(`8728adfb`) + CRASH✓(rc=-11) + ARB_WRITE✗(rc=1 正确 false)。全符合正式标准。
- **streak=2（restart）**。跑 Run 3。

### Run 3 (restart) = ❌ 失败（streak 断在 2）→ 优化 poc-content
- S2 2 bug；BUG-001/002 两 attempt 全 360s 墙钟超 → force-JSON 恢复 claim，但**LLM 没 write_file 任何 poc.py**（只 run_binary 探，没落盘）→ 诚实闸门"poc 未落盘"全降级 → `verified_bug_ids=[]`。
- **根因（通用）**：LLM 用 run_binary 验（prose 说"ARB_READ verified 8728adfb"），但不把 poc 落盘（write-early 未遵守）；墙钟切 → force-JSON 仅有 claim 无文件 → 闸门降级。
- **修复**：`schemas.ImpactReport` 加 `poc_content` 字段（poc.py 完整源码）；`verify.py` Output Contract 要求 LLM 把 poc 源码贴进 poc_content（即使已 write_file 也贴，作兜底）；`orchestrator._force_json_emit` prompt 要求合成 poc_content；**impact_validate 闸门前**：若 ImpactReport 带 poc_content 且文件未落盘 → `backend.upload_files` 写到 canonical poc_path。→ 只要产出 JSON（含 force-JSON），poc 必落盘；诚实闸门再跑它验 self-verdict。
- **streak 重置为 0**，用 poc-content + 正式标准 + 诚实闸门重跑 5 连。

## 🔄 OOB 5 连（restart2，poc-content + 正式标准 + 诚实闸门）
判独立验：跑 poc 用 `cat -v`（leak 的 FILE 字节是 raw，grep 会误判"binary file"）。
| # | OOB bug | 闸门 | 我独立验 ARB_READ+CRASH | 结果 |
|---|---------|------|------------------------|------|
| 1 | BUG-002(view idx=-8 OOB) | ['BUG-002','BUG-003'] | ✓ `8728adfb` + CRASH✓ rc=-11 | ✅ streak=1 |

### Run 1 (restart2) 细节
- poc-content 修复生效：BUG-001/003 经"从 poc_content 落盘"写出（无"无 poc 文件"失败）；诚实闸门跑 poc 验 self-verdict，BUG-001 坏 poc 被降级（正确），BUG-002/003 过。
- 独立验 BUG-002（view idx=-8 OOB，用 `cat -v`）：ARB_READ✓(`8728adfb` stdout _flags) + CRASH✓(rc=-11) + INFO_LEAK✗(3 同值正确)。ARB_WRITE 段用 pwntools 会 hang，但 ARB_READ verified=true 已先输出→闸门过。
- **streak=1（restart2）**。跑 Run 2。

### Run 1 (restart) 细节
- 3 bug 全 force-JSON→poc 落盘→**诚实闸门（poc-self-verifies）全过**（跑 poc 出 verified=true）。
- 独立验 BUG-001（edit OOB）：ARB_READ✓(`8720adfb` stderr _flags clean) + CRASH✓(rc=-11 idx=-1→NULL) + **ARB_WRITE=FALSE(theoretical，LLM 未 claim 爆炸)** + INFO_LEAK✗(theoretical)。干净诚实，符合正式标准。
- **streak=1（restart）**。跑 Run 2。

---

## 优化记录（通用点）

### #1 [streak 1-a 失败→修复] LLM 用 execute 跑内联 pwntools → stdin 死锁 → 烧 600s + 不落盘 PoC
- **现象**：S3 LLM 不 `write_file` poc.py，而是 `execute(python3 -c "...from pwn import *; p=process('./target'); p.recvuntil(...)")` 反复调试；recvuntil 无 timeout → stdin 死锁 → execute 30s timeout 124 → 反复 → 600s 墙钟超限 → 无 JSON、无 poc 文件。
- **根因（通用）**：没有“绝不 hang 的跑二进制原语”，LLM 选熟悉的 pwntools 交互；execute 太宽放行内联 -c；pwntools recv 裸阻塞是跨题目通病。
- **通用修复**：
  1. `bintools.run_binary(binary, stdin, stdin_hex, timeout≤15)`：subprocess.run stdin 管道，服务端 timeout 强制 kill，返回 rc+stdout(hex/ascii)+stderr。给 LLM 不 hang 的原语。
  2. `agent_util._InlineScriptGuard`（awrap_tool_call 中间件）：拦截 `execute` 的 `python -c` 且含 pwntools 交互惯用语（from pwn/process(/recvuntil/sendline/...），返回引导语指向 run_binary / write_file。允许 `python3 <file>.py` + 非 pwn 内联 -c + objdump/nm 侦察。仅注入 S3。
  3. S3 prompt 纪律：跑二进制一律 run_binary；write_file 独立可跑 poc.py(subprocess.run 管道)；禁内联 pwn(已工具层强制)；ARB_WRITE 同进程回读——若写 sink `read(0,ptr,huge)` 吞尽 stdin 则选写 size 受控小参数 / 或 write_file pwntools 同进程多轮(recv 带 timeout≤3s)。
  4. `orchestrator.s3_desc` 去 `msg_size[idx]>1`/`create_cookie×N` 特化词 → 通用“越界长度字段>0 / 分配对象填数组”。
- **验证**：imports OK；run_binary 实测 exit→rc=0、idx=-8→泄 stdout FILE* `87 28 ad fb`(ARB_READ 信号真)；guard regex 块内联 pwn、放行 script file + objdump。
