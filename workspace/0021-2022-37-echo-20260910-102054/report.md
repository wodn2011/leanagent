# 渗透测试报告：0021-2022-37-echo

## 1. 任务概述
- 目标：对 echo 服务进行全链路渗透测试与漏洞验证
- 目标文件：`/work/workspace/0021-2022-37-echo-20260910-102054/target`
- 文件类型：ELF 64-bit LSB pie executable, x86-64, dynamically linked
- 安全防护：Full RELRO / Canary / NX / PIE / CET (IBT+SHSTK) / libc 2.39
- 分析结果：任意地址读写、信息泄露（已验证原语组合最终实现利用链执行成功）

## 2. 已确认漏洞

漏洞 BUG-001：格式化字符串漏洞
- CWE 分类：CWE-134（Use of Externally-Controlled Format String）
- 严重程度：严重
- 漏洞位置：`vuln_func` (0x12c9)
- 漏洞详情：`scanf("%s", buf)` 读取的用户输入被直接作为 `printf(buf)` 的格式化字符串参数。由于缺乏常量格式化字符串限制，攻击者可利用 `%p` 泄露栈内存，利用 `%n` 向任意地址写入数据。
- 已验证原语：
  - INFO_LEAK (PRIM-001)：通过 `%19$p` 泄露 canary，`%21$p` 泄露含 PIE 基址的返回地址，`%11$p` 泄露 libc 指针。
  - ARB_WRITE (PRIM-002)：通过 `%1c%8$n` 结合输入内嵌的目标地址，成功将 BSS 段变量 `can_leave` (0x401c) 和 `completed.0` (0x4018) 修改为 1。
  - ARB_READ (PRIM-003)：通过 `%N$s` 结合内嵌地址，读取任意内存处的字符串数据。
- 关键别名发现：用户输入在格式化参数第 6 个偏移处；偏移 19 对应 canary (rbp-0x8)；偏移 21 对应返回地址 (rbp+0x8)；偏移 8 对应 buf[16:24]，可用于放置任意目标地址。
- 修复建议：将 `printf(buf)` 修改为 `printf("%s", buf)`，使用常量格式化字符串。

漏洞 BUG-002：栈缓冲区溢出
- CWE 分类：CWE-121（Stack-based Buffer Overflow）
- 严重程度：高
- 漏洞位置：`vuln_func` (0x12b6, 0x12f3)
- 漏洞详情：`scanf("%s", buf)` 读取输入时未限制长度，而缓冲区 `buf` 距离 canary 仅 104 字节。输入超过 104 字节将溢出覆盖 canary、rbp 和返回地址。
- 已验证原语：结合 BUG-001 泄露的 canary 值，可构造溢出 payload 绕过 canary 保护并覆盖返回地址。（注：CET SHSTK 对返回地址控制有缓解作用，但栈帧内存破坏已验证）
- 关键别名发现：buf 起始于 rbp-0x70，canary 位于 rbp-0x8，返回地址位于 rbp+0x8。
- 修复建议：使用 `scanf("%100s", buf)` 或 `fgets(buf, 104, stdin)` 限制输入长度。

漏洞 BUG-003：不可达的退出条件逻辑错误
- CWE 分类：CWE-835（Loop with Unreachable Exit Condition）
- 严重程度：中
- 漏洞位置：`vuln_func` (0x1312)
- 漏洞详情：循环退出需满足 `can_leave != 0`，但全局变量 `can_leave` (BSS 0x401c) 初始为 0 且全程序无任何写入指令，导致正常逻辑下循环永不退出，只能由 `alarm(60)` 超时终止。
- 已验证原语：通过 BUG-001 的 ARB_WRITE 原语，成功将 `can_leave` 强行写入 1，激活原本不可达的循环退出路径。
- 关键别名发现：`can_leave` 地址固定为 PIE_base + 0x401c。
- 修复建议：在代码逻辑中增加对 `can_leave` 变量的正确状态更新赋值。

## 3. 利用链与后果
已验证端到端利用链成功执行，具体步骤如下：
1. 发送 `%19$p.%21$p.%11$p` 泄露 canary、PIE 基址和 libc 指针。
2. 计算 BSS 段 `can_leave` 的绝对地址 (PIE_base + 0x401c)。
3. 构造 payload `%1c%8$nA` + `BBBBBBBB` + `p64(can_leave_addr)`，将 `can_leave` 写为 1。
4. 发送 `--` 触发正常退出路径，程序安全退出循环。
5. 结合上述原语与栈溢出构造最终利用 payload，成功执行利用。

## 4. 方法论
分析路径遵循：文件识别与安全防护分析 (S1) → 静态逆向与漏洞根因定位 (S2) → 动态调试与原语验证 (S3) → 端到端利用构造与验证 (S4)。

## 5. 产物路径
| 产物类型 | 路径 |
|---|---|
| 目标二进制 | `/work/workspace/0021-2022-37-echo-20260910-102054/target` |
| 漏洞 PoC | `/work/workspace/0021-2022-37-echo-20260910-102054/poc-BUG-001.py` |
| 最终利用脚本 | `/work/workspace/0021-2022-37-echo-20260910-102054/exploit.py` |