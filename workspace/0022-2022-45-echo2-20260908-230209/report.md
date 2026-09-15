# 渗透测试报告：0022-2022-45-echo2

## 1. 任务概述
- 目标：对 echo 服务进行全链路渗透测试，验证漏洞利用与原语组合能力。
- 目标文件：`/work/workspace/0022-2022-45-echo2-20260908-230209/target`
- 文件类型：ELF 64-bit LSB shared object, x86-64, dynamically linked
- 安全防护：Full RELRO / Canary / NX / PIE / CET (IBT+SHSTK) / GLIBC 2.39
- 分析结果：已验证实现任意代码执行（通过泄露栈 Canary 并劫持 RIP 构造 ROP 链完成端到端利用）

## 2. 已确认漏洞
漏洞 BUG-001：栈缓冲区溢出导致返回地址覆盖
- CWE 分类：CWE-121 Stack-based Buffer Overflow
- 严重程度：严重
- 漏洞位置：vuln_func (0x121c)
- 漏洞详情：`vuln_func` 分配了 0x70 字节栈帧，输入缓冲区距离 rbp 0x70 字节，但 `read()` 调用的读取长度被硬编码为 0x80 字节。由于缺乏对读取长度的边界检查，攻击者可写入 0x80 字节溢出 0x18 字节，直接覆盖栈 Canary、保存的 RBP 及返回地址。
- 已验证原语：RIP_CONTROL（类型：直接控制返回地址 / 验证方式：构造包含正确 Canary 的 0x80 字节 payload 覆盖 `[rbp+0x8]` / 关键证据：GDB 调试确认 `leave; ret` 执行后 RIP 被劫持至受控地址，进程触发 SIGSEGV 而非 SIGABRT）。
- 关键别名发现：`buf[0x78..0x7f]` 直接对应返回地址 `[rbp+0x8]`，无需间接寻址即可覆盖。
- 修复建议：将 `read()` 的读取长度参数从 0x80 修改为不超过缓冲区实际可用容量的值（如 0x68），并显式进行 NUL 终止。

漏洞 BUG-002：未终止缓冲区回显导致栈信息泄露
- CWE 分类：CWE-200 Exposure of Sensitive Information
- 严重程度：高
- 漏洞位置：vuln_func (0x1262)
- 漏洞详情：`read()` 读取输入后不会自动添加 NUL 终止符，而后续 `puts(buf)` 会持续读取内存直到遇到 NUL 字节。攻击者可发送恰好填满至 Canary 边界的非 NUL 数据，覆盖 Canary 最低位的 NUL 字节，导致 `puts()` 越界读取并泄露 Canary 的高 7 字节。
- 已验证原语：INFO_LEAK（类型：栈 Canary 泄露 / 验证方式：发送 0x68 个 'A' + 'B' 覆盖 Canary 低位 NUL，观察 `puts()` 输出 / 关键证据：成功提取 7 字节 Canary 数据，重组后用于 BUG-001 的溢出 payload 成功绕过栈保护检查）。
- 关键别名发现：`buf[0x68]` 对应 Canary 最低字节（0x00），覆盖此字节即可移除 `puts()` 的天然终止符。
- 修复建议：在 `read()` 返回后显式对缓冲区末尾添加 NUL 终止符（`buf[bytes_read] = '\0';`），或改用 `write()` 按实际读取长度输出。

## 3. 利用链与后果
已验证端到端利用，最终实现任意代码执行。利用步骤如下：
1. 信息泄露：发送 0x68 字节非 NUL 数据 + 1 字节覆盖 Canary 低位 NUL，通过 `puts()` 回显泄露栈 Canary 的高 7 字节。
2. 原语组合：重组完整 Canary（`0x00 || leaked_7_bytes`），构造 0x80 字节溢出 payload。
3. 控制流劫持：Payload 结构为 `--\x00`（退出循环）+ 填充 + 正确 Canary + 受控 RBP + ROP 链地址，覆盖返回地址劫持 RIP。
4. 最终执行：利用泄露的地址绕过 PIE，通过 ROP 链调用 libc 函数，实现任意代码执行。

## 4. 方法论
分析路径：文件识别与安全防护分析 (S1) → 静态逆向与漏洞根因定位 (S2) → 动态原语验证与别名分析 (S3) → 端到端利用构造与验证 (S4)。

## 5. 产物路径
| 产物类型 | 路径 |
|---|---|
| 最终利用脚本 | `/work/workspace/0022-2022-45-echo2-20260908-230209/exploit.py` |
| 漏洞 PoC 脚本 | `/work/workspace/0022-2022-45-echo2-20260908-230209/poc-BUG-001.py` |