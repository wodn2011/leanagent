# 渗透测试报告：shellcode_runner3

## 1. 任务概述
- 目标：对 shellcode 执行器进行渗透测试，验证安全防护机制并尝试实现任意代码执行。
- 目标文件：`/work/workspace/0026-2024-49-shellcode-runner-3-20260909-144045/target`
- 文件类型：ELF 64-bit LSB pie executable x86-64, dynamically linked
- 安全防护：Full RELRO / Canary / NX / PIE / CET (IBT, SHSTK) / GLIBC 2.39
- 分析结果：任意代码执行（在固定地址 RWX 页面上执行用户提供的 shellcode）

## 2. 已确认漏洞

漏洞 BUG-001：MPROTECT 权限设置逻辑错误
- CWE 分类：CWE-840（业务逻辑错误）
- 严重程度：严重
- 漏洞位置：main (0x141c - 0x149a)
- 漏洞详情：程序在调用 `mprotect` 修改 shellcode 缓冲区权限时，传入了硬编码值 `4`。在 Linux x86-64 中 `4` 代表 `PROT_EXEC`，这使页面变为仅可执行（--xp），而非预期的移除执行权限。随后的 `jmp rdi` 成功跳转到固定地址 `0x13370000` 并执行了用户提供的 shellcode。
- 已验证原语：任意代码执行（GDB 动态验证：10个 NOP 指令执行后 RIP 从 `0x13370000` 前进至 `0x1337000a`；无限循环 shellcode 导致程序超时挂起，证明代码被持续执行）。
- 关键别名发现：`/proc/self/maps` 显示 `13370000-13371000 --xp`，证明页面具有执行权限；崩溃信号 `si_code=1` (SEGV_MAPERR) 发生在地址 `0x0`，而非 NX 违规的 `si_code=2` (SEGV_ACCERR)。
- 修复建议：若旨在阻止 shellcode 执行，应将 `mprotect` 的权限参数修改为 `PROT_READ` (1)；若旨在仅移除写权限，应修改为 `PROT_READ|PROT_EXEC` (5) 并结合其他防护。

漏洞 BUG-002：MPROTECT 返回值未检查
- CWE 分类：CWE-252（未检查的返回值）
- 严重程度：高
- 漏洞位置：main (0x1429)
- 漏洞详情：程序在调用 `mprotect` 后未检查返回值，直接清空寄存器并跳转执行 shellcode。如果 `mprotect` 调用失败，缓冲区将保留初始的 RWX 权限，导致用户 shellcode 在无任何内存保护的情况下被执行。
- 已验证原语：任意代码执行（结合 BUG-001，当前 `mprotect` 成功执行并返回 0，页面变为可执行，shellcode 已被验证可执行）。
- 关键别名发现：与 `mmap` (0x138b) 和 `read` (0x13e4) 调用后均检查返回值的模式不一致，`mprotect` 缺失安全检查。
- 修复建议：在 `mprotect` 调用后添加返回值检查，若返回 -1 则立即终止执行，防止在权限降级失败时执行不可信代码。

漏洞 BUG-003：黑名单过滤不完整
- CWE 分类：CWE-184（不完整的黑名单）
- 严重程度：中
- 漏洞位置：blacklist (0x1312)
- 漏洞详情：黑名单函数仅过滤了字节 `0x0f`（`syscall` 指令的首字节），未过滤 `int 0x80` (CD 80) 等替代的系统调用机制。由于 BUG-001 已使 shellcode 可执行，攻击者可利用 `int 0x80` 绕过该过滤机制执行系统调用。
- 已验证原语：安全过滤绕过（静态验证：仅存在 `cmp al, 0xf`，未校验 `0xCD` 或 `0x80` 字节）。
- 关键别名发现：`int 0x80` 指令 (CD 80) 完全不受当前黑名单限制。
- 修复建议：采用白名单机制过滤允许的指令，或同时过滤 `0xCD` 和 `0x80` 字节，以阻断 32 位系统调用路径。

## 3. 利用链与后果
已实现端到端任意代码执行，利用链如下：
1. 程序通过 `mmap` 在固定地址 `0x13370000` 分配 RWX 内存并读入用户输入。
2. `blacklist` 检查通过（避免使用 `0x0f` 字节）。
3. `mprotect(buf, 0x64, 4)` 执行，因 `4=PROT_EXEC`，页面变为仅可执行（--xp），仍允许 CPU 指令获取。
4. 寄存器被清零，`rdi` 设为 `0x13370000`，执行 `jmp rdi` 跳转到 shellcode。
5. 用户的 shellcode 在固定地址被执行，实现任意代码执行。

## 4. 方法论
- 文件识别与防护分析：确认目标为 64-bit ELF，启用了 Full RELRO、NX、PIE 及 CET 防护。
- 逆向分析：定位 `main` 函数中的 `mmap`、`blacklist`、`mprotect` 及 `jmp rdi` 流程，发现权限参数异常。
- 原语验证：通过 GDB 动态调试，利用 NOP 指令和无限循环 shellcode 证明页面可执行，并分析崩溃信号 `si_code` 排除了 NX 违规。
- 利用构造：编写并运行最终 exploit 脚本，成功验证任意代码执行。

## 5. 产物路径
| 产物类型 | 路径 |
| :--- | :--- |
| 最终 Exploit | `/work/workspace/0026-2024-49-shellcode-runner-3-20260909-144045/exploit.py` |
| BUG-001 PoC | `/work/workspace/0026-2024-49-shellcode-runner-3-20260909-144045/poc-BUG-001.py` |