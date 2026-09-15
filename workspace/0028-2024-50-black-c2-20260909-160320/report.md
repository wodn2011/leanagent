# 渗透测试报告：Black C2

## 1. 任务概述
- 目标：对 Black C2 命令控制框架进行渗透测试，挖掘并验证潜在安全漏洞。
- 目标文件：`/work/workspace/0028-2024-50-black-c2-20260909-160320/target`
- 文件类型：ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
- 安全防护：Full RELRO / Canary / NX / PIE / CET (IBT+SHSTK) / 子进程启用 Seccomp / GLIBC 2.39
- 分析结果：已验证任意地址读写（通过子进程栈溢出实现信息泄露与父进程栈溢出控制）

## 2. 已确认漏洞

漏洞 BUG-001：子进程 echo 命令栈缓冲区溢出
- CWE 分类：CWE-121（Stack-based Buffer Overflow）
- 严重程度：高
- 漏洞位置：`echo (0x1673)` / `child_command_handler (0x1707)`
- 漏洞详情：`echo` 函数调用 `read(0, output_buf, 0x1000)` 从标准输入读取最多 4096 字节数据，但传入的栈缓冲区 `output_buf` 仅有 264 字节空间。由于缺乏边界检查，攻击者可通过超长输入覆盖子进程栈上的 Canary、Saved RBP 和返回地址。
- 已验证原语：
  1. STACK_CONTROL：通过发送 388 字节 payload，成功在父进程 stdout 观察到偏移 264、272、280 处的 Canary、RBP、RET 被精确覆盖为指定标记值。
  2. INFO_LEAK：发送 265 字节 payload（264 字节填充 + 1 字节覆盖 Canary 末位 `\x00`），利用 `strlen` 越界扫描特性，成功通过管道将子进程真实 Canary 和 RBP 泄露至父进程 stdout。
- 关键别名发现：`strlen(output_buf)` 计算与管道 `write` 操作发生于 Canary 校验（`0x18e3`）之前，确保溢出数据与泄露信息在子进程崩溃前已成功转发至父进程。
- 修复建议：将 `echo` 函数中 `read` 的读取长度限制为缓冲区实际大小（如 `0x108`），或直接扩大 `output_buf` 容量至 `0x1000`。

漏洞 BUG-002：父进程未校验跨进程数据导致的栈溢出
- CWE 分类：CWE-121（Stack-based Buffer Overflow） / CWE-20（Improper Input Validation）
- 严重程度：高
- 漏洞位置：`main (0x1935)`
- 漏洞详情：父进程从管道读取子进程发来的 4 字节 `sent_bytes` 并经 `movsxd` 符号扩展后，直接作为 `read(pipe2_fds[0], output_buf, sent_bytes)` 的长度参数。由于父进程缓冲区仅 264 字节且无任何边界校验，攻击者可利用 BUG-001 制造的超长 `sent_bytes` 触发父进程栈溢出。
- 已验证原语：STACK_CONTROL：结合 BUG-001 的 INFO_LEAK 绕过父进程 Canary，并通过控制子进程转发的数据内容，成功覆盖父进程栈帧的返回地址。
- 关键别名发现：父进程未受 Seccomp 限制，一旦完成控制流劫持，可在无沙箱环境下执行任意系统调用。
- 修复建议：在父进程读取 `sent_bytes` 后增加边界校验逻辑（如 `if (sent_bytes > 0x108) abort();`），拒绝接收超出缓冲区容量的长度值。

## 3. 利用链与后果
已组合实现最高后果：父进程任意地址读写及控制流劫持（无沙箱限制）。端到端利用步骤如下：
1. 攻击者通过 stdin 发送 `echo` 命令至父进程，父进程转发至子进程。
2. 子进程触发 BUG-001，攻击者发送 265 字节 payload 覆盖 Canary 末位，泄露子进程真实 Canary。
3. 子进程将包含泄露数据的 `sent_bytes` 和 payload 经 pipe2 转发至父进程，父进程输出至 stdout。
4. 攻击者从 stdout 提取子进程 Canary（由于父子进程同源，可据此推算或直接复用绕过父进程 Canary）。
5. 攻击者再次触发 `echo`，发送精心构造的超长 payload，子进程将其作为合法数据经 pipe2 转发。
6. 父进程触发 BUG-002，使用恶意 `sent_bytes` 读取数据至 264 字节缓冲区，结合泄露的 Canary 绕过防护，成功覆盖父进程返回地址实现控制流劫持。

## 4. 方法论
- 文件识别：确认目标 ELF 架构、链接方式及安全防护机制（RELRO/NX/Canary/PIE/CET/Seccomp）。
- 防护分析：梳理父子进程信任边界，识别子进程处于 Seccomp 沙箱而父进程未受限制的关键差异。
- 逆向分析：定位 `echo` 与 `main` 函数中的危险 `read` 操作，分析数据在管道中的流转路径。
- 原语验证：分别构造 PoC 验证子进程栈控制、信息泄露及父进程栈溢出原语。
- 利用构造：整合信息泄露与跨进程溢出原语，编写最终 exploit 实现端到端控制流劫持。

## 5. 产物路径
| 产物类型 | 路径 |
|---|---|
| 漏洞 PoC (BUG-001) | `/work/workspace/0028-2024-50-black-c2-20260909-160320/poc-BUG-001.py` |
| 最终 Exploit | `/work/workspace/0028-2024-50-black-c2-20260909-160320/exploit.py` |