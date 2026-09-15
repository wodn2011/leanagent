# 渗透测试报告：ChatGGT 1.0

## 1. 任务概述
- 目标：对 ChatGGT 1.0 聊天程序进行渗透测试，挖掘内存破坏漏洞并验证可利用原语。
- 目标文件：`/work/workspace/0032-2024-64-chatggt-20260909-223056/target`
- 文件类型：ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
- 安全防护：Partial RELRO / NX enabled / No Canary / No PIE (base 0x400000) / libc 2.39 (ASLR enabled) / CET (IBT/SHSTK marked but not enforced at runtime)
- 分析结果：已验证任意代码执行（通过 RIP 控制劫持至 `get_shell` 函数）

## 2. 已确认漏洞
漏洞 BUG-001：start_chat 函数栈缓冲区溢出
- CWE 分类：CWE-121 (Stack-based Buffer Overflow)
- 严重程度：严重
- 漏洞位置：`start_chat` (`0x40127f`，溢出点 `read@plt` 调用位于 `0x4012b6`)
- 漏洞详情：`start_chat` 函数通过 `sub rsp,0x100` 分配了 256 字节的栈缓冲区，但随后的 `read(0, rbp-0x100, 0x12c)` 调用从 stdin 读取了高达 300 字节的数据。由于缺乏边界检查且没有栈保护，多出的 44 字节将溢出并覆盖保存的 RBP（偏移 256）和返回地址（偏移 264）。
- 已验证原语：
  1. **RIP_CONTROL**：通过在偏移 264 处覆盖返回地址，在 `0x401300` (ret) 处验证。GDB 证明攻击者输入的地址（如 `0x4011f6`）被直接加载入 RIP，CET 未拦截。
  2. **STACK_CONTROL**：通过在偏移 256 处覆盖保存的 RBP，在 `0x4012ff` (leave) 处验证。RBP 被成功劫持为攻击者控制的值（如 `0x4343434343434343`）。
  3. **ARBITRARY_CODE_EXECUTION**：通过将返回地址覆盖为 `get_shell` (`0x4011f6`)，成功执行 `system("/bin/sh")`。
- 关键别名发现：`buffer[256:264]` 直接映射保存的 RBP 寄存器槽位，`buffer[264:272]` 直接映射返回地址槽位。溢出为线性连续写入，无指针别名干扰。
- 修复建议：将 `read()` 的读取长度限制为缓冲区实际大小（256 字节），并在编译时开启 Stack Canary (`-fstack-protector-strong`) 及 PIE 保护。

## 3. 利用链与后果
已成功完成端到端利用，实现任意代码执行。利用步骤如下：
1. **触发溢出**：向 stdin 发送 300 字节 payload，前 4 字节为 `'EXIT'` 以跳出循环触发 `leave; ret`。
2. **栈帧控制**：填充 252 字节垃圾数据，在偏移 256 写入 8 字节伪造 RBP。
3. **RIP 劫持**：在偏移 264 写入 `get_shell` 函数地址 (`0x4011f6`)。
4. **执行后果**：`ret` 指令将 `0x4011f6` 弹入 RIP，执行 `system("/bin/sh")`，获取交互式 Shell。

## 4. 方法论
- **文件识别**：确认目标为非剥离的 64 位 ELF 动态链接可执行文件。
- **防护分析**：通过 checksec 与运行时探测，确认无 Canary、无 PIE，且 CET SHSTK 虽在 ELF 标记但运行时未强制执行。
- **逆向分析**：定位 `start_chat` 函数中 `read()` 读取长度（300）大于栈缓冲区分配大小（256）的缺陷。
- **原语验证**：使用 GDB 在 `0x401300` (ret) 下断，单步执行确认 RIP 和 RBP 被完全控制。
- **利用构造**：编写并运行 exploit.py，将控制流导向 `get_shell`，成功获取 shell。

## 5. 产物路径
| 产物类型 | 路径 |
| :--- | :--- |
| 最终利用脚本 | `/work/workspace/0032-2024-64-chatggt-20260909-223056/exploit.py` |
| PoC 验证脚本 | `/work/workspace/0032-2024-64-chatggt-20260909-223056/poc-BUG-001.py` |