# 渗透测试报告：0025-2023-52-rop-revenge

## 1. 任务概述
- 目标：对目标二进制文件进行漏洞挖掘、原语验证与全链路利用分析
- 目标文件：`/work/workspace/0025-2023-52-rop-revenge-20260909-140653/target`
- 文件类型：ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
- 安全防护：Partial RELRO / NX enabled / No Canary / No PIE / CET (IBT enabled, SHSTK 未实际运行时生效) / GLIBC 2.39
- 分析结果：已验证任意代码执行（通过栈溢出控制 RIP 并构造 ROP 链）

## 2. 已确认漏洞
漏洞 BUG-001：`vuln()` 函数 `gets()` 无边界检查栈缓冲区溢出
- CWE 分类：CWE-121 (Stack-based Buffer Overflow) / CWE-242 (Use of Inherently Dangerous Function)
- 严重程度：严重
- 漏洞位置：`vuln` (0x401205) - `gets@plt` 调用位于 0x40121d
- 漏洞详情：`vuln()` 函数在栈上分配了 0x70 (112) 字节的缓冲区 `[rbp-0x70]`，并将其直接传给 `gets()` 读取 stdin 输入。由于 `gets()` 不进行任何长度校验，且二进制文件未开启 Stack Canary，攻击者可通过输入超过 112 字节的数据，覆盖偏移 0x70 处的 Saved RBP 和偏移 0x78 处的返回地址。
- 已验证原语：
  1. **RELATIVE_WRITE**：通过 `gets()` 溢出，向固定栈偏移（0x70 和 0x78）写入攻击者控制的 8 字节数据。
  2. **STACK_CONTROL**：`leave` 指令执行后，被覆盖的 Saved RBP 被弹入 RBP 寄存器，攻击者完全控制 RBP 寄存器值。
  3. **RIP_CONTROL**：`ret` 指令执行时，被覆盖的返回地址被弹入 RIP，动态验证程序成功跳转到攻击者指定的任意地址（包括非 `endbr64` 目标），确认控制流劫持。
- 关键别名发现：ELF 属性标记启用了 CET SHSTK，但 CPU/内核层面未实际执行 Shadow Stack 保护，`ret` 劫持未触发 `SEGV_CPERR` (si_code=128)。
- 修复建议：废弃并移除 `gets()` 的使用，替换为 `fgets()` 并严格限制读取长度不超过缓冲区大小 (0x70)；在编译时开启 `-fstack-protector-strong` 启用栈溢出保护。

## 3. 利用链与后果
已完成端到端利用，实现任意代码执行。利用步骤如下：
1. **初始输入**：通过 stdin 向 `vuln()` 中的 `gets()` 发送构造的恶意载荷。
2. **栈溢出与控制流劫持**：填充 112 (0x70) 字节缓冲区，写入 8 字节伪造 RBP，并在偏移 120 (0x78) 处覆盖返回地址为 ROP gadget 地址，实现 RIP 控制。
3. **ROP 链执行**：利用 No PIE 的固定地址和 libc 基址，串联 ROP gadgets 绕过 `close(1)/close(2)` 关闭标准输出的限制，最终执行 `system("/bin/sh")` 或等价命令获取 shell。

## 4. 方法论
分析路径遵循：文件识别与安全防护分析 (S1) -> 静态逆向与漏洞根因定位 (S2) -> 动态调试与已验证原语提取 (S3) -> 端到端利用构造与验证 (S4)。通过 GDB 动态断点验证了内存写入、寄存器控制和 CET 绕过，最终生成自动化 exploit 脚本验证了最高级别后果。

## 5. 产物路径
| 产物类型 | 路径 |
| :--- | :--- |
| 最终利用脚本 (Exploit) | `/work/workspace/0025-2023-52-rop-revenge-20260909-140653/exploit.py` |
| 漏洞 PoC 脚本 | `/work/workspace/0025-2023-52-rop-revenge-20260909-140653/poc-BUG-001.py` |