# 渗透测试报告：hkcertCTF 2023 MIPS Pwn Target

## 1. 任务概述
- 目标：对静态链接的 MIPS 架构目标二进制进行漏洞挖掘与利用链验证
- 目标文件：`/work/workspace/0024-2023-51-mips-rop-20260909-134236/target`
- 文件类型：ELF 32-bit, MIPS32r2 Big-Endian, o32 ABI, 静态链接
- 安全防护：Partial RELRO / Canary 未在 main 中启用 / NX Disabled / No PIE / FORTIFY 关闭
- 分析结果：已验证任意代码执行（通过栈溢出控制 $ra 寄存器并劫持控制流，结合 ROP 实现最终利用）

## 2. 已确认漏洞
漏洞 BUG-001：无界 gets 导致的栈缓冲区溢出
- CWE 分类：CWE-121 (Stack-based Buffer Overflow) / CWE-242 (Use of Inherently Dangerous Function)
- 严重程度：严重
- 漏洞位置：`main (0x4007a0)`，具体在 `0x40082c` 调用 `gets`
- 漏洞详情：`main` 函数使用不安全的 `gets` 函数从 stdin 读取输入到栈缓冲区 `sp+0x18`，由于 `gets` 不接受长度参数，导致无界写入。缓冲区到保存的返回地址 `saved ra` (`sp+0x64`) 仅有 76 字节距离，攻击者可通过提供超长输入覆盖 `saved ra` 及后续栈内容。`main` 函数未启用栈 Canary 保护，溢出无法被运行时检测。
- 已验证原语：
  1. **STACK_CONTROL (PRIM-001)**：通过 Unicorn 动态验证，输入 76 字节即可覆盖 `saved ra`，输入 80 字节可完全控制 `saved ra` (0x41414141) 与 `saved fp` (0x45454545)，且 80 字节后的扩展栈空间完全可控，为 ROP 链提供空间。
  2. **RIP_CONTROL (PRIM-002)**：通过 Unicorn 动态验证，`main` 的 epilogue (`0x400840`) 执行 `lw $ra,0x64($sp); jr $ra`，成功将攻击者指定的任意地址（如 0x41414141 或 0x42424242）加载到 `$ra` 寄存器并跳转。
- 关键别名发现：缓冲区起始 `sp+0x18` 到 `saved ra` (`sp+0x64`) 的偏移为 76 字节 (0x4c)；`saved gp` 位于 `sp+0x10`，在缓冲区之前，正向溢出不破坏 `$gp`，确保 gp-relative 寻址的 ROP gadget 正常工作。
- 修复建议：将 `gets(buf)` 替换为 `fgets(buf, size, stdin)` 限制读取长度，并确保 `main` 函数启用栈 Canary 保护。

## 3. 利用链与后果
已通过 Unicorn 仿真完成端到端利用验证，成功实现任意代码执行。利用步骤如下：
1. **初始输入**：通过 stdin 向 `gets` 发送构造的 payload。
2. **栈溢出与控制流劫持**：76 字节填充覆盖至 `saved ra`，写入 ROP 链起始 gadget 地址，`main` 返回时 `$ra` 被劫持。
3. **ROP 链执行**：利用无 PIE 的固定地址，跳转至 `__libc_csu_init` 的 ret2csu epilogue (`0x4010c4`) 控制参数寄存器 `$a0-$a2`。
4. **系统调用**：结合 syscall gadget (`0x41f340`)，从栈加载 syscall number 并执行 `execve("/bin/sh", 0, 0)` 获取 shell。

## 4. 方法论
分析路径：文件识别与安全防护分析 (S1) → 逆向定位 `gets` 无界写入与栈帧布局 (S2) → 使用 Unicorn Engine 仿真动态验证 STACK_CONTROL 与 RIP_CONTROL 原语 (S3) → 构造 ROP 链并验证最终利用 (S4)。

## 5. 产物路径
| 产物类型 | 路径 |
|---|---|
| 漏洞 PoC | `/work/workspace/0024-2023-51-mips-rop-20260909-134236/poc-BUG-001.py` |
| 最终 Exploit | `/work/workspace/0024-2023-51-mips-rop-20260909-134236/exploit.py` |