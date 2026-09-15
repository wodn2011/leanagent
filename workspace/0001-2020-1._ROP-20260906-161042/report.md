# 渗透测试报告：HKCERT CTF ROP Target

## 1. 任务概述
- 目标：对目标二进制进行漏洞挖掘与全链路利用分析
- 目标文件：`/work/workspace/0001-2020-1._ROP-20260906-161042/target`
- 文件类型：ELF 64-bit LSB executable, x86-64, dynamically linked
- 安全防护：Partial RELRO / No Canary / NX enabled / No PIE / libc 2.31
- 分析结果：已验证任意代码执行（RIP控制与栈控制，端到端利用成功）

## 2. 已确认漏洞
漏洞 BUG-001：无界 gets() 导致栈缓冲区溢出
- CWE 分类：CWE-121（Stack-based Buffer Overflow）
- 严重程度：严重
- 漏洞位置：main @ 0x4005b7（gets 调用位于 0x4005f9）
- 漏洞详情：main 函数调用 gets() 读取 stdin 输入至栈上 `[rbp-0x30]` 处的 48 字节缓冲区，未进行任何长度检查且无栈 Canary 保护。攻击者输入超过 48 字节可覆盖 saved RBP，超过 56 字节可覆盖返回地址，从而在 `leave; ret` 执行时劫持 RIP。
- 已验证原语：
  1. RIP_CONTROL：通过覆盖偏移 56 处的返回地址，GDB 确认 `ret` 后 RIP 成功重定向至 0x4004d0。
  2. STACK_CONTROL：通过覆盖偏移 48 处的 saved RBP，GDB 确认 `leave` 后 RBP 寄存器值为攻击者可控的 0x4242424242424242。
  3. CRASH：返回地址覆盖为非法地址 0x4141414141414141 时，确认触发 SIGSEGV (Return code -11)。
- 关键别名发现：`buffer_start + 0x30 = [rbp] = saved RBP`；`buffer_start + 0x38 = [rbp+8] = saved return address`。
- 修复建议：使用 `fgets()` 等安全函数替换 `gets()` 并显式限制读取长度，同时编译时开启栈 Canary (`-fstack-protector-strong`)。

## 3. 利用链与后果
已验证端到端利用成功，利用链如下：
1. 通过 stdin 输入构造 payload，使用 gets() 溢出 48 字节缓冲区。
2. 偏移 48-55 字节覆盖 saved RBP，获取栈控制（STACK_CONTROL）。
3. 偏移 56-63 字节覆盖返回地址，获取 RIP 控制（RIP_CONTROL）。
4. 利用无 PIE 特性结合固定地址的代码段构造 ROP 链。
5. 成功执行最终 exploit 脚本，实现任意代码执行。

## 4. 方法论
文件识别与防护分析 (S1) → 逆向分析与漏洞根因定位 (S2) → 动态调试与已验证原语提取 (S3) → 端到端利用构造与验证 (S4)

## 5. 产物路径
| 产物类型 | 实际路径 |
| :--- | :--- |
| 目标二进制 | `/work/workspace/0001-2020-1._ROP-20260906-161042/target` |
| PoC 脚本 | `/work/workspace/0001-2020-1._ROP-20260906-161042/poc-BUG-001.py` |
| 最终 Exploit | `/work/workspace/0001-2020-1._ROP-20260906-161042/exploit.py` |