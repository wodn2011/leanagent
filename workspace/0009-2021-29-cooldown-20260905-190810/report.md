# 渗透测试报告：Echo Service

## 1. 任务概述
- 目标：对 Echo 服务二进制文件进行全链路渗透测试与漏洞验证
- 目标文件：`/work/workspace/0009-2021-29-cooldown-20260905-190810/target`
- 文件类型：ELF 64-bit LSB shared object, x86-64, dynamically linked
- 安全防护：Partial RELRO / Canary enabled / NX enabled / PIE enabled / GLIBC 2.39
- 分析结果：已验证任意代码执行（通过信息泄露绕过 Canary 并劫持 RIP）

## 2. 已确认漏洞
漏洞 BUG-001：栈缓冲区溢出
- CWE 分类：CWE-121（基于栈的缓冲区溢出）
- 严重程度：高
- 漏洞位置：`main (0x1248)`
- 漏洞详情：程序使用 `read(0, rbp-0x70, 0x100)` 读取最多 256 字节输入到仅 112 字节的栈缓冲区中，缺乏长度校验。溢出的 144 字节可覆盖至 rbp-0x8 处的 Canary、rbp+0 处的保存的 RBP 以及 rbp+0x8 处的返回地址。
- 已验证原语：STACK_CONTROL（直接覆写 Canary 触发 SIGABRT）；RIP_CONTROL（结合 BUG-002 逐字节泄露 Canary 后，在偏移 120 写入返回地址劫持 RIP 触发 SIGSEGV）。
- 关键别名发现：`buf[104..111]` 别名 `canary at rbp-0x8`；`buf[120..127]` 别名 `return address at rbp+0x8`。
- 修复建议：将 `read()` 的读取大小限制为缓冲区实际大小（0x70），并在读取后无条件添加 NULL 终止符。

漏洞 BUG-002：通过 printf 泄露栈信息
- CWE 分类：CWE-200（将信息暴露给未经授权的行为者）
- 严重程度：高
- 漏洞位置：`main (0x127b)`
- 漏洞详情：程序仅在 `buf[read_retval]` 为换行符时进行 NULL 终止，随后直接使用 `printf("%s", buf)` 输出。攻击者可通过控制输入长度避免触发终止条件，使 printf 越界读取栈内存，从而泄露 rbp-0x8 处的 Canary 值。
- 已验证原语：INFO_LEAK（通过发送 105-111 字节输入，逐字节泄露 7 个非零 Canary 字节）。
- 关键别名发现：`buf[104]` 对应 Canary 的最低字节（LSB，固定为 0x00），`buf[105..111]` 对应 Canary 的剩余 7 字节。
- 修复建议：在调用 `printf` 前，无条件对 `buf[read_retval]` 或 `buf[read_retval-1]` 进行 NULL 终止处理。

## 3. 利用链与后果
已验证端到端利用，实现任意代码执行（RIP_CONTROL），步骤如下：
1. **信息泄露**：在 7 次循环中分别发送 105 至 111 字节无换行符的输入，利用 `printf("%s")` 越界读取，逐字节泄露 7 个 Canary 字节。
2. **缓冲区溢出**：发送 128 字节 payload：104 字节填充 + 8 字节正确 Canary + 8 字节伪造 RBP + 8 字节受控返回地址（0x4141414141414141）。
3. **触发控制流劫持**：输入 'Y' 退出循环，Canary 校验通过，执行 `ret` 指令时 RIP 被劫持至受控地址，触发 SIGSEGV。
- 关键偏移：Canary 偏移 104，保存的 RBP 偏移 112，返回地址偏移 120。

## 4. 方法论
- 文件识别：确认目标 ELF 架构及输入接口（stdin 交互式 Echo 服务）。
- 防护分析：检测到 Partial RELRO、Canary、NX 及 PIE 防护机制。
- 逆向分析：定位 `main` 函数中 `read` 越界写入与 `printf` 条件终止的根因。
- 原语验证：动态构造 PoC，分别验证 Canary 覆写（SIGABRT）与返回地址劫持（SIGSEGV）。
- 利用构造：结合信息泄露与缓冲区溢出漏洞，编写最终 exploit 完成全链路控制流劫持。

## 5. 产物路径
| 产物类型 | 路径 |
| :--- | :--- |
| 最终利用脚本 | `/work/workspace/0009-2021-29-cooldown-20260905-190810/exploit.py` |
| 漏洞 PoC | `/work/workspace/0009-2021-29-cooldown-20260905-190810/poc-BUG-001.py` |