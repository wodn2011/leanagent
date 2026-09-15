# 渗透测试报告：0017-2022-30-shellcode-runner2

## 1. 任务概述
- 目标：对 shellcode 运行器进行渗透测试，验证输入过滤机制的绕过能力及最高级别后果。
- 目标文件：`/work/workspace/0017-2022-30-shellcode-runner2-20260908-134900/target`
- 文件类型：ELF 64-bit, x86-64, 静态链接, 未剥离
- 安全防护：Partial RELRO, NX enabled, Canary enabled, No PIE (基址 0x400000), CET (IBT/SHSTK) 标记但运行时未强制执行, 无 seccomp。
- 分析结果：任意代码执行（在 RWX 内存区域执行任意指令及系统调用）。

## 2. 已确认漏洞

漏洞 BUG-001：通过 NUL 字节与 strlen 绕过 shellcode 过滤器
- CWE 分类：CWE-20 (Improper Input Validation)
- 严重程度：严重
- 漏洞位置：`is_all_upper` (0x401819), `main` (0x4018dd)
- 漏洞详情：`is_all_upper` 函数使用 `strlen(buf)` 作为字节过滤的循环边界，而 `strlen` 遇到 NUL (0x00) 字节即停止扫描。但程序通过 `read(0, mmap_buf, 99)` 读取原始二进制数据，不会在 NUL 处终止。攻击者可在输入第 1 字节后注入 NUL，导致过滤器仅检查首字节，后续所有字节均未经过滤直接存入 RWX 内存并被 `call rax` 执行。
- 已验证原语：任意代码执行（类型：CODE_EXECUTION，验证方式：动态执行 PoC，关键证据：成功执行 `exit(42)`、`exit(99)` 及 `write(1, mmap_buf, 14)` 系统调用，证明完全控制指令流与系统调用号及参数）。
- 关键别名发现：`is_all_upper` 循环边界 `strlen(buf)` 与实际数据长度 `read()` 返回值存在别名关系；NUL 字节具有双重作用，既终止 `strlen` 扫描，又作为 `ADD [rax], al` 指令的 opcode 及 ModRM 字节，实现无害过渡。
- 修复建议：将 `is_all_upper` 中的循环边界从 `strlen(buf)` 修改为 `read()` 函数的实际返回值，确保对所有读取的字节进行完整校验。

漏洞 BUG-002：read 返回值检查不当导致越界读写
- CWE 分类：CWE-252 (Unchecked Return Value) / CWE-787 (Out-of-bounds Write)
- 严重程度：中
- 漏洞位置：`main` (0x4019b8)
- 漏洞详情：`read()` 的返回值仅检查了是否为 0 (EOF)，未拦截负数（错误返回 -1）。当发生错误时，代码使用 `-1` 作为索引计算 `buf[read_ret - 1]`，导致符号扩展后访问 `mmap_buf - 2` (0x1336FFFE) 处的内存，引发越界读取，若该字节恰为 0x0a 则触发越界写入 0x00。
- 已验证原语：潜在越界读写（类型：OOB_READ/OOB_WRITE，验证方式：静态分析确认数据流与指令逻辑，关键证据：0x4019e3 处对 0x1336FFFE 的越界读取，及 0x4019fd 处条件性越界写入）。
- 关键别名发现：`read_ret` 变量在作为大小检查和数组索引时存在符号扩展别名，`eax` 通过 `cdqe` 符号扩展为 `rax` 导致负索引。
- 修复建议：将 `read()` 返回值的检查逻辑从 `== 0` 修改为 `<= 0`，同时拦截 EOF 和错误状态。

漏洞 BUG-003：执行 shellcode 前泄露寄存器状态
- CWE 分类：CWE-200 (Information Exposure)
- 严重程度：低
- 漏洞位置：`main` (0x401afb)
- 漏洞详情：在通过 `call rax` 执行用户控制的 shellcode 之前，`main` 函数将所有通用寄存器（包括 rsp, rbp 等）通过 `printf` 打印到 stdout。这向攻击者泄露了运行时的栈地址和 libc 数据段地址，从而绕过了 ASLR 保护。
- 已验证原语：信息泄露（类型：INFO_LEAK，验证方式：静态分析与运行时行为确认，关键证据：0x401afb 处调用 `_IO_printf` 输出 14 个寄存器值）。
- 关键别名发现：寄存器转储输出与 shellcode 执行前的进程状态存在直接映射关系，为 shellcode 提供了精确的内存布局信息。
- 修复建议：移除在执行用户输入前的寄存器转储调试功能，或在执行 shellcode 前将寄存器清零。

## 3. 利用链与后果
已验证端到端利用，成功实现任意代码执行。利用链步骤如下：
1. 构造 Payload：`[0x50]` (合法字符 'P') + `[0x00]` (NUL，截断 strlen) + `[0x00]` (ModRM，作为无害指令 ADD [rax], al) + `[任意 shellcode]`。
2. 通过 stdin 发送 Payload，`read(0, mmap_buf, 99)` 将原始字节读入位于 0x13370000 的 RWX 内存区。
3. `is_all_upper` 调用 `strlen` 获取长度 1，仅校验首字节 'P' 并通过检查。
4. `main` 执行 `call rax` (0x401b4b)，跳转到 0x13370000，CET/IBT 未强制执行，不触发异常。
5. CPU 顺序执行 NUL 字节构成的无害指令，随后执行攻击者注入的任意 shellcode。
6. 成功执行 `exit(42)`、`exit(99)` 和 `write(1, mmap_buf, 14)` 系统调用，验证了完全控制指令流与系统调用。

## 4. 方法论
- 文件识别：确认目标为静态链接 ELF 64-bit，无 PIE。
- 防护分析：解析 ELF 安全标志，确认 NX/Canary/RELRO 状态，发现 CET 标记但运行时未强制执行，无 seccomp。
- 逆向分析：定位 `main` 中的输入读取与 `call rax` 调用，分析 `is_all_upper` 过滤逻辑，发现 `strlen` 与 `read` 长度不一致缺陷。
- 原语验证：构造包含 NUL 截断的 PoC，动态验证了任意代码执行原语（执行不同退出码和 write 系统调用）。
- 利用构造：整合原语形成稳定利用链，通过管道传入二进制 Payload 成功执行任意 shellcode。

## 5. 产物路径
| 产物类型 | 路径 |
| :--- | :--- |
| 最终利用脚本 | `/work/workspace/0017-2022-30-shellcode-runner2-20260908-134900/exploit.py` |
| PoC 验证脚本 | `/work/workspace/0017-2022-30-shellcode-runner2-20260908-134900/poc-BUG-001.py` |