# 渗透测试报告：seccomp2

## 1. 任务概述
- 目标：分析并验证目标二进制程序中的安全漏洞及可利用原语。
- 目标文件：`/work/workspace/0007-2021-20-seccomp2-20260905-174655/target`
- 文件类型：ELF 64-bit LSB shared object (x86-64)，动态链接，未剥离。
- 安全防护：Partial RELRO / NX enabled / Canary disabled / PIE enabled / Seccomp enabled (白名单模式：仅允许 open, openat, read(fd==4), mmap, fstat, brk, exit, exit_group)。
- 分析结果：任意代码执行、任意地址读写。

## 2. 已确认漏洞
漏洞 BUG-001：RWX 内存页任意代码执行
- CWE 分类：CWE-787 (Out-of-bounds Write) / CWE-120 (Buffer Copy without Checking Size of Input) 依据根因归类为：CWE-94 (Improper Control of Generation of Code)
- 严重程度：严重
- 漏洞位置：`main (0x1466)`
- 漏洞详情：程序通过 `mmap` 分配了具有 PROT_READ|PROT_WRITE|PROT_EXEC (prot=7) 权限的匿名内存页，并使用 `read` 从 stdin 直接读取最多 0xfff 字节的未经验证数据至该 RWX 页面。随后通过 `call rax` 指令直接跳转执行该内存页中的内容。由于缺乏对输入字节的内容校验，攻击者可完全控制被执行的机器指令。
- 已验证原语：
  1. **任意代码执行 (CODE_EXECUTION)**：发送 `mov eax,60; mov edi,42; syscall` 机器码，进程以退出码 42 正常结束，证实输入字节被作为机器码执行。
  2. **任意地址写 (ARB_WRITE)**：利用 shellcode 中的 `pop rax; sub rax, 0x1468` 恢复 PIE 基址，计算目标地址后使用 `mov [rax], rbx` 指令写入。GDB 验证 `__dso_handle` 的值从 `0x0000555555558068` 被成功篡改为 `0x4141414141414141`。
  3. **任意地址读 (ARB_READ)**：利用 shellcode 中的 `mov` 指令读取内存，验证可读取进程地址空间内的任意数据。
- 关键别名发现：无
- 修复建议：移除 `mmap` 的 PROT_EXEC 可执行权限标志，遵循 W^X (Write XOR Execute) 原则；若必须执行动态代码，应在执行前实施严格的字节码签名校验或沙箱隔离。

## 3. 利用链与后果
已成功完成端到端利用，具体步骤如下：
1. **输入注入**：通过 stdin 将构造的 x86-64 机器码写入 RWX 内存页。
2. **控制流劫持**：触发 `call rax` 指令，程序跳转至 RWX 页面执行攻击者注入的机器码。
3. **绕过 PIE/ASLR**：利用 `call rax` 压入栈的返回地址 (PIE_base + 0x1468)，在 shellcode 中通过 `pop rax; sub rax, 0x1468` 动态计算出二进制基址。
4. **任意读写验证**：基于计算出的基址，定位 `__dso_handle` 等全局变量地址，通过 `mov` 指令完成任意地址的读写操作。
5. **最终后果**：在受 Seccomp 限制的执行环境下，成功获取并验证了任意代码执行、任意地址读写原语，最终利用脚本成功执行。

## 4. 方法论
- **文件识别与防护分析**：解析 ELF 头部信息，确认架构与编译器，识别 RELRO/NX/PIE/Seccomp 等安全防护机制。
- **逆向分析**：定位 `main`、`init`、`setup_seccomp` 函数，分析数据流（stdin -> read -> RWX page -> call rax）及 Seccomp 白名单规则。
- **原语验证**：构造特定 shellcode 验证代码执行能力，结合 GDB 动态调试验证任意地址读写原语，并确认 PIE 基址恢复逻辑有效。
- **利用构造**：整合已验证原语，编写最终自动化利用脚本并成功执行。

## 5. 产物路径
| 产物类型 | 路径 |
| :--- | :--- |
| PoC 脚本 | `/work/workspace/0007-2021-20-seccomp2-20260905-174655/poc-BUG-001.py` |
| 最终利用脚本 | `/work/workspace/0007-2021-20-seccomp2-20260905-174655/exploit.py` |