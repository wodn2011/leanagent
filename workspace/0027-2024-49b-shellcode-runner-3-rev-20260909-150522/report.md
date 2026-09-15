# 渗透测试报告：shellcode_runner3

## 1. 任务概述
- 目标：绕过 shellcode 黑名单过滤机制并验证最高级别利用后果
- 目标文件：`/work/workspace/0027-2024-49b-shellcode-runner-3-rev-20260909-150522/target`
- 文件类型：ELF 64-bit DYN (PIE executable), amd64, little-endian
- 安全防护：Full RELRO / Canary / NX / PIE / CET (IBT+SHSTK) / GLIBC 2.39
- 分析结果：任意代码执行（已验证通过黑名单绕过和复用 libc syscall 实现 mprotect 将执行段改回 RWX）

## 2. 已确认漏洞

漏洞 BUG-001：不完整的黑名单过滤机制
- CWE 分类：CWE-184（Incomplete List of Disallowed Inputs）
- 严重程度：严重
- 漏洞位置：blacklist (0x12ed), main (0x14ae)
- 漏洞详情：`blacklist()` 函数仅静态扫描输入是否包含 `0x0f` 和 `0xcd` 字节，以阻止 `syscall` 和 `int 0x80` 指令。但该黑名单无法阻止运行时动态指令发现，攻击者可在 shellcode 中通过读取 `fs:0x00` 获取 TLS 地址，并向前扫描内存以定位 libc 中的 `0x0f 0x05` 指令并直接跳转执行。
- 已验证原语：任意代码执行（通过跳转至 libc 中的 syscall gadget 执行 `mprotect(0x13370000, 0x1000, 7)`，成功将执行段从 R-X 改为 RWX，为后续自修改代码和任意系统调用提供基础）。
- 关键别名发现：`fs:0x00`（TLS 自指针，提供已知可写内存地址以初始化栈）；`TLS + 0x2B000`（libc .text 节起始地址的固定相对偏移）；`0x0f 0x05 in libc .text`（可复用的 syscall 指令）。
- 修复建议：放弃黑名单机制，改用基于白名单的沙箱（如 seccomp 严格过滤），仅允许安全的系统调用。

漏洞 BUG-002：read 返回值检查不完整
- CWE 分类：CWE-252（Unchecked Return Value）
- 严重程度：低
- 漏洞位置：main (0x13f8)
- 漏洞详情：`main()` 在调用 `read()` 后仅检查返回值是否为 0（EOF），未检查负值（错误）。若 `read()` 返回 -1，程序会继续执行全 0 的 shellcode 缓冲区。
- 已验证原语：空指针解引用引发崩溃（缓冲区全 0 字节被解码为 `add BYTE PTR [rax], al`，在 rax=0 时触发 SIGSEGV 拒绝服务）。
- 关键别名发现：无
- 修复建议：正确检查 `read()` 的返回值，遇到负值（错误）时进行妥善处理或终止执行。

漏洞 BUG-003：mprotect 返回值未检查
- CWE 分类：CWE-252（Unchecked Return Value）
- 严重程度：低
- 漏洞位置：main (0x143d)
- 漏洞详情：`main()` 调用 `mprotect()` 将 shellcode 区域权限从 RWX 降级为 R-X，但未检查返回值。若调用失败，该区域将保持 RWX 权限，直接允许自修改代码。
- 已验证原语：无（理论可导致自修改代码绕过，但在当前环境中未直接触发该路径，实际通过 BUG-001 达成同等效果）。
- 关键别名发现：无
- 修复建议：检查 `mprotect()` 返回值，若失败则拒绝执行 shellcode。

漏洞 BUG-004：mmap 返回值检查不完整
- CWE 分类：CWE-252（Unchecked Return Value）
- 严重程度：低
- 漏洞位置：main (0x139f)
- 漏洞详情：`main()` 检查 `mmap()` 返回值是否为 -1（MAP_FAILED），但在某些边缘情况下若返回其他错误码可能导致非预期行为。
- 已验证原语：无
- 关键别名发现：无
- 修复建议：严格验证 `mmap()` 返回的指针有效性。

## 3. 利用链与后果
已验证端到端利用，步骤如下：
1. **初始状态**：shellcode 执行时所有寄存器为 0，rdi=0x13370000，rsp=0，执行段权限为 R-X。
2. **获取可写内存**：执行 `mov rax, fs:0x0` 获取 TLS 基址（0x7ffff7da0740），设置 rsp=rax+0x200 建立栈。
3. **构造系统调用参数**：设置 rax=10 (mprotect)，rdi=0x13370000，rsi=0x1000，rdx=7 (PROT_RWX)。
4. **定位 syscall gadget**：从 TLS 向前扫描内存（偏移 0x2B000 处进入 libc .text），寻找 `0x0f 0x05` 字节序列。
5. **执行系统调用**：跳转至 libc 中的 syscall 指令（如 0x7ffff7dcb8b5），成功执行 `mprotect`，返回 rax=0。
6. **最终后果**：shellcode 执行段 (0x13370000) 权限变更为 rwxp，实现任意代码执行能力。

## 4. 方法论
文件识别 → 防护分析 → 逆向工程 → 原语验证 → 利用构造

## 5. 产物路径
| 产物类型 | 路径 |
|---|---|
| 最终利用脚本 | `/work/workspace/0027-2024-49b-shellcode-runner-3-rev-20260909-150522/exploit.py` |
| BUG-001 PoC | `/work/workspace/0027-2024-49b-shellcode-runner-3-rev-20260909-150522/poc-BUG-001.py` |