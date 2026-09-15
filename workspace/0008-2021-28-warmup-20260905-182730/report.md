# 渗透测试报告：warmup

## 1. 任务概述
- 目标：针对 warmup echo 服务的二进制漏洞利用与原语验证
- 目标文件：`/work/workspace/0008-2021-28-warmup-20260905-182730/target`
- 文件类型：ELF64 LSB executable, x86-64, dynamically linked, not stripped
- 安全防护：Partial RELRO / NX enabled / No Canary / No PIE / libc 2.39
- 分析结果：已验证任意代码执行（RIP_CONTROL，成功重定向至 `get_shell` 函数）

## 2. 已确认漏洞
漏洞 BUG-001：栈缓冲区溢出（read 越界写入）
- CWE 分类：CWE-121 Stack-based Buffer Overflow
- 严重程度：严重
- 漏洞位置：main（0x401239）
- 漏洞详情：`read(0, rbp-0x70, 0x100)` 从 stdin 读取最多 256 字节到栈缓冲区，但缓冲区距 saved rbp 仅 112 字节。由于缺少长度校验且无 Canary，输入可覆盖 saved rbp（偏移 112）与返回地址（偏移 120），直接劫持控制流。
- 已验证原语：RIP_CONTROL（DIRECT，GDB 动态验证 ret 指令处 [rsp] 被覆盖为 0x4141414141414141 / 0x4242424242424242，并成功重定向至 get_shell 0x401182）；STACK_CONTROL（DIRECT，GDB 验证 rbp 寄存器被覆盖为攻击者控制值）
- 关键别名发现：buffer_start + 0x70 = saved_rbp；buffer_start + 0x78 = return_address；No PIE 基址 0x400000，get_shell 固定于 0x401182
- 修复建议：将 read 的 size 参数限制为缓冲区实际容量（0x70），并启用栈 Canary

漏洞 BUG-002：read 返回值符号扩展导致越界读
- CWE 分类：CWE-197 Off-by-one Error（使用未校验返回值作为索引）
- 严重程度：低
- 漏洞位置：main（0x401249）
- 漏洞详情：`read` 返回值存入 32 位 int 后执行 `eax = ret - 1` 并经 `cdqe` 符号扩展为 64 位索引。若 read 返回 0 或 -1，索引变为 -1 或 -2，导致 `[rbp+rax-0x70]` 访问缓冲区下方内存，引发 1 字节越界读或崩溃。
- 已验证原语：OOB_READ（THEORETICAL，静态分析确认负索引计算路径，未动态触发）
- 关键别名发现：read 返回值未校验即作为数组索引使用
- 修复建议：在使用 `read` 返回值作为索引前，增加 `if (ret <= 0) return;` 校验

## 3. 利用链与后果
1. 发送 256 字节 payload，填充 112 字节缓冲区 + 8 字节 saved rbp + 8 字节返回地址
2. 返回地址覆盖为 ret gadget（0x401016）用于栈对齐
3. 紧接写入 get_shell 地址（0x401182）
4. 发送 'Y\n' 退出循环，触发 `leave; ret`
5. RIP 被劫持至 get_shell，执行 `system("/bin/sh")`
- 关键偏移：saved rbp @ +0x70(112)，return address @ +0x78(120)
- 最终后果：任意代码执行（已验证）

## 4. 方法论
文件识别 → 防护分析（checksec）→ 逆向（定位 read 溢出与 get_shell）→ 原语验证（GDB 动态确认 RIP/STACK 控制）→ 利用构造（ret2win）

## 5. 产物路径
| 产物 | 路径 |
|------|------|
| PoC 脚本 | `/work/workspace/0008-2021-28-warmup-20260905-182730/poc-BUG-001.py` |
| 最终 exploit | `/work/workspace/0008-2021-28-warmup-20260905-182730/exploit.py` |