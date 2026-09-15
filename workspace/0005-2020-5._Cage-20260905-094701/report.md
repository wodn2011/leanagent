# 渗透测试报告：0005-2020-5._Cage

## 1. 任务概述
- 目标：针对沙箱二进制文件进行全链路漏洞挖掘与原语验证分析
- 目标文件：`/work/workspace/0005-2020-5._Cage-20260905-094701/target`
- 文件类型：ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
- 安全防护：Full RELRO, NX enabled, PIE enabled, CET enabled (IBT+SHSTK), seccomp enabled (SCMP_ACT_KILL_PROCESS 白名单模式), libc 2.39
- 分析结果：相对地址越界写与拒绝服务（基于已验证原语定级，未拔高至任意代码执行）

## 2. 已确认漏洞

漏洞 BUG-001：read() 返回值未校验导致越界写
- CWE 分类：CWE-252 (Unchecked Return Value)
- 严重程度：高
- 漏洞位置：main (0x13f3)
- 漏洞详情：main 函数的 read 循环中，未检查 read() 的返回值是否为负数（错误/EINTR）。当 read() 返回 -1 时，偏移累加器变为 0xFFFFFFFF，随后被符号扩展为 64 位并加到缓冲区指针上，导致下一次 read() 调用向 buf-1 写入数据，且大小参数发生 32 位整型溢出变为 0x1001，造成越界写。
- 已验证原语：RELATIVE_WRITE (BUG-001) - 通过发送 SIGURG/SIGWINCH 中断阻塞的 read() 触发 EINTR，验证了偏移损坏并导致向 buf-1 越界写入（GDB 证实目标地址与大小）；CRASH (BUG-001) - 因 buf-1 落在未映射内存页，触发 SIGSEGV 进程崩溃（退出码 -11）。
- 关键别名发现：偏移 0xFFFFFFFF 经 `movsxd` 符号扩展为 0xFFFFFFFFFFFFFFFF，目标地址固定为 buf-1；大小参数 0x1000 - 0xFFFFFFFF 在 32 位运算下回绕为 0x1001。
- 修复建议：在累加 read() 返回值前增加校验，若 ret < 0 处理错误并退出，若 ret == 0 处理 EOF。

漏洞 BUG-002：mmap() 返回值未校验导致无效指针解引用
- CWE 分类：CWE-252 (Unchecked Return Value)
- 严重程度：中
- 漏洞位置：main (0x138e)
- 漏洞详情：main 函数调用 mmap() 分配 RWX 内存后，未检查返回值是否为 MAP_FAILED。若 mmap() 失败，后续 read() 将向无效地址 0xFFFFFFFFFFFFFFFF 写入，且最终通过 `call rdx` 尝试执行该无效地址，导致段错误。
- 已验证原语：暂无动态验证原语（理论分析为 CRASH/无效指针解引用）。
- 关键别名发现：无
- 修复建议：在调用 mmap() 后增加 `if (buf == MAP_FAILED)` 错误处理逻辑。

漏洞 BUG-003：seccomp_arch_add() 返回值未校验导致沙箱绕过
- CWE 分类：CWE-252 (Unchecked Return Value)
- 严重程度：高
- 漏洞位置：bamAll (0x12fe)
- 漏洞详情：bamAll 函数调用 seccomp_arch_add() 限制架构，但未检查返回值。若该函数失败，x32 ABI 系统调用可能绕过 seccomp 白名单过滤，导致沙箱隔离失效。
- 已验证原语：暂无动态验证原语（理论分析为沙箱绕过）。
- 关键别名发现：无
- 修复建议：检查 seccomp_arch_add() 的返回值，失败时进行重置并退出。

## 3. 利用链与后果
已验证利用链（BUG-001 触发崩溃）：
1. 攻击者向目标进程 stdin 发送部分数据（不足 0x1000 字节），使 read() 阻塞等待
2. 攻击者发送 SIGURG (信号 23) 或 SIGWINCH (信号 28) 中断阻塞的 read()
3. read() 返回 -1 (EINTR)，偏移累加器损坏为 0xFFFFFFFF
4. 循环继续，下一次 read() 计算出目标地址 buf-1，大小 0x1001
5. 攻击者发送后续数据触发越界写，因 buf-1 未映射导致 SIGSEGV (退出码 -11)

当前卡点：在当前内存布局中，buf-1 落在未映射的内存间隙，导致相对越界写直接引发崩溃，未能成功腐蚀到相邻可写内存以实现完整任意地址读写。

## 4. 方法论
分析路径：文件识别 (ELF 64-bit) → 防护分析 (Full RELRO/NX/PIE/seccomp) → 逆向分析 (main/bamAll/bam 函数逻辑) → 原语验证 (GDB 强制返回值 + 信号注入 EINTR 触发) → 利用构造 (PoC 脚本验证崩溃)。

## 5. 产物路径
| 产物类型 | 路径 |
|---|---|
| Exploit | `/work/workspace/0005-2020-5._Cage-20260905-094701/exploit.py` |
| PoC (BUG-001) | `/work/workspace/0005-2020-5._Cage-20260905-094701/poc-BUG-001.py` |