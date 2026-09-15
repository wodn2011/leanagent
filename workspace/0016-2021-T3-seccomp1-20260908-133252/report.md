# 渗透测试报告：seccomp1

## 1. 任务概述
- 目标：分析并绕过目标二进制中的 seccomp 沙箱保护机制
- 目标文件：`/work/workspace/0016-2021-T3-seccomp1-20260908-133252/target`
- 文件类型：ELF 64-bit x86-64 (动态链接，未剥离)
- 安全防护：Partial RELRO / NX enabled / PIE enabled / Canary disabled / Seccomp enabled (default KILL) / Glibc 2.39
- 分析结果：任意文件读写（通过 seccomp 文件描述符重用绕过实现）

## 2. 已确认漏洞
漏洞 BUG-001：Seccomp 沙箱文件描述符重用绕过
- CWE 分类：CWE-665 (Improper Initialization) / CWE-863 (Incorrect Authorization)
- 严重程度：高
- 漏洞位置：`setup_seccomp` (0x11c5)
- 漏洞详情：`setup_seccomp()` 限制 `read()` 仅能使用 fd==0，`write()` 仅能使用 fd==1，但 `close(3)`、`open(2)` 和 `openat(0x101)` 被无条件列入白名单。攻击者可通过 `close(0)` 释放 fd 0，随后 `open("/flag.txt")` 复用 fd 0，此时 `read(0, buf, n)` 将读取被打开的文件而非标准输入，从而绕过 fd==0 的限制。同理，`close(1)+open()` 可重用 fd 1 进行任意文件写入。
- 已验证原语：
  1. **任意文件读 (ARB_READ)**：已验证。PoC 执行 `close(0) + open('/flag.txt') + read(0, buf, 256) + write(1, buf, n)`，成功读取 `/flag.txt` 内容 `test_flag_content_here` 并输出至 stdout，进程返回码 0。
  2. **任意文件写 (ARB_WRITE)**：已验证。PoC 执行 `close(1) + open('/tmp/s3_write_test', O_WRONLY|O_CREAT|O_TRUNC) + write(1, 'S3_ARB_WRITE_VERIFIED', 22)`，成功在 `/tmp/s3_write_test` 写入指定内容，进程返回码 0。
- 关键别名发现：seccomp 的 `SCMP_CMP_EQ` 比较仅检查文件描述符的整数值，而非底层文件对象标识。`close+open` 操作改变了 fd 0/fd 1 绑定的文件对象，但整数检查仍能通过，形成 TOCTOU 逻辑漏洞。
- 修复建议：移除 seccomp 白名单中的 `open`、`openat` 和 `close` 系统调用，或禁止对 fd 0 和 fd 1 执行 `close` 操作。

## 3. 利用链与后果
已验证端到端利用，步骤如下：
1. 目标程序将用户输入读入 RWX mmap 页并执行 (`call rax` at 0x1500)
2. Shellcode 执行 `close(0)` 释放标准输入文件描述符
3. Shellcode 执行 `open("/flag.txt", O_RDONLY)`，复用 fd 0
4. Shellcode 执行 `read(0, buf, 256)`，读取 `/flag.txt` 内容（通过 fd==0 检查）
5. Shellcode 执行 `write(1, buf, n)`，将内容输出至 stdout
6. 进程正常退出，返回码 0，成功获取文件内容

## 4. 方法论
文件识别 → 安全防护分析 → 逆向 `setup_seccomp` → 识别 fd 重用逻辑漏洞 → 构造并执行 PoC 验证任意文件读写原语 → 端到端利用确认

## 5. 产物路径
| 产物类型 | 路径 |
|---------|------|
| 最终 Exploit | `/work/workspace/0016-2021-T3-seccomp1-20260908-133252/exploit.py` |
| PoC 脚本 | `/work/workspace/0016-2021-T3-seccomp1-20260908-133252/poc-BUG-001.py` |
| 目标二进制 | `/work/workspace/0016-2021-T3-seccomp1-20260908-133252/target` |