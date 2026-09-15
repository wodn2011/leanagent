# 渗透测试报告：flag-hasher

## 1. 任务概述
- 目标：针对目标二进制文件进行全链路漏洞挖掘与利用验证
- 目标文件：`/work/workspace/0030-2024-55-flag-hasher-20260909-195252/target`
- 文件类型：ELF 64-bit LSB shared object (x86-64)，动态链接，未剥离
- 安全防护：Full RELRO / Canary / NX / PIE / CET (IBT+SHSTK) / ASLR / glibc 2.39
- 分析结果：信息泄露（通过越界读实现栈/libc/PIE基址泄露）

## 2. 已确认漏洞

漏洞 BUG-001：越界数组索引缺失边界检查
- CWE 分类：CWE-129 (Improper Validation of Array Index)
- 严重程度：高
- 漏洞位置：`main` (0x17e5)
- 漏洞详情：在读取哈希记录路径中，`scanf('%u')` 读取的用户输入索引未进行上界检查即直接用于 `hash_array` 数组寻址。攻击者可提供大于 15 的索引，导致越界读取栈上相邻数据（如栈帧指针、返回地址等），并将读取到的 8 字节值作为指针解引用，打印该地址处的 32 字节数据。
- 已验证原语：信息泄露（通过 idx 146 泄露栈/libc/PIE 地址，通过 idx 147 泄露 libc 代码，通过 idx 151 泄露 PIE 代码；通过 idx 145 解引用随机 canary 值导致 SIGSEGV 拒绝服务）
- 关键别名发现：idx 146 = rbp+0 (saved rbp)；idx 147 = rbp+8 (return address)；idx 151 = rbp+0x28 (PIE addr)；idx 16-145 = text_buf (被 memset 清零，无法用于伪造指针)
- 修复建议：在 0x17e5 处的数组访问前增加索引上界检查（如 `cmp idx, 0xf; ja abort`），限制索引范围为 0-15。

漏洞 BUG-002：read 返回值未校验即用作索引
- CWE 分类：CWE-252 (Unchecked Return Value)
- 严重程度：中
- 漏洞位置：`main` (0x16bc)
- 漏洞详情：在计算哈希路径中，`read(0, buf, 0x3ff)` 的返回值未检查错误/EOF 条件即直接减 1 并用作 `text_buf` 的索引。若 `read()` 返回 0 或 -1，索引经符号扩展后变为巨大的负值，导致越界读取栈帧之外的 1 字节数据。
- 已验证原语：理论越界读（1字节 OOB read，仅用于换行符比较，未存储或写入）
- 关键别名发现：read_ret=0 时索引为 -1 (0xFFFFFFFFFFFFFFFF)；read_ret=-1 时索引为 -2 (0xFFFFFFFFFFFFFFFE)
- 修复建议：在 0x16b7 处减 1 操作前增加返回值检查（如 `cmp eax, 0; jle skip`），确保仅在 `read()` 成功时才进行索引计算。

## 3. 利用链与后果
已验证端到端利用链（基于 BUG-001）：
1. 设置环境变量 `flag=testflag` 启动目标程序
2. 选择菜单选项 2 (Read Hash record)
3. 输入索引 146 → 泄露 32 字节数据，解码得到栈地址、libc 地址、PIE 地址
4. 选择菜单选项 2，输入索引 147 → 泄露 32 字节 libc .text 代码
5. 选择菜单选项 2，输入索引 151 → 泄露 32 字节 PIE .text 代码（以 endbr64 开头）
6. 选择菜单选项 2，输入索引 145 → 解引用 canary 随机值导致 SIGSEGV

关键偏移：
- idx 146: rbp+0 (saved rbp) → 泄露栈/libc/PIE 地址
- idx 147: rbp+8 (return address) → 泄露 libc 代码
- idx 151: rbp+0x28 → 泄露 PIE 代码
- idx 145: rbp-8 (canary) → 触发 SIGSEGV

最终后果：成功实现信息泄露，绕过 ASLR 获取栈/libc/PIE 基址。利用脚本 `exploit.py` 执行成功。

## 4. 方法论
分析路径：文件识别 (file/readelf) → 防护分析 (checksec) → 逆向分析 (objdump/gdb) → 原语验证 (动态调试) → 利用构造 (PoC/exploit)

## 5. 产物路径
| 产物类型 | 路径 |
|---------|------|
| PoC (BUG-001) | `/work/workspace/0030-2024-55-flag-hasher-20260909-195252/poc-BUG-001.py` |
| 最终 Exploit | `/work/workspace/0030-2024-55-flag-hasher-20260909-195252/exploit.py` |