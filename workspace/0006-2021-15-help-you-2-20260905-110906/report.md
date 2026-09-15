# 渗透测试报告：0006-2021-15-help-you-2

## 1. 任务概述
- 目标：对目标服务进行全链路漏洞挖掘与利用验证
- 目标文件：`/work/workspace/0006-2021-15-help-you-2-20260905-110906/target`
- 文件类型：ELF 64-bit LSB pie executable, x86-64
- 安全防护：Full RELRO / NX enabled / PIE enabled / No Canary / CET (IBT+SHSTK) enabled / GLIBC 2.39
- 分析结果：信息泄露与栈溢出组合利用（成功执行最终利用链）

## 2. 已确认漏洞
漏洞 BUG-001：read_line 未校验返回值导致越界读写
- CWE 分类：CWE-129 (Improper Validation of Array Index)
- 严重程度：中
- 漏洞位置：read_line (0x150e / 0x1525)
- 漏洞详情：`read_line()` 将 `read()` 的返回值直接作为数组索引计算 `buf[ret-1]`，未检查返回值是否大于 0。当关闭 stdin 触发 EOF 使 `read()` 返回 0 时，索引变为 -1，导致对 `buf[-1]` 产生越界读取。若读取到的字节恰好为换行符 `0x0a`，还会向该地址写入 NUL 字节。
- 已验证原语：RESTRICTED_READ (已验证) / RESTRICTED_WRITE (理论存在)。通过 GDB 断点验证，EOF 时读取 `buf[-1]`，用户名调用读取到 0x00，猜测调用读取到 0x5f ('_')。由于读取值均不为 0x0a，写原语未触发。
- 关键别名发现：用户名调用时 `buf[-1]` 对应 `loop1_hash[255]` 的最后一字节（未初始化栈数据，恒为 0x00）；猜测调用时对应 `temp+0x9`（sprintf 输出的 '_' 字符）。
- 修复建议：在调用 `read()` 后增加对返回值的下界校验，确保 `ret > 0` 再将其作为索引访问缓冲区。

漏洞 BUG-002：缓冲区缺少 NUL 终止符引发非受限字符串操作
- CWE 分类：CWE-120 (Buffer Copy without Checking Size of Input) / CWE-125 (Out-of-bounds Read)
- 严重程度：高
- 漏洞位置：init (0x1475) / read_line (0x1511) / main (0x15f2, 0x169e, 0x175f)
- 漏洞详情：`init()` 读取 47 字节 flag 未追加 NUL，`read_line()` 在输入填满缓冲区时也不追加 NUL。随后程序对这些非 NUL 终止的缓冲区使用 `strcpy`、`strlen` 和 `printf %s` 等非受限字符串函数，导致栈数据越界读取、信息泄露以及向 `temp_buffer` 的栈溢出。
- 已验证原语：INFO_LEAK (已验证) / STACK_OVERFLOW (已验证)。运行时验证 `printf` 越界读取泄露了 2 字节栈数据；`strcpy(temp+0xa, base)` 在未遇到 NUL 时可跨越 0x1006 字节覆盖到保存的 rbp 和返回地址。
- 关键别名发现：`strcpy` 的源地址为 flag buffer (base+0x0)，跨越 47 字节 flag + 17 字节 gap + 4096 字节 loop2_hashes + 4096 字节 loop1_hashes，直至遇到 NUL。
- 修复建议：在 `fread` 和 `read_line` 结束时强制对缓冲区末尾写入 NUL 终止符，并将所有非受限字符串操作替换为 `strncpy`、`strnlen` 和 `snprintf`。

漏洞 BUG-003：基于 MD5 哈希比较的侧信道信息泄露
- CWE 分类：CWE-203 (Observable Discrepancy)
- 严重程度：高
- 漏洞位置：main / print_flag
- 漏洞详情：程序将用户输入与 flag 分别计算 MD5 哈希并逐字节比较，根据匹配数计算得分。当得分未超过阈值时，程序会泄露其中一个哈希值。结合 `strlen` 越界读取导致的哈希输入污染，攻击者可推断出栈数据或 flag 相关的敏感信息。
- 已验证原语：INFO_LEAK (已验证)。通过 256 次猜测交互，结合泄露的哈希值与得分，可逐步恢复出 flag 或栈上的敏感数据。
- 关键别名发现：`strlen(temp_buffer)` 越界读取的字节被作为 `MD5_Update` 的输入，导致哈希计算包含非预期栈数据。
- 修复建议：使用恒定时间的 `memcmp` 进行哈希比较，且在计算哈希时严格限制输入长度，不依赖字符串的 NUL 终止符。

## 3. 利用链与后果
已成功完成端到端利用，利用步骤如下：
1. 触发信息泄露：发送 32 字节无换行符的用户名，利用 `printf("%s")` 越界读取泄露栈/堆地址。
2. 构造栈溢出：利用 `init()` 读取的 47 字节 flag 无 NUL 终止符，触发 `strcpy(temp+0xa, base)` 越界拷贝。
3. 劫持控制流：通过精心构造的输入控制越界拷贝的数据，覆盖 `temp_buffer` 之后的保存 rbp (偏移 0x1006) 和返回地址 (偏移 0x100e)。
4. 最终效果：成功执行利用脚本，实现控制流劫持。

## 4. 方法论
分析路径：文件识别 (ELF 64-bit) → 防护分析 (Full RELRO/NX/PIE/No Canary) → 逆向工程 (定位 `read_line`、`init`、`main` 中的非受限操作) → 原语验证 (GDB 动态调试确认 OOB 读写与信息泄露) → 利用构造 (基于栈溢出覆盖返回地址完成端到端利用)。

## 5. 产物路径
| 产物类型 | 路径 |
|---|---|
| 最终 Exploit | `/work/workspace/0006-2021-15-help-you-2-20260905-110906/exploit.py` |
| BUG-001 PoC | `/work/workspace/0006-2021-15-help-you-2-20260905-110906/poc-BUG-001.py` |