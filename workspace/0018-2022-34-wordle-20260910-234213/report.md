# 渗透测试报告：0018-2022-34-wordle

## 1. 任务概述
- 目标：对 Wordle 游戏二进制文件进行全链路漏洞挖掘与渗透测试
- 目标文件：`/work/workspace/0018-2022-34-wordle-20260910-234213/target`
- 文件类型：ELF 64-bit LSB PIE executable, x86-64, dynamically linked, not stripped
- 安全防护：Full RELRO / Canary / NX / PIE / CET(IBT+SHSTK) / GLIBC 2.39
- 分析结果：拒绝服务（DoS）/ 无害的越界读写（已验证原语无法提权为任意代码执行或信息泄露）

## 2. 已确认漏洞

漏洞 BUG-001：SIZE_ZERO_INTEGER_UNDERFLOW_OOB_WRITE
- CWE 分类：CWE-191（Integer Underflow）
- 严重程度：低
- 漏洞位置：importWords (0x229c)
- 漏洞详情：`importWords` 函数中通过 `scanf("%lu")` 读取用户输入的 `size`，未检查下界。当 `size=0` 时，执行 `buffer[size-1]=0` 触发无符号整数下溢，计算出目标地址为 `buffer + 0xFFFFFFFFFFFFFFFF`（即 `buffer-1`），导致向堆块元数据的最高字节写入单字节 NULL。
- 已验证原语：受限写（RESTRICTED_WRITE）。GDB 动态验证确认在 0x229c 处向 `buffer-1`（堆块 size 字段 MSB）写入了 0x00。但由于 glibc 实际分配的 chunk size 极小，该字节原本即为 0x00，写入操作为无副作用空操作。
- 关键别名发现：`buffer-1` 实际指向 malloc chunk header 的 size 字段第 7 字节（MSB）。
- 修复建议：在执行 `buffer[size-1] = 0` 之前增加对 `size` 的下界校验（如 `if (size == 0) return;`）。

漏洞 BUG-002：INPUTGUESS_READ_RETURN_ZERO_OOB_ACCESS
- CWE 分类：CWE-787（Out-of-bounds Write）/ CWE-125（Out-of-bounds Read）
- 严重程度：低
- 漏洞位置：inputGuess (0x1ce4)
- 漏洞详情：`inputGuess` 函数中调用 `read(0, buf, 6)` 后，仅检查返回值是否为 -1，未处理返回 0（EOF）的情况。当返回 0 时，去换行符逻辑计算索引 `0-1=-1`，经符号扩展后访问 `buf[-1]`，导致栈上越界读写 1 字节。
- 已验证原语：相对读/写（RELATIVE_READ/WRITE）。静态分析确认会读取 `rbp-0xf` 处 1 字节，若该字节恰好为 0x0a 则写入 0x00。该越界发生在栈 padding 区，距离 Canary 7 字节，无法造成信息泄露或破坏控制流。
- 关键别名发现：`buf[-1]` 指向栈帧 `rbp-0xf`，位于返回值变量与缓冲区之间的对齐填充区。
- 修复建议：全面检查 `read` 函数返回值，若 `<= 0` 则直接返回或要求重试，禁止利用返回值计算数组索引。

漏洞 BUG-003：ADDWORDSTOLIST_REALLOC_FAILURE_NULL_DEREF
- CWE 分类：CWE-476（NULL Pointer Dereference）
- 严重程度：低
- 漏洞位置：addWordsToList
- 漏洞详情：`addWordsToList` 中调用 `realloc` 扩展词表，未检查返回值是否为 NULL。若 `realloc` 失败返回 NULL，后续代码直接解引用该空指针加上偏移进行写入，导致程序崩溃。
- 已验证原语：崩溃（CRASH / DoS）。验证表明 `realloc` 失败时，写入目标为 `NULL + (word_count*8 - 8)`，必定触发 SIGSEGV，仅能造成拒绝服务，无法转化为任意写。
- 关键别名发现：无
- 修复建议：检查 `realloc` 返回值，若为 NULL 则处理错误并释放原指针，避免解引用空指针。

## 3. 利用链与后果
- 当前状态：未完成端到端利用。
- 最高后果评估：拒绝服务（DoS）。三个已验证漏洞均无法升级为任意代码执行：
  1. BUG-001 的越界写固定写入 0x00 到堆块 size 字段 MSB，由于实际 size 极小该字节恒为 0，写操作为无副作用空操作；伴随的 `strtok` 越界读数据被 `isAllAlpha` 过滤，无法输出给攻击者。
  2. BUG-002 的栈越界读写仅限 1 字节且位于无意义 padding 区，无法触及 Canary 或返回地址。
  3. BUG-003 仅引发空指针解引用崩溃。
- 当前卡点：系统开启 Full RELRO 阻止 GOT 覆写，glibc 2.39 移除了 `__free_hook`，NX 阻止 shellcode，PIE+ASLR 需要信息泄露（当前原语均无法泄露），Canary 保护返回地址，CET 保障控制流完整性。所有标准利用路径均被阻断。

## 4. 方法论
- 文件识别：通过 file 指令与 ELF 头解析确认架构与动态链接属性。
- 防护分析：使用安全防护检查工具确认 RELRO, NX, Canary, PIE, CET 状态及 glibc 版本。
- 逆向分析：定位 `importWords`, `inputGuess`, `addWordsToList` 等关键函数，分析输入数据流与边界检查缺失。
- 原语验证：编写 PoC 触发 `size=0` 及 `read` EOF 路径，结合 GDB 断点确认越界读写地址及实际写入值，评估原语真实破坏力。
- 利用构造：尝试组合原语进行堆破坏或栈控制，因防护严密及原语本身能力受限，确认无法构造稳定利用链。

## 5. 产物路径
| 产物类型 | 路径 |
| :--- | :--- |
| PoC (BUG-001) | `/work/workspace/0018-2022-34-wordle-20260910-234213/poc-BUG-001.py` |
| 最终利用脚本 | 无（未实现稳定利用） |