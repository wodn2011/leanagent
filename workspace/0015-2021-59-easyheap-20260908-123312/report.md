# 渗透测试报告：easyheap

## 1. 任务概述
- 目标：对目标堆管理二进制进行漏洞挖掘与利用验证
- 目标文件：`/work/workspace/0015-2021-59-easyheap-20260908-123312/target`
- 文件类型：ELF 64-bit LSB pie executable, x86-64, dynamically linked
- 安全防护：Full RELRO / Canary / NX / PIE / CET (IBT, SHSTK) / GLIBC 2.39
- 分析结果：已验证任意地址读写（基于堆溢出篡改相邻堆块结构体指针）

## 2. 已确认漏洞
漏洞 BUG-001：edit函数整数下溢致堆溢出
- CWE 分类：CWE-191 Integer Underflow
- 严重程度：严重
- 漏洞位置：`edit (0x1520)` / `read_input (0x12ae)`
- 漏洞详情：`edit` 函数在处理 `user->size` 时，使用 `movzx` 读取作为无符号字节并减 1。当 size 为 0 时，减法产生 `0xFFFFFFFF`，截断为单字节 `0xFF` 后再次零扩展为 255。该值作为长度传给 `read_input`，导致向原本仅 1 字节的堆缓冲区写入 255 字节，造成最大 254 字节的堆溢出。
- 已验证原语：
  - RELATIVE_WRITE：通过 `add(size=1)` + 两次 `edit` 触发溢出，写入 255 字节完全可控数据至相邻堆内存。
  - HEAP_OBJECT_CONTROL：溢出数据覆盖相邻 `user1` 结构体，精确篡改 `msg_ptr` (偏移 56) 和 `size` (偏移 40) 字段。
  - ARB_READ：篡改 `msg_ptr` 后调用 `view(1)` 触发 `puts(msg_ptr)`，泄露目标地址数据。
  - ARB_WRITE：篡改 `msg_ptr` 后调用 `edit(1)` 触发 `read(0, msg_ptr, size-1)`，写入目标地址。
- 关键别名发现：`user0_msg_buffer + 32 = user1_struct start`；`overflow[56:64]` 直接别名 `user1->msg_ptr`。
- 修复建议：在 `edit` 函数中执行减法前增加对 `user->size > 0` 的下界检查，并在读取数据时校验长度不超过初始 `calloc` 分配的大小。

漏洞 BUG-002：view函数未截断堆信息泄露
- CWE 分类：CWE-170 Improper Null Termination
- 严重程度：中
- 漏洞位置：`view_message (0x1269)`
- 漏洞详情：`add` 和 `edit` 函数使用 `read()` 填充堆缓冲区，但未在末尾追加空字节。`view_message` 函数直接调用 `puts(user->message)` 输出内容，当缓冲区被非空数据填满时，`puts()` 会越界读取相邻堆内存，直到遇到空字节为止。
- 已验证原语：INFO_LEAK，通过 `add(size=N)` 填满 N 字节非空数据后调用 `view`，`puts` 越界输出相邻堆块数据。
- 关键别名发现：无
- 修复建议：在 `read()` 读取数据后，显式在缓冲区末尾添加空字节终止符，或改用 `write()` 并指定缓冲区实际长度进行输出。

## 3. 利用链与后果
已验证端到端利用成功，最高后果为任意地址读写。利用链步骤如下：
1. `add(size=1)`：分配 1 字节消息缓冲区（user0），`user->size=1`。
2. `add(size=8)`：分配相邻堆块（user1 结构体）。
3. `edit(user0)`：触发 `size-1=0`，读取 0 字节，`user0->size` 递减为 0。
4. `edit(user0)`：触发整数下溢，`size-1=0xFF=255`，读取 255 字节可控数据，覆盖至 `user1` 结构体。
5. 构造溢出数据：在偏移 40 处写入伪造 `size`，偏移 56 处写入目标地址 `Y` 覆盖 `user1->msg_ptr`。
6. `view(user1)`：调用 `puts(user1->msg_ptr)` 即 `puts(Y)`，实现任意地址读。
7. `edit(user1)`：调用 `read(0, user1->msg_ptr, size-1)` 即 `read(0, Y, ...)`，实现任意地址写。

## 4. 方法论
- 文件识别：确认目标为 64 位 ELF 动态链接可执行文件。
- 防护分析：检查 RELRO, NX, Canary, PIE 及 GLIBC 2.39 堆保护机制。
- 逆向分析：反编译 `add/edit/view/remove` 函数，定位 `size` 运算逻辑与指针解引用操作。
- 原语验证：通过动态调试脚本验证堆溢出、结构体字段控制及任意地址读写能力。
- 利用构造：基于验证后的原语组合，编写并执行端到端利用脚本。

## 5. 产物路径
| 产物类型 | 路径 |
| :--- | :--- |
| 最终利用脚本 | `/work/workspace/0015-2021-59-easyheap-20260908-123312/exploit.py` |
| PoC 验证脚本 | `/work/workspace/0015-2021-59-easyheap-20260908-123312/poc-BUG-001.py` |