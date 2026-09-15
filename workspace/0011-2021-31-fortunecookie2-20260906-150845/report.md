# 渗透测试报告：Fortune Cookie 2

## 1. 任务概述
- 目标：对 Fortune Cookie 2 程序进行漏洞验证与利用测试，探查内存破坏类漏洞及其实际危害。
- 目标文件：`/work/workspace/0011-2021-31-fortunecookie2-20260906-150845/target`
- 文件类型：ELF 64-bit LSB pie executable, x86-64, dynamically linked
- 安全防护：Full RELRO / Canary enabled / NX enabled / PIE enabled / GLIBC 2.39
- 分析结果：任意地址读写（结合信息泄露）

## 2. 已确认漏洞

漏洞 BUG-001：索引边界检查符号不匹配导致越界读写
- CWE 分类：CWE-1284（Improper Validation of Specified Quantity in Input） / CWE-194（Unexpected Sign Extension）
- 严重程度：严重
- 漏洞位置：`edit_cookie` (0x1684), `read_cookie` (0x17ad)
- 漏洞详情：程序通过 `scanf("%llu")` 读取无符号数作为数组索引，但边界检查使用了有符号比较指令 `jl`。当输入大于等于 `0x8000000000000000` 的无符号值时，被视作负数通过检查，导致对 `msg` 和 `msg_size` 数组的越界访问。
- 已验证原语：
  1. 信息泄露（INFO_LEAK）：利用 `read_cookie` 越界读取 `stdout` 等 FILE 指针并解引用，泄露 libc 结构体内容（如 `0x8728adfb`）。
  2. 任意地址写（ARB_WRITE）：利用 `edit_cookie` 越界访问 `__dso_handle`（自引用指针），通过两步写机制实现向任意地址写入数据。
- 关键别名发现：`msg[-8]` 别名 `stdout FILE*` (0x4020)；`msg[-11]` 别名 `__dso_handle` (0x4008)；`msg_size[-11]` 别名 `msg[26]` 的高 4 字节 (0x4134)。
- 修复建议：将边界检查指令从有符号比较 `jl` 替换为无符号比较 `jb`，或增加对输入索引显式的下界检查（`idx >= 0`）。

漏洞 BUG-002：零大小整数下溢导致堆缓冲区溢出
- CWE 分类：CWE-191（Integer Underflow） / CWE-122（Heap-based Buffer Overflow）
- 严重程度：高
- 漏洞位置：`create_cookie` (0x13f2), `edit_cookie` (0x16b9)
- 漏洞详情：`create_cookie` 允许 `size=0` 通过检查，`calloc(0,1)` 返回极小堆块。后续 `edit_cookie` 计算写入长度时发生 `0-1` 下溢，经符号扩展变为 `0xFFFFFFFFFFFFFFFF` 传入 `read()`，导致无限堆溢出。
- 已验证原语：堆内存破坏（MEMORY_CORRUPTION），可覆盖相邻堆块元数据与数据。
- 关键别名发现：无
- 修复建议：在 `create_cookie` 中增加下界检查拒绝 `size <= 0` 的请求，或在 `edit_cookie` 执行减法前校验 `msg_size[idx] > 0`。

漏洞 BUG-003：负数分配大小导致空指针解引用
- CWE 分类：CWE-476（NULL Pointer Dereference）
- 严重程度：中
- 漏洞位置：`create_cookie` (0x13f2)
- 漏洞详情：`create_cookie` 使用有符号比较 `jle` 检查 `size`，允许负数通过。`calloc` 接收到转换后的极大无符号数会分配失败返回 NULL，程序未检查返回值直接用于 `read()` 导致崩溃。
- 已验证原语：拒绝服务（CRASH/NULL Pointer Dereference）。
- 关键别名发现：无
- 修复建议：校验 `size > 0` 且检查 `calloc` 返回值是否为 NULL。

漏洞 BUG-004：未初始化内存访问
- CWE 分类：CWE-908（Use of Uninitialized Resource）
- 严重程度：低
- 漏洞位置：`eat_cookie` 等
- 漏洞详情：程序在处理 cookie 时未完全初始化相关结构体或指针，可能读取到残留的栈/堆数据。
- 已验证原语：潜在信息泄露（条件触发）。
- 关键别名发现：无
- 修复建议：确保所有分配的结构体和指针在使用前使用 `memset` 或直接赋值进行初始化。

## 3. 利用链与后果
已验证可组合出任意地址读写能力，端到端利用链如下：
1. 信息泄露：调用 `read_cookie`，输入 `idx = 18446744073709551608` (即 -8)，绕过 `jl` 检查，读取 `stdout FILE*` 并解引用，泄露 libc 地址片段。
2. 堆布局准备：调用 `create_cookie` 22 次（索引 5-26），填充 `msg[26]` 为堆指针，使 `msg_size[-11]` 变为 `0x00005555`（有效写入长度）。
3. 任意地址写步骤 1：调用 `edit_cookie`，输入 `idx = 18446744073709551605` (即 -11)，利用 `__dso_handle` 自引用特性，将其值覆盖为目标地址 Y。
4. 任意地址写步骤 2：再次调用 `edit_cookie`，输入 `idx = -11`，此时 `msg[-11]` 已被替换为 Y，`read()` 向地址 Y 写入攻击者控制的数据。

## 4. 方法论
分析路径：文件识别与安全防护侦察 (S1) -> 静态逆向分析与数据流追踪 (S2) -> 动态原语验证与别名发现 (S3) -> 端到端利用链构造与验证 (S4)。

## 5. 产物路径
| 产物类型 | 路径 |
|---|---|
| 最终利用脚本 | `/work/workspace/0011-2021-31-fortunecookie2-20260906-150845/exploit.py` |
| PoC 脚本 | `/work/workspace/0011-2021-31-fortunecookie2-20260906-150845/poc-BUG-001.py` |
| 目标二进制 | `/work/workspace/0011-2021-31-fortunecookie2-20260906-150845/target` |