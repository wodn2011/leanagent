# 渗透测试报告：fortunecookie1

## 1. 任务概述
- 目标：对 fortunecookie1 二进制进行全链路渗透测试，验证漏洞原语并完成端到端利用。
- 目标文件：`/work/workspace/0010-2021-30-fortunecookie1-20260905-194852/target`
- 文件类型：ELF 64-bit LSB shared object (DYN/PIE), x86-64, dynamically linked, not stripped
- 安全防护：Full RELRO / Canary / NX / PIE / GLIBC 2.39
- 分析结果：任意地址写（结合信息泄露已验证端到端利用成功）

## 2. 已确认漏洞

漏洞 BUG-001：OOB 索引符号性校验错误
- CWE 分类：CWE-194（Unexpected Sign Extension to Unsigned Width）/ CWE-129（Improper Validation of Array Index）
- 严重程度：严重
- 漏洞位置：`edit_cookie` (0x1684) / `read_cookie` (0x17ad)
- 漏洞详情：`edit_cookie` 和 `read_cookie` 通过 `scanf("%llu")` 读取无符号 64 位索引，但边界检查使用有符号 `jl` 指令与 `cookie_num` 比较。攻击者传入大无符号数（如 `0xFFFFFFFFFFFFFFFF`，有符号为 -1）可通过检查，导致对 `msg[]` 和 `msg_size[]` 数组进行越界读写，访问低地址处的 `stdout/stdin/stderr` 等 FILE 指针及 `__dso_handle`。
- 已验证原语：
  1. **信息泄露 (PRIM-001, VERIFIED)**：`read_cookie` 使用越界索引 -8 读取 `msg[-8]` 获取 `stdout` FILE 指针，`printf` 打印 FILE 结构内容，泄露 libc 地址；索引 -11 读取 `__dso_handle` 自引用指针，泄露 PIE 基地址。
  2. **相对写 (PRIM-002, CANDIDATE/Dead End)**：`edit_cookie` 使用索引 -8 尝试写 `stdout` 结构，但 `msg_size[-8]=0` 导致长度为 `0xFFFFFFFFFFFFFFFF`，触发 EFAULT 失败。
  3. **任意地址写 (PRIM-003, VERIFIED)**：利用索引 -11 两步写入。第一步写入目标地址 Y 到 `__dso_handle`；第二步 `msg[-11]` 变为 Y，实现向任意地址 Y 写入数据。
- 关键别名发现：`msg[-8]` 别名 `stdout` FILE* (0x4020)；`msg[-11]` 别名 `__dso_handle` 自引用指针 (0x4008)；`msg_size[-11]` 别名 `msg[26]` 高 4 字节（堆指针，值为 0x00005555，提供有效写入长度 0x5554）。
- 修复建议：将边界检查中的 `jl`（有符号小于跳转）替换为 `jb`（无符号低于跳转），并显式增加下界检查（`index >= 0`）。

漏洞 BUG-002：Create Cookie 负长度空指针解理
- CWE 分类：CWE-194（Unexpected Sign Extension to Unsigned Width）/ CWE-476（NULL Pointer Dereference）
- 严重程度：低
- 漏洞位置：`create_cookie` (0x13f6)
- 漏洞详情：`create_cookie` 使用 `scanf("%lld")` 读取有符号长度，检查使用 `jle`（有符号小于等于）。传入负数（如 -1）通过检查后被隐式转换为无符号传给 `calloc`，导致分配失败返回 NULL。后续 `buf[read_return_value]` 解引用空指针造成 SIGSEGV 崩溃。
- 已验证原语：**拒绝服务 (NULL Pointer Dereference, VERIFIED)**：传入长度 -1，`calloc(0xFFFFFFFFFFFFFFFF, 1)` 返回 NULL，`read` 后解引用 `NULL + retval` 导致程序崩溃。
- 关键别名发现：无
- 修复建议：在 `jle` 检查前显式增加下界校验（`length > 0`），或使用无符号比较指令。

漏洞 BUG-003：Eat Cookie 堆 UAF
- CWE 分类：CWE-416（Use After Free）
- 严重程度：中
- 漏洞位置：`eat_cookie`
- 漏洞详情：`eat_cookie` 释放 `msg[index]` 堆块后未将指针置零。若后续 `edit_cookie` 或 `read_cookie` 再次访问该索引，会导致 UAF。
- 已验证原语：**释放后重用 (VERIFIED)**：释放后的堆指针仍保留在 `msg[]` 数组中，可被后续操作重复访问。
- 关键别名发现：无
- 修复建议：在 `free(msg[index])` 之后立即添加 `msg[index] = NULL` 和 `msg_size[index] = 0`。

## 3. 利用链与后果
已验证端到端利用成功，步骤如下：
1. **泄露 PIE 基地址**：调用 `read_cookie`，输入索引 -11 (`0xFFFFFFFFFFFFFFF5`)，读取 `__dso_handle` 自引用指针，泄露 PIE 基地址。
2. **泄露 libc 基地址**：调用 `read_cookie`，输入索引 -8 (`0xFFFFFFFFFFFFFFF8`)，读取 `stdout` FILE 指针，泄露 libc 地址。
3. **填充 msg[26]**：调用 `create_cookie` 22 次（索引 5-26），使 `msg[26]` 包含堆指针，确保 `msg_size[-11]` 提供有效长度 0x5554。
4. **覆写 __dso_handle**：调用 `edit_cookie`，输入索引 -11，发送 8 字节目标地址 Y，将 `__dso_handle` 的值覆写为 Y。
5. **向 Y 写入数据**：再次调用 `edit_cookie`，输入索引 -11，此时 `msg[-11]` 已变为 Y，发送数据写入 Y 地址，实现任意地址写。

## 4. 方法论
分析路径：文件识别 (S1 侦察) → 防护分析 → 逆向工程 → 原语验证 (S3 动态调试) → 利用构造 (S4 端到端验证)

## 5. 产物路径
| 产物类型 | 路径 |
|---|---|
| 目标二进制 | `/work/workspace/0010-2021-30-fortunecookie1-20260905-194852/target` |
| BUG-001 PoC | `/work/workspace/0010-2021-30-fortunecookie1-20260905-194852/poc-BUG-001.py` |
| 最终利用脚本 | `/work/workspace/0010-2021-30-fortunecookie1-20260905-194852/exploit.py` |