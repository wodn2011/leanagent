# 渗透测试报告：0003-2020-3. Babyheap

## 1. 任务概述
- 目标：针对目标二进制文件进行全链路漏洞挖掘与利用分析
- 目标文件：`/work/workspace/0003-2020-3._Babyheap-20260904-235752/target`
- 文件类型：ELF 64-bit LSB pie executable, x86-64, dynamically linked
- 安全防护：Full RELRO / Canary / NX / PIE / glibc 2.27 (无 tcache double-free 检测)
- 分析结果：已验证任意地址读与堆元数据控制

## 2. 已确认漏洞
漏洞 BUG-001：堆释放后使用与双重释放
- CWE 分类：CWE-416 (Use After Free) / CWE-415 (Double Free)
- 严重程度：高
- 漏洞位置：`drop_note (0x1380)` / `view_note (0x1444)`
- 漏洞详情：`drop_note` 在释放数据块和结构体头后，仅清空了局部栈变量 `[rbp-0x10]`，未将全局指针数组 `note_list[index]` 置空，且未递减计数器 `idx`。攻击者可对同一索引重复调用释放操作，在无 tcache 双重释放检测的 glibc 2.27 环境下成功破坏堆元数据，并通过 `view_note` 触发 UAF 读取。
- 已验证原语：
  1. 堆元数据控制 (PRIM-001)：双重释放导致 tcache 0x20 bin 形成环状链表 (b260->b280->b260)，tcache count 异常增至 4。
  2. 任意地址读 (PRIM-002)：利用 tcache 自循环使结构体头与数据块重叠，通过 `read_input` 覆盖 `data_ptr`，使 `view_note` 调用 `secure_print` 读取攻击者指定地址 (如 0x555555556041 和 0x555555556050)。
  3. 相对地址读 (PRIM-003)：UAF 类型混淆，`note_list[0]` 与 `note_list[1]` 指向同一结构体头，通过 `view_note(0)` 读取 note 1 的数据。
- 关键别名发现：双重释放后 `malloc(0x10)` 返回同一地址 (b260)，导致 `[b260+0x0]` (size) 与 `[b260+0x8]` (data_ptr) 别名于数据块的前 16 字节。
- 修复建议：在 `drop_note` 执行 `free()` 后，必须将 `note_list[index]` 置为 NULL，并递减 `idx`；在调用 `free()` 前应检查指针是否为 NULL。

漏洞 BUG-002：read 函数返回值未检查
- CWE 分类：CWE-252 (Unchecked Return Value)
- 严重程度：低
- 漏洞位置：`read_input`
- 漏洞详情：`read_input` 调用 `read(0, buf+i, 1)` 后未检查返回值。若 `read` 返回 0 或 -1，程序会继续处理 `buf[i]` 中的残留或未初始化数据。在 UAF 场景下，这可能将残留的堆数据误作用户输入处理，导致逻辑异常。
- 已验证原语：未直接验证产生独立原语，作为 BUG-001 利用链中的辅助条件（允许包含 `\x00` 的 payload 完整写入）。
- 关键别名发现：无
- 修复建议：检查 `read()` 的返回值，若返回值 <= 0 则应终止输入循环并作错误处理。

## 3. 利用链与后果
已验证原语可组合出任意地址读与堆元数据控制，当前未拔高至代码执行。利用链步骤如下：
1. `create_note(0x10)` 分配 note 0 (结构体头 b260 + 数据块 b280)。
2. `drop_note(0)` 释放两块，因未清空 `note_list[0]` 且未递减 `idx`，产生悬挂指针。
3. `drop_note(0)` 再次释放，触发 tcache 双重释放，0x20 bin 形成循环 (b260->b280->b260)。
4. `create_note(0x10)` 分配 note 1，`malloc(0x10)` 两次均返回 b260 (结构体头与数据块重叠)。
5. `read_input` 向 b260 写入 `p64(0x100) + p64(target_addr)`，控制 note 0 的 `size` 和 `data_ptr`。
6. `view_note(0)` 通过悬挂指针读取被篡改的结构体头，调用 `secure_print(target_addr, length)` 实现任意地址读。

## 4. 方法论
分析路径：文件识别与安全防护分析 (S1) -> 逆向工程与漏洞根因定位 (S2) -> 动态调试与原语验证 (S3) -> 利用链构造与验证 (S4)。通过静态分析定位 `drop_note` 中清空局部变量而非全局指针的逻辑缺陷，结合 glibc 2.27 tcache 无双重释放检测的特性，动态验证了 tcache 破坏与任意地址读原语，最终完成利用链构造。

## 5. 产物路径
| 产物类型 | 路径 |
|---|---|
| 最终利用脚本 | `/work/workspace/0003-2020-3._Babyheap-20260904-235752/exploit.py` |
| PoC 脚本 | `/work/workspace/0003-2020-3._Babyheap-20260904-235752/poc-BUG-001.py` |
| 任意地址读 Payload 1 | `/work/workspace/0003-2020-3._Babyheap-20260904-235752/payload_arbread.bin` |
| 任意地址读 Payload 2 | `/work/workspace/0003-2020-3._Babyheap-20260904-235752/payload_arbread2.bin` |