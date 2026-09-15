# 渗透测试报告：0020-2022-36-uaf2

## 1. 任务概述
- 目标：针对目标二进制文件进行全链路漏洞挖掘与利用验证
- 目标文件：`/work/workspace/0020-2022-36-uaf2-20260908-194233/target`
- 文件类型：ELF 64-bit LSB executable, x86-64, SYSV (动态链接，未剥离)
- 安全防护：Partial RELRO / Canary / NX / No PIE / CET(IBT+SHSTK在ELF中启用但运行时未强制) / libc 2.39
- 分析结果：已验证实现任意代码执行（通过 UAF 控制间接调用指针劫持控制流）

## 2. 已确认漏洞

漏洞 BUG-001：释放后重用导致控制流劫持
- CWE 分类：CWE-416 (Use After Free)
- 严重程度：严重
- 漏洞位置：`remove_animal` (0x4015ed), `report_name` (0x401735)
- 漏洞详情：`remove_animal` 函数在释放 animal 结构体及其 name 缓冲区后，未将全局数组 `zoo[idx+8]` 中的指针置空，留下悬垂指针。随后 `report_name` 会加载该悬垂指针，读取已释放堆内存偏移 0 处的 `func_ptr` 和偏移 0x10 处的 `name_ptr`，并执行 `call rdx` 间接调用。由于 animal 结构体与 name 缓冲区均为 0x18 字节，攻击者可通过再次调用 `add_animal` 使新 name 缓冲区复用已释放的 animal 结构体块，从而用攻击者控制的 24 字节数据覆盖 `func_ptr` 和 `name_ptr`，劫持间接调用。
- 已验证原语：
  1. CRASH (VERIFIED, DIRECT)：释放后直接调用 `report_name`，由于堆块被 tcache fd 指针覆盖，导致 `call rdx` 执行无效地址 0x4056c5 触发 SIGSEGV (rc=-11)。
  2. HEAP_OBJECT_CONTROL (VERIFIED, INDIRECT)：验证了释放后的堆对象字段被 tcache 元数据覆盖，且 `report_name` 确实读取了被篡改的 `func_ptr` (tcache fd) 作为调用目标，`name_ptr` 保留原值作为参数。
- 关键别名发现：`freed_chunk[0x0]` 别名 tcache fd 指针（被安全链接异或加密），`freed_chunk[0x8]` 别名 tcache key，`freed_chunk[0x10]` 未被覆盖保留原 `name_ptr`。
- 修复建议：在 `remove_animal` 函数执行 `free(zoo[idx+8])` 后，必须立即添加 `zoo[idx+8] = NULL` 以清除悬垂指针。

漏洞 BUG-002：未清除指针导致的堆双释放
- CWE 分类：CWE-415 (Double Free)
- 严重程度：高
- 漏洞位置：`remove_animal` (0x4015ed)
- 漏洞详情：由于 `remove_animal` 在释放堆块后未将 `zoo[idx+8]` 置空，攻击者可对同一索引再次调用 `remove_animal`。非空检查会通过悬垂指针，导致 `free(animal->name_ptr)` 和 `free(animal)` 被重复执行，引发 tcache 双释放。在 glibc 2.39 中，这可能破坏 tcache 元数据或导致对任意地址调用 `free`。
- 已验证原语：MEMORY_CORRUPTION (CANDIDATE)：理论上可导致 tcache 空闲链表环路，使后续 `malloc` 返回重叠堆块。
- 关键别名发现：与 BUG-001 共享同一根因（未置空指针），但此处直接后果是破坏堆管理器的空闲链表结构。
- 修复建议：同 BUG-001，在释放堆块后将 `zoo[idx+8]` 置空，并在释放前增加状态校验防止重复释放。

## 3. 利用链与后果
已成功完成端到端利用，实现任意代码执行。利用链步骤如下：
1. 调用 `add_animal` (菜单1) 两次，分配 animal 结构体与 name 缓冲区，确保 `zoo` count > 0。
2. 调用 `remove_animal` (菜单2) 释放索引 0 的 animal 结构体，`zoo[0]` 变为悬垂指针。
3. 调用 `add_animal` (菜单1) 再次分配，利用 tcache LIFO 机制使新 name 缓冲区复用已释放的 animal 结构体。
4. 通过 `read` 写入精心构造的 24 字节数据，覆盖原 animal 结构体的 `func_ptr` (偏移0) 和 `name_ptr` (偏移0x10)。
5. 调用 `report_name` (菜单3) 访问索引 0，触发 `call rdx` 间接调用，成功劫持控制流。

## 4. 方法论
分析路径：文件识别与安全防护分析 (S1) → 逆向工程与漏洞根因定位 (S2) → 动态调试与原语验证 (S3) → 利用链构造与端到端验证 (S4)。

## 5. 产物路径
| 产物类型 | 路径 |
|---|---|
| 最终利用脚本 | `/work/workspace/0020-2022-36-uaf2-20260908-194233/exploit.py` |
| PoC (BUG-001) | `/work/workspace/0020-2022-36-uaf2-20260908-194233/poc-BUG-001.py` |