# 渗透测试报告：zoo

## 1. 任务概述
- 目标：对 zoo 动物管理程序进行漏洞挖掘与利用验证
- 目标文件：`/work/workspace/0019-2022-35-uaf-20260908-191003/target`
- 文件类型：ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
- 安全防护：Partial RELRO / Canary enabled / NX enabled / No PIE / IBT & SHSTK 标记但运行时未强制启用 / libc 2.39
- 分析结果：任意代码执行（已验证通过控制间接调用指针劫持执行流）

## 2. 已确认漏洞
漏洞 BUG-001：堆释放后重用导致控制流劫持
- CWE 分类：CWE-416（Use After Free）
- 严重程度：严重
- 漏洞位置：`remove_animal` (0x40175c-0x40177c), `report_name` (0x4018bf)
- 漏洞详情：`remove_animal` 释放 animal 结构体后未将 `zoo[idx]` 置空，留下悬垂指针。`report_name` 仅检查该指针非空便解引用，从已释放内存加载函数指针（+0x00）和名称指针（+0x10）并执行间接调用。攻击者可通过 tcache 填充技术使新分配的 name buffer 复用已释放结构体内存，从而控制间接调用目标。
- 已验证原语：HEAP_OBJECT_CONTROL + FUNCTION_POINTER_CONTROL（动态验证：gdb 断点 0x4018bf 处 rdx=0x4141414141414141，rip 停于 call rdx，进程 SIGSEGV 返回码 -11）
- 关键别名发现：tcache_0x20 填满 7 项后第 8 次 free 溢出至 fastbin，打破 struct/name LIFO 配对；name_buffer_addr == struct_2_addr，攻击者 read() 输入直接覆盖 struct_2+0x00 函数指针
- 修复建议：在 `remove_animal` 中 free 后立即执行 `zoo[idx] = NULL`，并在 `report_name` 中增加结构体生命周期校验

漏洞 BUG-002：悬垂名称指针导致信息泄露
- CWE 分类：CWE-416（Use After Free）
- 严重程度：中
- 漏洞位置：`report_name` (0x4018bf) → `print` (0x4012c5)
- 漏洞详情：同一 UAF 根因下，若结构体内存尚未被复用，函数指针仍指向 `speak`，`report_name` 会以结构体+0x10 处的名称指针调用 `printf(': %s\n', name_ptr)`。该名称指针指向已释放的 name buffer，printf 将读取并打印释放后堆内存内容直至遇到空字节，造成信息泄露。
- 已验证原语：INFO_LEAK（静态推导：printf %s 解引用 freed name_ptr，读取已释放堆内存作为字符串输出）
- 关键别名发现：struct+0x10 name_ptr 字段在 free 后成为 stale pointer，仍被 printf 作为 %s 参数解引用
- 修复建议：释放结构体后置空所有内部指针字段，并在使用前验证 name buffer 指针指向有效存活分配

## 3. 利用链与后果
已验证端到端利用链（最终利用成功）：
1. add_animal ×4（zone 0-3, name_length=24）— 分配 4 个 struct + 4 个 name buffer
2. remove_animal ×4（zone 0-3）— 8 次 free 填满 tcache_0x20（7 项），第 8 项溢出至 fastbin，打破 LIFO 配对
3. add_animal（zone 4, name_length=24, payload=伪造 struct: +0x00=目标地址, +0x10=可控参数）— name buffer 分配落在 struct_2 内存上
4. report_name（zone 2）— 悬垂指针 zoo[2] 解引用攻击者控制的 struct_2，call rdx 执行攻击者指定地址

关键偏移：struct+0x00 = 函数指针（8 字节），struct+0x10 = 名称指针/rdi 参数（8 字节），struct 大小 0x18（tcache bin 0x20）

最终后果：任意代码执行（exploit.py 运行成功，status: ok）

## 4. 方法论
文件识别（file/readelf）→ 安全防护分析（checksec + ELF 标记）→ 逆向工程（函数接口、全局变量、GOT/PLT 映射）→ 漏洞根因分析（remove_animal 缺失置空、report_name 仅 NULL 检查）→ 原语验证（tcache 填充 UAF 链动态调试，gdb 确认 rdx/rdi 寄存器受控）→ 利用构造（No PIE 下固定地址直接劫持间接调用）

## 5. 产物路径
| 产物类型 | 路径 |
|---------|------|
| 最终 exploit | `/work/workspace/0019-2022-35-uaf-20260908-191003/exploit.py` |
| BUG-001 PoC | `/work/workspace/0019-2022-35-uaf-20260908-191003/poc-BUG-001.py` |
| 目标二进制 | `/work/workspace/0019-2022-35-uaf-20260908-191003/target` |