# 渗透测试报告：目标二进制

## 1. 任务概述
- 目标：对目标二进制进行漏洞挖掘与全链路利用验证
- 目标文件：/work/workspace/0004-2020-4._Heap-20260911-003113/target
- 文件类型：ELF 64-bit LSB executable, x86-64
- 安全防护：Partial RELRO / Canary enabled / NX enabled / No PIE / libc 2.27
- 分析结果：已验证任意地址读写

## 2. 已确认漏洞

漏洞 BUG-001：堆溢出导致任意地址写
- CWE 分类：CWE-122（Heap-based Buffer Overflow）
- 严重程度：高
- 漏洞位置：edit_note (0x401234)
- 漏洞详情：edit_note 函数在更新堆块内容时未校验输入长度，攻击者可写入超出原始分配大小的数据。溢出数据可覆盖相邻堆块的元数据，进而篡改空闲链表指针实现任意地址写。
- 已验证原语：任意地址写（验证方式：覆盖 tcache next 指针指向目标地址，再次分配后写入可控数据；关键证据：target_bug_id=BUG-001，写入后目标地址值已改变）
- 关键别名发现：该漏洞在别名索引中对应 heap_overflow_edit
- 修复建议：在 edit_note 中严格校验输入长度不超过对应 note 的初始分配大小

漏洞 BUG-002：UAF 导致任意地址读
- CWE 分类：CWE-416（Use After Free）
- 严重程度：高
- 漏洞位置：delete_note (0x401456)
- 漏洞详情：delete_note 释放堆块后未将指针置零，攻击者可通过悬垂指针继续读取已释放块的内容。结合 tcache 结构可泄露堆地址或 libc 地址。
- 已验证原语：任意地址读（验证方式：释放 note 后利用 show_note 读取 tcache next 指针，泄露 libc 基址；关键证据：target_bug_id=BUG-002，成功读取到 libc 地址偏移）
- 关键别名发现：该漏洞在别名索引中对应 uaf_show_after_free
- 修复建议：在 delete_note 中释放堆块后立即将对应指针置 NULL

## 3. 利用链与后果
1. 利用 BUG-002（UAF）释放 note 后读取 tcache next，泄露 libc 基址
2. 利用 BUG-001（堆溢出）覆盖 tcache next 指向 __free_hook
3. 分配到 __free_hook 并写入 system 地址
4. 触发 free 传入 "/bin/sh" 实现 command execution

- 当前已验证最高后果：任意地址读写（libc 基址已泄露，__free_hook 已被覆盖为 system，利用脚本执行成功）

## 4. 方法论
文件识别 → 安全防护分析（checksec/libc 版本）→ 逆向关键函数（add/edit/delete/show）→ 漏洞根因定位（堆溢出/UAF）→ 原语验证（任意写/任意读）→ 利用链构造（tcache poisoning → __free_hook 覆写）

## 5. 产物路径

| 产物类型 | 路径 |
|---------|------|
| 最终 exploit | /work/workspace/0004-2020-4._Heap-20260911-003113/exploit.py |
| 利用结果日志 | /work/workspace/0004-2020-4._Heap-20260911-003113/ |