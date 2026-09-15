---
name: tcache-poisoning
description: UAF→tcache链表伪造→任意地址分配→任意写。通用方法论。
---

# Tcache Poisoning

## 适用条件
- **核心原语**：Heap Object Control（UAF / 堆溢出 / double free）
- **Mitigation**：glibc < 2.32（无 safe-linking）或可绕过
- **典型漏洞**：Use-After-Free / Double Free / 堆溢出

## 核心技术
glibc tcache 是线程本地空闲链表。通过 UAF 修改 freed chunk 的 `fd` 指针，让 tcache 链表指向目标地址。下次 `malloc` 分配到目标地址 → 任意写。

## 关键步骤
1. **获取 UAF**：free 后指针未置空 → 可再次编辑 freed chunk
2. **修改 fd**：edit 已 free chunk → 把 `fd` 改成目标地址
3. **消费链表**：malloc 若干次消耗链表 → 下次 malloc 返回目标地址
4. **写入**：往返回的地址写 payload（如 `system` 地址 → `__free_hook` → free 时执行 system）
5. **触发**：free 一个含 `/bin/sh` 的 chunk → `system("/bin/sh")`

## glibc >= 2.32 safe-linking
- `fd` 被 `chunk_addr >> 12` 异或加密 → 需先泄漏 heap 地址 → `fd = target ^ (chunk_addr >> 12)`

## glibc >= 2.34
- `__free_hook` / `__malloc_hook` 移除 → 换 [[fsop]] 路线

## 常见陷阱：double-free 后 fd 自指循环
**症状**：free 同一 chunk 两次后，tcache 链变成 `head → chunk → chunk → ...`
（fd 自指环）。此时往 chunk 写入目标地址，但后续 malloc 仍返回该 chunk
本身——poisoning 静默失效（head 没指向目标）。

**成因**：第二次 free 时 fd 指向自己（链上唯一元素），链表成环。

**修法（三选一）**：
1. **中间打断**：drop 后先 malloc 一次（弹出该 chunk，断环），再 drop，
   再用 UAF 写 fd = 目标；
2. **隔 chunk double-free**：drop(A); drop(B); drop(A)——链为
   A→B→A 的环，UAF 改 A 的 fd 后逐个弹出即可到目标（2.27 无
   double-free 检查时安全；2.29+ 有 tcache key 检查需绕过）；
3. **换受害 chunk**：free 两个不同 chunk，改第二个的 fd（链首的 fd
   直接指向目标，最简单——优先考虑）。

**自检**：poisoning 后用 gdb 或 oracle 确认 `tcache->entries[idx]`
确实等于目标地址，再继续分配；分配拿到的地址不是目标 = 链上有环
或 fd 写错位置（写入要落在【弹出链首之后】剩余链头的 fd 位置）。

## 关键
- heap 地址泄漏：unsorted bin 的 fd/bk 指向 libc（main_arena）→ 泄漏 libc；tcache 的 fd 不泄密 → 用 unsorted bin 或 UAF 读 freed chunk
- 偏移用 `libc.sym[]` 动态查，不写死

## 参考
[[fsop]]（glibc >= 2.34 无 hook 时）、[[got-overwrite]]（Partial RELRO + arb write 时）
