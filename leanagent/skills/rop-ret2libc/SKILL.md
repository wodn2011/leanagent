---
name: rop-ret2libc
description: 栈溢出→RIP Control→ROP链/ret2libc/SROP拿shell。通用方法论。
---

# ROP / ret2libc / SROP

## 适用条件
- **核心原语**：RIP Control（栈溢出覆盖返回地址）
- **Mitigation**：NX 开（不能直接执行 shellcode）；Canary 未开或可绕过
- **典型漏洞**：栈缓冲区溢出（gets/scanf/read 无长度限制）

## 核心技术
通过覆盖返回地址，复用二进制/libc 中已有的代码片段（gadget），拼接成 ROP 链实现任意操作。

### ret2libc（最简）
1. 泄漏 libc 基址（如 `puts(puts@GOT)` → 算 libc base = leaked - libc.sym['puts']）
2. 构造链：`pop rdi; ret` + `/bin/sh` 地址 + `system()`
3. 注意栈 16 字节对齐（movaps 要求）——加一个 `ret` gadget 对齐

### ROP（完整链）
1. 用 `find_offset` 或 cyclic 找溢出偏移
2. `search_rop_gadgets` 搜 gadget（pop rdi / pop rsi / pop rdx / syscall / ret）
3. 拼接链实现 `execve("/bin/sh", 0, 0)` 或 `mprotect + shellcode`

### SROP（Sigreturn）
1. 覆盖返回地址为 `__restore_rt` gadget
2. 栈上伪造 `sigcontext` 结构（设置所有寄存器 + rip 指向 syscall）
3. 一次 sigreturn 直接控制所有寄存器 → 执行 `execve`

## 关键
- 栈对齐：x86_64 的 `movaps` 要求 RSP % 16 == 0，加 `ret` gadget 对齐
- 泄漏 libc：如果 PIE 开，先泄漏 PIE base（相邻全局指针）再泄漏 libc
- gadget 地址用 `search_rop_gadgets` 动态查，不写死

## 参考
[[got-overwrite]]（Partial RELRO 时可劫持 GOT 替代栈攻击）、[[fsop]]（Full RELRO + arb write 时）
