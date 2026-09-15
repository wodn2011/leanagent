---
name: got-overwrite
description: 任意写→GOT表劫持→调system。Partial RELRO时通用方法论。
---

# GOT Overwrite

## 适用条件
- **核心原语**：Arbitrary Write（任意地址写）
- **Mitigation**：Partial RELRO 或 No RELRO（GOT 可写）
- **典型漏洞**：OOB 写 / 格式化字符串 %n / 堆溢出

## 核心技术
GOT（Global Offset Table）存放动态链接函数的运行时地址。覆写 GOT 条目，让程序调用该函数时跳到攻击者控制地址。

## 关键步骤
1. **确定目标函数**：选一个程序会调用的 libc 函数（如 `puts`/`printf`/`atoi`/`exit`），用 `got_plt` 或 `elf_plt_got(binary, "<func>")` 查 GOT 地址
2. **确定写入值**：
   - 如果已知 libc base：写入 `system` 地址 → 调用时执行 `system(参数)`
   - 如果参数可控（如 `atoi(user_input)`）：覆写 `atoi@GOT` = `system` → `atoi(input)` 变 `system(input)`
3. **触发**：让程序再次调用被覆写的函数

## 关键
- Full RELRO 时 GOT 只读不可写 → 换 [[fsop]] 路线
- GOT 地址用 `elf_plt_got` 或 `got_plt` 动态查，不写死
- 写入值用 `libc.sym['system']` 动态算（需先泄漏 libc base）
- 如果 PIE 开，GOT 地址含 PIE base → 先泄漏 PIE base

## 参考
[[rop-ret2libc]]（栈溢出时可直接 ROP，不需 GOT）、[[fsop]]（Full RELRO 时）、[[format-string]]（%n 写 GOT）
