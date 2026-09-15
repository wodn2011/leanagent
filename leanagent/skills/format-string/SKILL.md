---
name: format-string
description: 格式化字符串漏洞→Arbitrary Read(%p/%s)+Arbitrary Write(%n)。通用方法论。
---

# Format String Attack

## 适用条件
- **核心原语**：Arbitrary Read（任意读）+ Arbitrary Write（任意写）
- **漏洞类型**：格式化字符串漏洞（printf(user_input)）
- **Mitigation**：无特殊要求（FORTIFY 可限制 %n）
- **典型漏洞**：printf/fprintf 直接用用户输入做格式串

## 核心技术
printf 的格式 specifier 提供读/写原语：
- `%p`/`%s` → **Arbitrary Read**（读栈/内存数据 → 泄漏地址）
- `%n`/`%hn`/`%hhn` → **Arbitrary Write**（栈上指针 → 目标地址，写入已打印字符数）

## 关键步骤
1. **确定偏移**：输入 `%p.%p.%p...` 找到用户输入在栈上的位置（第 N 个参数）
2. **泄漏**：
   - `%N$p` → 读第 N 个栈参数（泄露栈/libc/PIE 地址）
   - `%N$s` → 读第 N 个栈参数指向的字符串（泄露 GOT 内容 → libc 地址）
3. **写入**（%n）：
   - 栈上放目标地址 → `%N$n`/`%N$hn`/`%N$hhn` 写入目标
   - 精确控制写入值：用 `%Nc`（填充字符数）+ `%N$hn`（写 2 字节）
   - 多次 %hhn 拼接完整地址（如写 system 到 GOT）
4. **目标**：覆写 GOT（[[got-overwrite]]）/ 覆写返回地址（[[rop-ret2libc]]）/ 覆写 _IO_FILE（[[fsop]]）

## FORTIFY 绕过
- `_FORTIFY_SOURCE` 会检测 `%n` → 换用 `%*N$c` + `%N$hn`（有些实现不检测）
- 或用 `%s` 先泄漏再找其他写入原语

## 关键
- 偏移用 `%p` 序列试探，不写死
- 栈上放地址：pwntools `p64(target) + b'%N$n'` 或 `fmtstr_payload`（自动生成）
- 多次 `%hhn` 拼接：每个 `%hhn` 写 1 字节，需要多次调用或一次长格式串
- 地址值用 `elf.got[]`/`libc.sym[]` 动态查

## 参考
[[got-overwrite]]（%n 写 GOT）、[[rop-ret2libc]]（%n 写返回地址）、[[fsop]]（%n 写 _IO_FILE）

★**单次 printf + Full RELRO + ASLR 的死局先别放弃**：泄+写同轮闭环不可行
（参数预读）时，评估 [[partial-brute-format-string]]（只写低 1-2 字节 + 1/256
外层重试）——完整地址 28 bit 随机不可暴力，但低 16 位里只有 4 bit 是真随机。
