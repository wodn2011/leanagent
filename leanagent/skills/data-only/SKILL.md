---
name: data-only
description: 任意写→篡改数据达成目标（不控控制流，绕CFI）。通用方法论。
---

# Data-Only Attack / BOP

## 适用条件
- **核心原语**：Arbitrary Write（任意地址写）
- **Mitigation**：强 CFI（控制流不可劫持）/ Full RELRO + 无 vtable 可用 / sandbox
- **典型漏洞**：OOB 写 / 堆溢出 / 格式化字符串 %n

## 核心技术
不劫持控制流（不 ROP/不覆写 GOT/不覆写 vtable），直接修改程序数据/特权变量达成目标。

## 关键步骤
1. **确定目标数据**：程序逻辑依赖的全局变量/结构体字段
   - `uid`/`gid`（提权）
   - `auth`/`is_admin` 标志
   - `buf_limit`/`size` 限制值
   - 函数指针表（非 vtable 类，如自定义 dispatch table）
2. **用 arb write 改值**：找到目标地址 → 写入期望值
3. **触发**：让程序读修改后的数据 → 改变行为（提权/绕过限制/改变执行逻辑）

## 适用场景
- **CFI 开**：控制流劫持被拦截 → 数据篡改不受 CFI 限制
- **Full RELRO + 无 vtable 可用**：不能 GOT/FSOP → 改数据
- **Sandbox**：不能 execve → 改文件路径/权限
- **flag 读取**：改 `open` 路径变量 → 读取 flag 文件

## 关键
- 目标地址用 `global_vars`/`symbols` 工具查
- 理解程序逻辑（`disassemble` 看哪些全局变量影响控制流/权限）
- 不需要泄漏 libc（不调 system/不 ROP）→ 只改数据

## 参考
[[got-overwrite]]（Partial RELRO 时劫持 GOT 更直接）、[[fsop]]（Full RELRO + 可用 vtable 时 RCE）
