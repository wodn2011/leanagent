# 渗透测试报告：profix-calc

## 1. 任务概述
- 目标：对后缀表达式计算器进行渗透测试与漏洞验证
- 目标文件：`/work/workspace/0029-2024-54-profix-calc-20260909-185030/target`
- 文件类型：ELF 64-bit LSB PIE executable, x86-64, dynamically linked, not stripped
- 安全防护：Partial RELRO / Canary / NX / PIE / Fortify未启用 / Glibc 2.39
- 分析结果：已验证任意地址读写（通过越界读写泄露 libc 与 PIE 地址，并覆写 GOT 表实现任意控制流劫持）

## 2. 已确认漏洞
漏洞 BUG-001：全局栈指针无边界检查导致越界读写
- CWE 分类：CWE-787 (Out-of-bounds Write) / CWE-125 (Out-of-bounds Read)
- 严重程度：严重
- 漏洞位置：`push` (0x128a) / `pop` (0x12b5) / `eval_expr` (0x13d0)
- 漏洞详情：后缀表达式求值使用的全局栈指针 `stack_top` 在执行 `push` 和 `pop` 时完全缺失边界检查。攻击者可通过构造特定数量的操作符使 `stack_top` 下溢至 `.bss` 中的 `FILE*` 指针区与 `.got.plt` 区，或上溢越过栈数组边界。结合 `strtoll` 解析的任意 64 位数值，攻击者可对 GOT 表进行越界读写。
- 已验证原语：
  1. INFO_LEAK (libc)：3 个 `+` 操作符使 `stack_top` 下溢至 0x40a8，末尾 `pop` 读取 `stderr FILE*` 泄露 libc 地址 (0x76ae413574e0)。
  2. INFO_LEAK (PIE)：9 个 `+*+*+*+*+` 操作符使 `stack_top` 下溢至 0x4078，末尾 `pop` 读取 `stack_top` 自身全局变量值泄露 PIE 地址 (0x608dae2b2070)。
  3. RELATIVE_WRITE：4 个 `+` 操作符使 `stack_top` 下溢至 0x40a0，随后 `push(0xdeadbeef)` 覆写 `stderr FILE*`，末尾 `pop` 读回写入值确认写成功。
  4. ARB_WRITE：结合上述泄露的 PIE 与 libc 基址，通过操作符将 `stack_top` 下溢至 GOT 表目标地址，`push` 写入计算好的地址覆写 GOT 表实现控制流劫持。
- 关键别名发现：`stack_top = 0x40c0 - N*8`（N 为空栈执行的操作符数），下溢指针分别别名映射至 `FILE*` 指针槽、`stack_top` 自身变量及 `.got.plt` 表项。
- 修复建议：在 `push()` 和 `pop()` 函数中增加对 `stack_top` 相对于数组上下界（`0x40c0` 与 `0x48c0`）的严格校验，并在 `eval_expr` 中跟踪栈深度，拒绝会导致溢出或下溢的异常表达式。

## 3. 利用链与后果
已验证端到端最高后果：任意地址读写与控制流劫持
1. 泄露 libc 地址：发送 `+ + +`，下溢读取 `stderr FILE*` 获得 libc 运行时地址。
2. 泄露 PIE 基址：发送 `+*+*+*+*+`，下溢读取 `stack_top` 自身变量，计算得出 PIE 基址。
3. 越界相对写验证：发送 `+ + + + 0xdeadbeef`，下溢并覆写 `stderr FILE*` 验证写入能力。
4. 任意地址写与劫持：利用泄露的基址计算 GOT 表项偏移，通过操作符将 `stack_top` 下溢至目标 GOT 地址，`push` 写入构造的地址完成劫持。

## 4. 方法论
文件识别与安全防护分析 -> 逆向分析输入处理与栈操作逻辑 -> 静态确认缺失边界检查 -> 动态构造 PoC 验证越界读写原语 -> 组合原语泄露基址并实现任意地址写 -> 端到端利用验证。

## 5. 产物路径
| 产物类型 | 路径 |
|---|---|
| PoC 脚本 | `/work/workspace/0029-2024-54-profix-calc-20260909-185030/poc-BUG-001.py` |
| 最终利用脚本 | `/work/workspace/0029-2024-54-profix-calc-20260909-185030/exploit.py` |