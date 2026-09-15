---
name: fsop
description: 任意写+Full RELRO→伪造_IO_FILE/vtable劫持(House of Apple 2)→system(" sh")。通用方法论（FILE 字段布局+别名技巧+触发链）。
---

# FSOP / House of Apple 2（任意写 + Full RELRO → RCE）

## 适用条件
- **核心原语**：Arbitrary Write（能往一个**已知地址**写 controlled 数据）
- **Mitigation**：Full RELRO（GOT 只读）+ glibc >= 2.24（vtable 校验）→ 不能劫 GOT，走 FSOP
- glibc >= 2.34 无 `__free_hook` → House of Apple 2 是主 RCE 路线

## 核心思想
glibc 的 `_IO_FILE` 结构（224B/0xe0）含 `vtable` 指针。在程序会 flush 的 FILE（`stderr`/`stdout`，地址 = `libc_base + libc.sym['_IO_2_1_stderr_']` 等）上**用 ARB_WRITE 伪造整个 _IO_FILE**：`vtable`→`_IO_wfile_jumps`（libc 内合法 vtable，过 `IO_validate_vtable`），`_wide_data` 设成 `FILE-0x10`（把 wide_data 字段**别名到 FILE 自身可写区**），让 `exit()`→`_IO_flush_all_lockp` 遍历到该 FILE 时走 wide path → `_IO_wfile_overflow` → `_IO_wdoallocbuf` → 调 `*(wide_data->_wide_vtable + 0x68)`。把 `_wide_vtable` 设成 FILE 自身地址 → `*(FILE+0x68)` 就是你写在 FILE+0x68 的 `system`。`rdi` = FILE 指针，FILE 头 8 字节设成 `" sh\0"` → `system(" sh")` 拿 shell。

---

## 前置
- **ARB_WRITE 写原语**：能往受控地址写 controlled 数据（已验证可用）——把它**原样复用**（同样的 I/O 时序、同样的"如何让写目标地址 = 你要的地址"），只把"写什么/写到哪"换成下面的 FILE payload + FILE 结构地址。别重造写原语。
- **libc base**：已泄漏（ARB_READ/INFO_LEAK）。下面所有 libc 地址用 `libc.sym[]` 算。
- **目标 FILE 结构地址** = `libc_base + libc.sym['_IO_2_1_stderr_']`（或 `_IO_2_1_stdout_`）。用 ARB_WRITE 把 payload 写到这个地址。

### Leak 前置：突破 %s 的 NUL 截断（受限读泄 FILE 指针字段的通用两步法）

若 leak 原语是 `printf("%s", ptr)` 类（读到 NUL 截断），直接读可达的 FILE 结构
只能泄出开头的 `_flags`（后面 padding 全 NUL）。要泄出结构内的指针字段
（libc/堆地址），通用两步法：

1. **先写**：用受限/OOB 写**只覆盖该 FILE 的前 8 字节**——
   `_flags`（前 4 字节）保持原值 + padding（后 4 字节）填任意非零
   ——把结构内的第一个 NUL 推迟到指针字段的高位零字节处；
2. **再读**：同样的 %s 读这次会越过 padding，一直打印到第一个指针字段的
   高位 NUL（64 位地址形如 0x00007f..，最高 2 字节是 0）→ 泄出该指针的
   低 6 字节 → `libc_base = leak - (该字段在 FILE 结构内的偏移 + 对应符号的 libc 偏移)`。

要点：
- 覆盖长度精确到 8 字节，多写会破坏要泄的指针字段本身；
- `_flags` 换成异常值会破坏后续 printf —— 保持原值；
- stdout/stderr/stdin 三个 FILE 指针若都可达，写哪个读哪个（size 约束满足的那个）；
- ★**全部 I/O 禁止依赖 recvuntil 边界的顺序假设**（不只泄露段——
  写入段的确认回显、触发前的状态收集同样）：
  - 【禁令】`recvuntil(b'xxx')` 后假设"接下来恰好是想要的内容"——
    管道调度/缓冲 flush 时机变化下会错位（拿到空数据/吞掉目标段）；
  - 【正确模式】发送后 `recvrepeat(0.3)` 收全部剩余输出，再在完整
    buffer 里 `find(marker)` 定位（marker = 已知特征字节：你写的
    flags+padding、已知提示串、固定回显）。定位失败按下面分级重试；
- **泄露有效性检查**：解出的 base 必须同时满足 `& 0xfff == 0` **且
  `> 0x10000`**（负值/零 base 恰好页对齐会绕过纯对齐检查——
  空数据 u64 后减偏移得到小负值，仍可能通过 `& 0xfff`）；
- **分级重试**（泄露失败 ≠ 进程报废）：
  - 读操作失败（view/printf 泄露没抓到）→ **进程还活着且状态未动**：
    清残留输出（`recvrepeat(0.2)`）+ 同进程重抓泄露——最便宜，先做；
  - 同进程连抓 2-3 次都失败 → 才 `p.close()` 重开 process 整轮重来；
  - **写操作搞砸了**（如两步写第一步把间接槽位改成了错误值、
    不再自引用）→ 状态不可逆，必须重开进程；
  - 重试 3-5 轮。单次裸跑的成功率不可靠，不要拿一次失败下结论；
- ★**竞态是常态，成功一次即定案**：菜单交互 + FSOP 触发链存在
  小概率时序竞态（libc 内部状态、堆布局 ASLR），逐次消除不现实。
  exploit 脚本内自带重试循环（整链从头 N 次），**任何一次 attempt
  拿到 shell 立即 break 返回成功**——agent 层不再重复验证稳定性；
- 拿到合法 base 后再进入 FSOP 构造阶段。

## 步骤

### 1. 伪造 FILE 结构（House of Apple 2 字段布局，~0xe0 字节）
构造 0xe0 字节 payload，用 ARB_WRITE 写到目标 FILE 结构地址。偏移是 `_IO_FILE` 通用结构偏移（glibc 稳定）：

| 偏移 | _IO_FILE 字段 | 值 | 作用 |
|---|---|---|---|
| 0x00 | `_flags` | `0x00687320`（= `" sh\0"` 小端）| `rdi`=FILE 指针时，FILE[0:8]=`" sh"` → `system(" sh")` |
| 0x08 | `_IO_read_ptr` | `0` | = `wide_data->_IO_write_base`，`_IO_wdoallocbuf` 要求为 0 |
| 0x10 | `_IO_read_end` | `1` | = `wide_data->_IO_write_ptr`，`_IO_flush_all` 检查 `write_base < write_ptr` 要通过 |
| 0x18 | `_IO_read_base` | `0` | 链不用 |
| 0x20 | `_IO_write_base` | `0` | = `wide_data->_IO_buf_base`，`_IO_wdoallocbuf` 要求为 0 |
| 0x28/0x30 | `_IO_write_ptr`/`_end` | `0` | 链不用 |
| 0x68 | `_chain` | **`system` 地址** | `fake_wide_vtable[0x68]`（`__doallocate` 槽）= `*(FILE+0x68)`（见下别名）|
| 0x88 | `_lock` | `FILE_addr + 0x40`（可写、不与 wide_data 字段重叠）| lock 获取时不崩 |
| 0xa0 | `_wide_data` | **`FILE_addr - 0x10`** | ★把 `wide_data` 字段**别名到 FILE 自身可写区**：`wide_data+0x18`=`FILE+0x08`，`wide_data+0x20`=`FILE+0x10`，`wide_data+0x30`=`FILE+0x20`，`wide_data+0xe0`（`_wide_vtable`）=`FILE+0xd0` |
| 0xc0 | `_mode` | `1`（>0）| 触发 `_IO_flush_all_lockp` 走 wide path |
| 0xd0 | `_wide_vtable`（wide_data+0xe0）| **`FILE_addr`** | ★`fake_wide_vtable = FILE` → `*(fake_wide_vtable+0x68)` = `*(FILE+0x68)` = 你写的 `system` |
| 0xd8 | `vtable` | **`_IO_wfile_jumps`**（`libc.sym` 查）| 过 `IO_validate_vtable`（必须 libc 内合法 vtable）|

payload 只覆盖这一个 FILE（0x00~0xe0），别溢到相邻 FILE。

### 2. 触发 → system(" sh") → shell
触发程序的正常退出路径（exit/return 到 `exit()`）→ `exit(0)` → `_IO_flush_all_lockp` 遍历 `_IO_list_all` 到你伪造的 FILE：
- `_flags & 0x8000 == 0`（`0x00687320` 满足）→ 继续
- `_mode > 0`（=1）→ wide path
- `wide_data->_IO_write_base`(=FILE+0x08=0) `<` `wide_data->_IO_write_ptr`(=FILE+0x10=1) → 通过
- `vtable`=`_IO_wfile_jumps` 过校验 → 调 `vtable[0x18]`=`_IO_wfile_overflow`
- `_IO_wfile_overflow`：`wide_data->_IO_write_base`(0)==0 → 调 `_IO_wdoallocbuf`
- `_IO_wdoallocbuf`：`wide_data->_IO_buf_base`(=FILE+0x20=0)==0 → 取 `wide_data->_wide_vtable`(=FILE+0xd0=FILE_addr) → 调 `*(fake_wide_vtable+0x68)`=`*(FILE+0x68)`=`system`，`rdi`=FILE 指针，FILE[0:8]=`" sh"` → `system(" sh")` → shell
- 拿到 shell 后 `cat /flag*` / `id`，打印 `LEANAGENT_SUCCESS` + 输出。

---

## 关键检查点（卡住时逐条核对）
1. **ARB_WRITE 复用已验证的写原语**（I/O 时序 + "如何让写目标=FILE 地址"），别自己重造。
2. payload 写到的是 **FILE 结构本体地址**（`libc_base + libc.sym['_IO_2_1_stderr_']`），不是它的某个字段指针。
3. 六件套缺一不触发：`_wide_data=FILE-0x10`、`_wide_vtable(FILE+0xd0)=FILE`、`+0x68=system`、`vtable=_IO_wfile_jumps`、`_mode=1`、`_lock` 可写。+ `0x08=0`/`0x10=1`/`0x20=0` 触发链检查项。
4. 触发走 `exit`（正常退出路径），不是 abort/segv。
5. libc 偏移**全 `libc.sym[]` 动态查**（`_IO_2_1_stderr_`/`_IO_wfile_jumps`/`system`/`next(libc.search(b'/bin/sh'))`），不写死版本常量。
6. ★**经间接槽位写大 payload 的"写后检查"坑**（写 0xe0 字节 FILE 前必读）：
   很多程序的读入函数在 read 返回后会**检查/改写写入区末尾的字节**
   （如 `buf[read_return]` 的换行/NUL 处理——读取 N 字节后看 `*(target+N)`
   是否为 `\n` 并替换为 `\0`）。经间接槽位（如先改指针槽 P 再写 `*P`）
   写大结构时：
   - `*(target+N)` 处的字节【不受你控制】（它是目标结构后面的内存）；
   - 若该字节不可读 → 解引用崩溃；若恰为 `\n` → 被替换成 `\0` 破坏后续字段，
     或触发异常分支（如失控刷输出）；
   - **写前先验证**：`*(target+N)`（gdb 或读原语看一眼）必须可读且非 `\n`；
     不满足就调整写入长度 N（让它落在已知安全的字节上）或分段写；
   - 更稳的通用替代：**别直接往目标结构写大 payload**——先让槽位 P 指向
     一个你能完全控制的缓冲区（BSS/堆上），把大 payload 写进缓冲区
     （缓冲区后面的内存你可控或已知），再一次性/分步搬迁。
   症状识别：payload 写完目标结构"半残"（前几个字段对了、后面错乱），
   或写完后程序行为异常（失控输出/提前退出），先查写后检查。

## glibc 版本
- <2.24：vtable 不校验 → 任意 vtable
- 2.24-2.33：vtable 校验 → 用 `_IO_wfile_jumps` 等合法 vtable
- >=2.34：无 `__free_hook` → 本路线（House of Apple 2）为主

## 参考
[[got-overwrite]]（Partial RELRO 时劫 GOT 更简单）、[[tcache-poisoning]]（UAF 可分配到 FILE 附近配合）、[[data-only]]（CFI 强保护改数据不控流）
