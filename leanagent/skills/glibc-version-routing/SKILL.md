---
name: glibc-version-routing
description: 按 glibc 版本选利用路线的总路由表——先定版本再选链，避免在高版本机制失效的低版本上空转（或反之）。
---

# Glibc 版本路由（先看版本，再选链）

**第一动作**：确定题目 libc 版本（S1 的 identify_libc / strings "GNU C Library"），
对照下表圈定可用机制，再进入具体技能。路线在错误版本上空转是最贵的失败模式。

## 版本机制速查表

| 机制 | 2.23- | 2.24-2.25 | 2.26-2.27 | 2.28-2.33 | 2.34+ |
|---|---|---|---|---|---|
| tcache | ✗ | ✗ | ✓ | ✓ | ✓ |
| tcache safe-linking | ✗ | ✗ | ✗ | 2.32+ | ✓ |
| tcache double-free 检查 | ✗ | ✗ | ✗ | 2.29+ | ✓ |
| `__malloc_hook`/`__free_hook` | ✓ | ✓ | ✓ | ✓ | ✗ **已移除** |
| unsorted bin attack | ✓ | ✓ | ✓ | ✗ 2.28 加双向链表校验 | ✗ |
| 经典 FSOP（伪造 vtable） | ✓ | ✗ **IO_validate_vtable 引入** | ✗ | ✗ | ✗ |
| `_IO_str_jumps` 链 | ✓ | ✓ | ✓ | ✗ 2.28 限制 | ✗ |
| `_IO_wfile_jumps`（Apple 系） | ✓ | ✓ | ✓ | ✓ | ✓ |
| fastbin attack | ✓ | ✓ | ✓ | ✓ | ✓（有 tcache 时需先填满 bin） |

## 按版本选终点（劫持目标）

- **< 2.34**：优先 `__free_hook = system` + free("/bin/sh")（最短链）；
  fastbin/tcache poisoning 到 hook 附近的 fake chunk。chunk size 必须与请求
  的 fastbin/tcache bin 精确匹配（calloc(0x40) → 只认 0x5X）。

  ★**fake size 扫描的正确操作**（两轮实测翻车点，务必照做）：
  1. 把 `__malloc_hook`/`__free_hook`/`__realloc_hook` **三个都扫**——
     只扫 malloc_hook 就断言"无 fake size"是错的；
  2. **扫的是 libc 文件的 .data/.rodata 静态字节**（readelf -lW 拿 vaddr→
     文件偏移映射，再读文件字节），不是运行时 .bss（hook 本身在 .bss，
     文件里是 0，运行时才初始化——扫 .bss 必然得出"全零"的错误结论）；
  3. `__free_hook` 前后 0x100 范围常是字符串区，ASCII 字节恰好凑出
     合法 size（实测 2.24 的 `__free_hook-0x3d` 处有 0x5f，前一条字符串
     "the r'e_max_failures' variable is obsolete..." 的 `_` = 0x5f）；
  4. 找到候选字节后**反推覆盖关系**：fake chunk header 在 size 字节处-8，
     user data 从 size 字节+8 起；`hook_addr - (size_byte_addr + 8)` 必须
     ≥0 且 < size 值（write 写入范围内能覆盖到 hook）；
  5. 实测命令模板（容器内可直接跑）：
     ```python
     # data = open(libc_path,'rb').read(); 按段映射把 vaddr 转文件偏移
     for i in range(hook_off-0x100, hook_off+0x10):
         b = data[v2f(i)]
         if 请求bin的下界 <= b <= 上界:   # 如 calloc(0x40)→0x50<=b<=0x5f
             rel = hook_off - (i + 8)
             if 0 <= rel < b - 0x10: print(hex(i), hex(b), '+', hex(rel))
     ```
- **>= 2.34**：hook 没了 → [[fsop]]（House of Apple 2 等）为主。

## 按版本选 FSOP 形态

- **< 2.24**：vtable 无校验 → 任意伪造 vtable 直接 system。
- **2.24-2.27**：vtable 必须在 `__libc_IO_vtables` 区间内 →
  - `_IO_str_jumps` + `_IO_str_overflow` 的 `_allocate_buffer` 指针（2.28 前）
  - 或 `_IO_wfile_jumps`（[[fsop]] House of Apple 2 全版本可用）
- **>= 2.28**：`_IO_str_jumps` 严格限制 → 只剩 `_IO_wfile_jumps` 系
  （House of Apple 2 / Emma——伪造 `_wide_data->_wide_vtable`）。

## unsorted bin 相关路线（严格卡版本）

- **unsorted bin attack**（bk 改 target-0x10 → `*target = main_arena+88`）：
  **仅 2.27 及以前**。2.28 起 `bck->fd == victim` 校验直接杀死此技术。
  House of Orange 的阶段 3 依赖它 → 完整 Orange 仅 2.23-2.27。
- **House of Orange 阶段 1**（改 top size 触发 sysmalloc 释放旧 top——
  "无 free 函数"题型的造 free chunk 手法）：**全版本通用**（含 2.35+），
  只是后续劫持段要换成 large bin attack + Apple/Emma。
- **2.26+ 有 tcache**：小 chunk 先进 tcache，unsorted 流转被打断——
  想利用 unsorted/large bin 先用 7 个同 size chunk 填满对应 tcache。

## 堆攻击面通用优先级（与版本无关的短路检查）

1. off-by-one / 溢出能改下一 chunk 的 size → **chunk overlap** 是最短链
   （改大 size → free → 重新分配 → 重叠指针双写）；
2. overlap/UAF 写 fastbin/tcache 的 fd → [[tcache-poisoning]]（注意版本
   分支：2.32+ safe-linking 要先泄堆地址；无 tcache 版本走 fastbin）；
3. poisoning 落点：hook（<2.34）/ `_IO_list_all` 或 FILE 结构（FSOP 系）；
4. 以上都长时才考虑 unsorted/large bin attack（版本限制多、检查多）。

★反模式（实测翻车）：在有短链（off-by-one → overlap → fastbin →
`__free_hook`）的版本上，绕远路走 FSOP/unsorted bin attack——链长一倍，
检查点多一倍，S4 预算内跑不完。先穷举短链再上长链。

## 参考
[[tcache-poisoning]]（fd 篡改细节+版本分支）、[[fsop]]（House of Apple 2
全版本细节）、[[blind-oracle-leak]]（泄露阶段）
