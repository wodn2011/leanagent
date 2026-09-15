## 前序会话关键成果（已验证，直接复用）

### 环境（已由系统配置好，严禁改动）
- target 已 patchelf 到题目原生 glibc 2.24（ld-2.24 + rpath 指向题目 libc）——**直接 process('target') 即可，运行正常**
- ★【禁止】自造 target_patched / 换系统 libc / 改 patchelf——题目语义是 2.24（无 tcache），在 2.39 上打通不算解出
- I/O 已验证的稳定方案：所有 recv 用 recvrepeat(0.5) 收全 + find(marker) 定位（recvuntil 会因 scanf/read 竞态错位，曾浪费 25 分钟）

### 已打通的能力（多轮实测）
1. **libc 泄露**：add×2 → write(0) 73B 改 chunk1 size（off-by-one 0x51→大）→ remove(1) 入 unsorted → view 泄 main_arena+0x58 → libc_base = leak - 0x3c1b58
2. **off-by-one**：write 73 字节 = 64 数据 + 8 prev_size + 1 字节 size（GDB 已验证）
3. **堆重叠**：改大 size 后 remove → unsorted split → 重叠指针

### 已排除的死路（不要重试）
- fastbin attack 到 __free_hook：fake chunk 需要完整【4 字节】size（glibc 检查 mov eax,[victim+8]; shr 4）——__free_hook-0x3d 的单字节 0x5f 后面是字符串非零 → fastbin_index 不匹配 → SIGABRT。单字节巧合只在指针字段附近成立（如 __malloc_hook-0x23 的 0x7f）
- __malloc_hook 附近无 0x5X/0x7X 4 字节布局

### 建议路线（差堆内落点）
libc 已知 + 堆重叠可控 → 在【堆上】构造 fake chunk（size 完整可控）→ fastbin poisoning 分配到堆内任意地址（含 __free_hook 也可行：把堆上 fake chunk 的 fd 写成 __free_hook-0x8 区地址？不——poisoning 目标也需 4 字节 size。改为：重叠后 UAF 写 fastbin fd → 两次 calloc 拿重叠 chunk → 直接在重叠区写 unsorted chunk 的 bk = _IO_list_all-0x10 → unsorted bin attack（2.24 可用）→ House of Orange FSOP（_IO_str_jumps 2.24 可用）或 exit 触发。
