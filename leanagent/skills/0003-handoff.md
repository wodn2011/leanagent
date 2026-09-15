## 前序会话的关键成果（已验证，直接复用，不要重新推导）

### 环境（glibc 2.27 原题环境，全部实测确认）
- libc 2.27（无 safe-linking、无 tcache double-free 检查、`__free_hook` 存在）
- 已知偏移：`__free_hook=0x3ed8e8`，`system=0x4f4e0`，`_IO_2_1_stdout_=0x3ec760`，`main_arena≈0x3ebc40`（unsorted bin fd 指向 main_arena+0x60）
- 菜单提示词（实测精确措辞）：`>` 选单；`Which note?` index；`Offset?` offset；`Who long?` length
- **oracle 信号（实测完美工作）**：`offset > size` → `"Invalid offset."`；`length > size` → `"Invalid lenght."`（注意拼错的 lenght）；两项都过 → 进 secure_print（其 D1[0]=0 时安全返回）。程序在 Invalid 后继续运行（进程内 oracle，无需重启）

### 已打通的能力
1. **盲注 oracle 二分读任意 8 字节字段**（BUG-002 UAF：free 后 note header 留在 tcache，H0 的 size 字段=堆地址）——已实测用 length 二分出 `size=0x63eeaad57260`（H0 自身地址）。二分约 48 次查询、每次毫秒级，同一进程内完成
2. **堆地址泄露已解决**：BUG-001 的 create 第 15 次 idx OOB 写 note_list[14]=idx，printf 泄露堆地址（低 12 位 0x5e0 固定）
3. 堆布局实测：note header 0x20 chunk（H），data chunk 尺寸随 size；H0[0]=fd、H0[8]=data_ptr；drop 顺序 free(data)→free(header)

### 卡过的坑（不要重蹈）
- ❌ 直接读指针内容 → secure_print 的 isprint 过滤 exit(-1)——**盲注 oracle 完全绕过它，不要碰 secure_print**
- ❌ 二分脚本 recv 卡死（60s 超时）——每步 recv 必带 timeout=2；二分前先 oracle(0)=True / oracle(上界)=False 验证
- ❌ tcache poisoning 时 header 与 data 同 bin 污染——注意 header(0x20) 与 data 的 bin 分离，drop 顺序控制
- ❌ /proc/pid/maps 里 libc 映射行不含 "libc.so.6" 字样（ld-2.27 加载），按 r-xp 大段定位

### 建议路线（只剩 Phase 3 最后一步，且卡点已诊断）
Phase 1（盲注 oracle 二分 H0->size 泄露堆地址）✅ 已稳定打通
Phase 2（盲注 oracle 二分 unsorted bin fd 泄露 libc，libc_base = fd - 0x3ebd20）✅ 已稳定打通，页对齐验证通过
Phase 3（tcache poisoning → __free_hook）❌ 卡点已精确诊断：
- **症状**：note 12 弹出 D6 后 tcache head = D6->fd = D6（fd 自指循环链），写入 free_hook 地址后 head 没变化——后续分配拿到的还是 D6，不是 __free_hook
- **原因**：double-free 同一 chunk 后 tcache 链成自指环，中间没有分配打断
- **修法**：drop(D6) 后先 create 一次（把 D6 弹出、打断循环），再 drop(D6)（此时 fd 已指向先前伪造目标），或改用"隔一个 chunk 的 double-free"（drop(D6); drop(D7); drop(D6) 在 2.27 无 double-free 检查下安全）；写 fd 时注意 note 12 的写入操作要落在弹出的 chunk 的 fd 位置
- 之后：分配两次到 __free_hook → 写 system → free 一个内容为 "/bin/sh" 的 note → EXPLOIT_SUCCESS

已落盘文件：`/work/workspace/0003-babyheap-libc227/exploit.py`（Phase 1/2 已工作，只修 Phase 3 堆操作顺序）
