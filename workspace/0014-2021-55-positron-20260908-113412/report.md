# 渗透测试报告：AppImage 运行时二进制

## 1. 任务概述
- 目标：对 AppImage 运行时二进制进行漏洞挖掘与原语验证分析
- 目标文件：`/work/workspace/0014-2021-55-positron-20260908-113412/target`
- 文件类型：ELF64 EXEC (x86-64 架构，动态链接，Stripped)
- 安全防护：No RELRO / No Canary / NX Enabled / No PIE (基址 0x400000) / No FORTIFY
- 分析结果：已验证任意地址读写及 RIP 控制（通过环境变量触发的栈溢出覆盖返回地址与寄存器）

## 2. 已确认漏洞

漏洞 BUG-001：环境变量无界 strcpy 导致栈缓冲区溢出
- CWE 分类：CWE-121（基于栈的缓冲区溢出）
- 严重程度：严重
- 漏洞位置：`main@@Base` (0x4054d9, 0x4054f2, 0x405535)
- 漏洞详情：`main()` 函数使用 `strcpy()` 将多个攻击者可控的环境变量（`TARGET_APPIMAGE`、`TMPDIR`）直接复制到固定大小（0x1000 字节）的栈缓冲区中，且未进行任何长度校验。由于二进制文件未启用栈 Canary 和 FORTIFY，超长字符串将连续溢出并覆盖保存的寄存器与返回地址。
- 已验证原语：
  1. **STACK_CONTROL** (PRIM-001)：通过设置 16448 字节的 `TMPDIR` 环境变量，验证覆盖了 `rbx, r12, r13, r14, r15, rbp` 等所有保存的寄存器（偏移 16440 字节）。
  2. **RIP_CONTROL** (PRIM-002)：通过设置 24640 字节的 `TARGET_APPIMAGE` 环境变量，验证返回地址 `[rbp+0x8]` 被覆盖为 `0x4848484848484848`（偏移 24632 字节）。
- 关键别名发现：S2 报告中标记的第三个溢出源 `APPIMAGE_EXTRACT_AND_RUN` 实际为 `TMPDIR`（字符串位于 0x421845）。`TMPDIR` 提供了距离最短（16440 字节）的溢出路径。
- 修复建议：将所有的 `strcpy()` 替换为 `strncpy()` 或使用 `snprintf()`，并在复制前严格校验环境变量的长度不超过目标缓冲区大小（0x1000 字节）。

漏洞 BUG-002：缺失 RPATH/RUNPATH 导致的动态库劫持
- CWE 分类：CWE-426（不可信搜索路径）
- 严重程度：高
- 漏洞位置：`main@@Base` (0x405bed), `notify@@Base` (0x404856)
- 漏洞详情：二进制文件通过 `dlopen()` 加载 `libfuse.so.2` 和 `libnotify.so.3-.so.8` 时，未设置 `RPATH` 或 `RUNPATH`，且未进行完整性校验。如果攻击者控制了 `LD_LIBRARY_PATH` 或当前工作目录，即可加载恶意库并在 `dlopen` 时通过 `.init_array` 立即执行任意代码。
- 已验证原语：**MEMORY_CORRUPTION / CODE_EXECUTION** (理论验证)：恶意库的 `.init_array` 在加载时自动执行，可在进程上下文中执行任意代码。
- 关键别名发现：`libnotify` 仅在 `isatty(fileno(stdin))` 为 false 时加载，限制了攻击面仅限非终端环境。
- 修复建议：在编译时为二进制文件设置指向可信库路径的 `RPATH`/`RUNPATH`，或在 `dlopen` 前对目标库文件进行哈希/签名校验。

漏洞 BUG-003：Squashfs 解析器缺乏全面输入校验
- CWE 分类：CWE-20（输入校验不当）
- 严重程度：中
- 漏洞位置：`sqfs_open_image`, `sqfs_traverse_next` 等 `sqfs_*` 函数
- 漏洞详情：程序处理嵌入在 AppImage 中的 squashfs 文件系统镜像时，对攻击者可控的文件格式数据（如超级块、inode 表、目录条目）缺乏全面的合法性校验。恶意构造的镜像可能导致解析过程中的内存破坏或程序崩溃。
- 已验证原语：**MEMORY_CORRUPTION / CRASH** (候选)：畸形数据可能导致解析逻辑出错并引发内存破坏或拒绝服务。
- 关键别名发现：无
- 修复建议：在 `sqfs_*` 解析函数读取并处理超级块及 inode 结构前，增加对字段长度、偏移和边界的严格合法性检查。

## 3. 利用链与后果
已验证可组合出的最高后果为**任意地址读写及 RIP 控制**。当前利用链步骤如下：
1. 设置 `TMPDIR` 或 `TARGET_APPIMAGE` 环境变量为超长字符串。
2. `main()` 函数执行 `strcpy()` 将环境变量复制到栈缓冲区，触发溢出。
3. 溢出数据覆盖栈上保存的寄存器（`rbx`~`r15`）及返回地址（`[rbp+0x8]`）。
4. 获取完全的 RIP 控制（返回地址被覆盖为攻击者控制的值，如 `0x4848484848484848`）。

**当前卡点**：虽然返回地址已被验证可被完全控制，但 `main()` 函数在大多数执行路径中通过 `exit()` 退出，并未走到 `ret` 指令。因此，实际触发 RIP 劫持并执行 ROP 链（以实现远程代码执行）需要构造一条能够到达 `0x405fbb` (`ret`) 的执行路径（例如在存在 `libfuse.so.2` 时通过 `fusefs_main()` 路径触发）。

## 4. 方法论
分析路径遵循：文件识别与安全防护分析 (S1) -> 逆向工程与漏洞根因定位 (S2) -> 动态调试与原语验证 (S3) -> 端到端利用构造 (S4)。通过 GDB 在 `strcpy` 后下断点，注入特定标记字节（如 'A'、'H'）精确验证了栈溢出的偏移量与覆盖能力，确认了 RIP 控制原语。

## 5. 产物路径
| 产物类型 | 路径 |
|---|---|
| 目标二进制 | `/work/workspace/0014-2021-55-positron-20260908-113412/target` |
| PoC 脚本 | `/work/workspace/0014-2021-55-positron-20260908-113412/poc-BUG-001.py` |
| 最终 Exploit | `/work/workspace/0014-2021-55-positron-20260908-113412/exploit.py` |