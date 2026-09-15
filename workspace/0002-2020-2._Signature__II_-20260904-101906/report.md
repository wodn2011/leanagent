# 渗透测试报告：0002-2020-2._Signature__II_

## 1. 任务概述
- 目标：对目标二进制文件进行全链路安全分析，验证潜在漏洞与最高级别后果。
- 目标文件：`/work/workspace/0002-2020-2._Signature__II_-20260904-101906/target`
- 文件类型：ELF 64-bit LSB pie executable, x86-64, dynamically linked
- 安全防护：Partial RELRO / NX enabled / No Canary / PIE enabled / glibc 2.39
- 分析结果：已验证最高级别后果为【相对地址越界读与信息泄露】（通过短字符串越界读取相邻内存并经 DES 加密回传泄露）。

## 2. 已确认漏洞

漏洞 BUG-001：命令行参数缺失导致空指针解引用
- CWE 分类：CWE-476 (NULL Pointer Dereference)
- 严重程度：中（直接导致进程拒绝服务）
- 漏洞位置：main (0x1193 / 0x117b)
- 漏洞详情：main() 在解引用 argv[1] 和 argv[2] 前未校验 argc >= 3。当程序以少于 2 个参数启动时，argv[1] 或 argv[2] 为 NULL，导致双重间接寻址时解引用地址 0x0，引发 SIGSEGV。
- 已验证原语：NULL_POINTER_DEREF（动态验证：0 参数时在 0x1193 处 SIGSEGV，1 参数时在 0x117b 处 SIGSEGV，返回码 -11）
- 关键别名发现：argv[1] = *(argv + 0x8) 当 argc < 2 时解析为 NULL (0x0)；argv[2] = *(argv + 0x10) 当 argc < 3 时解析为 NULL (0x0)。
- 修复建议：在 main() 入口处增加 argc 校验，确保 argc >= 3 后再访问 argv[1] 和 argv[2]。

漏洞 BUG-002：短字符串参数越界读取导致信息泄露
- CWE 分类：CWE-125 (Out-of-bounds Read)
- 严重程度：高（验证可泄露相邻内存数据）
- 漏洞位置：main (0x117b / 0x1193)
- 漏洞详情：main() 通过 `mov rax,[rax]` 固定读取 argv 字符串指针的 8 字节，但未校验字符串实际长度。当输入字符串短于 8 字节时，读取操作越过 NUL 终止符进入相邻内存，越界读取的字节经 DES 加密后输出至 stdout，造成信息泄露。
- 已验证原语：RELATIVE_READ（动态验证：输入短字符串，解密输出发现包含非输入的相邻环境变量等内存数据）及 INFO_LEAK（攻击者控制密钥可解密恢复泄露字节）。
- 关键别名发现：argv[2] string pointer + 8 bytes，越界字节来源于相邻的环境变量或 argv 字符串区域，攻击者可通过设置环境变量影响读取内容。
- 修复建议：在读取 8 字节前使用 `strnlen` 校验 argv 字符串长度，或使用安全的边界拷贝函数处理输入。

漏洞 BUG-003：动态库搜索路径劫持
- CWE 分类：CWE-426 (Untrusted Search Path)
- 严重程度：高（环境可控时可导致任意代码执行）
- 漏洞位置：_start / 动态链接器加载阶段
- 漏洞详情：二进制文件未设置 RPATH 或 RUNPATH，动态链接器解析 NEEDED 库时 LD_LIBRARY_PATH 优先级高于系统路径。攻击者若控制执行环境，可注入木马版本的 libcrypto.so.1.1，在 main() 执行前通过 init_array 实现代码执行。
- 已验证原语：LIBRARY_SEARCH_PATH_HIJACK（静态验证：ELF 文件无 RPATH/RUNPATH 字段，依赖外部环境解析路径）。
- 关键别名发现：无
- 修复建议：在编译时通过链接器选项设置 RPATH/RUNPATH 绑定可信库绝对路径。

## 3. 利用链与后果
已验证端到端利用链（基于 BUG-002 信息泄露）：
1. 攻击者构造已知 8 字节 DES 密钥作为 argv[1]。
2. 攻击者构造短字符串（1-7 字节）作为 argv[2]。
3. 攻击者通过环境变量在相邻内存中布置特定标记数据。
4. 触发 `./target <key> <short_str>`，程序越界读取相邻内存。
5. 程序将包含越界数据的 8 字节明文进行 DES ECB 加密并输出至 stdout。
6. 攻击者捕获密文，使用已知密钥解密，成功恢复相邻内存中的泄露数据。

## 4. 方法论
分析路径：文件识别与安全防护侦察 (S1) → 逆向分析与漏洞根因定位 (S2) → 动态原语验证与 PoC 构造 (S3) → 端到端利用链实现 (S4)。

## 5. 产物路径
| 产物类型 | 路径 |
|---|---|
| 目标二进制 | `/work/workspace/0002-2020-2._Signature__II_-20260904-101906/target` |
| BUG-001 PoC | `/work/workspace/0002-2020-2._Signature__II_-20260904-101906/poc-BUG-001.py` |
| BUG-002 PoC | `/work/workspace/0002-2020-2._Signature__II_-20260904-101906/poc-BUG-002.py` |
| 最终利用脚本 | `/work/workspace/0002-2020-2._Signature__II_-20260904-101906/exploit.py` |