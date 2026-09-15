"""LeanAgent 工具集。

各阶段从 tools.bintools 的 make_*_tools 工厂取子集（agent 在容器内直接执行，
工具实现是进程内 Python + subprocess 起外部命令，不再经 base64 转接）：
- S1：make_recon_tools（bin 工具减动态执行类）
- S2：make_semantic_tools（13 个纯静态工具）
- S3：make_verify_tools（全部 23 个）
- S4：make_exploit_tools（全部 23 个）
"""
