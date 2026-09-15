"""通用二进制分析工具集（各 LLM 阶段 S1-S4 按需子集使用）。

agent 直接跑在容器内（LocalShellBackend = 直接 subprocess），工具实现是
进程内 Python 辅助函数 + subprocess 起外部命令（objdump/gdb/ROPgadget 等）。
不再经 base64 转接（那是 Windows 宿主时代的 docker exec 遗产）。
各阶段经 make_*_tools 取子集（如 S2 静态化只留纯静态工具）。
"""
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import tempfile

from langchain_core.tools import tool


# ===========================================================================
# 进程内辅助函数（原 _XXX_SCRIPT 脚本的直接 Python 化）
# ===========================================================================

# ---- run_script 输出摘要（最小过滤 + key evidence 前置）----

def _summarize(data: bytes, max_chars: int) -> str:
    txt = data.decode("utf-8", errors="replace")
    keep, noise, evidence = [], 0, []
    for ln in txt.splitlines():
        s = ln.strip()
        # ★最小过滤：只滤三类纯噪音（curses 警告 / [x] debug / [DEBUG] recv/send dump）
        if s.startswith(("[x]", "[DEBUG]Recv", "[DEBUG]Sent", "Warning: _curses", "Terminal features")) or "setupterm" in s:
            noise += 1
            continue
        # 关键证据行（shell 回显/成功标记）单独收集——超 max_chars 截断后仍前置展示
        if "uid=" in s or "LEANAGENT_SUCCESS" in s or "flag{" in s:
            evidence.append(ln)
        keep.append(ln)
    if noise:
        keep.append(f"(... {noise} noise lines dropped: [x]/[DEBUG]/curses)")
    res = "\n".join(keep)
    if len(res) > max_chars:
        res = res[:max_chars // 2] + f"\n(... middle truncated, {len(res)} chars total ...)\n" + res[-max_chars // 2:]
    if evidence:
        res = "--- key evidence ---\n" + "\n".join(evidence) + "\n--- rest ---\n" + res
    return res or "(empty)"


def _run_script_impl(path: str, timeout_s: int, max_chars: int) -> str:
    # LLM 可能写错路径（实测 0000-2020-4 vs 0004-2020-4）——
    # cwd 指向不存在目录时 subprocess 直接 FileNotFoundError 裸异常崩主进程
    if not os.path.isfile(path):
        return f"[ERROR] 脚本不存在: {path}（检查路径拼写）"
    env = dict(os.environ)
    env["TERM"] = "xterm"
    env["PWNLIB_NOTERM"] = "1"
    try:
        r = subprocess.run([sys.executable, "-u", path], capture_output=True,
                           timeout=timeout_s, env=env, cwd=os.path.dirname(path) or ".")
        out, err, rc = r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired as e:
        out = e.stdout or b""
        err = e.stderr or b""
        rc = -124
    parts = [f"rc={rc}", "--- stdout (summarized) ---", _summarize(out, max_chars)]
    err_s = _summarize(err, max_chars)
    if err_s != "(empty)":
        parts += ["--- stderr (summarized) ---", err_s]
    if rc == -124:
        parts.append(f"[TIMEOUT] killed after {timeout_s}s —— 脚本卡住：查 recv 同步点/输入序列/未 close 的进程，修脚本别加 timeout。")
    return "\n".join(parts)


# ---- check_byte：gdb 断点读任意地址 ----

def _check_byte_impl(binary: str, addr: str, nbytes: int, stdin_data: str) -> str:
    cmds = ["set pagination off", "b *main", "run", f"x/{nbytes}bx {addr}"]
    args = ["gdb", "-q", "-batch"]
    for c in cmds:
        args += ["-ex", c]
    args += ["--args", binary]
    try:
        if stdin_data:
            r = subprocess.run(args, capture_output=True, timeout=20, input=stdin_data.encode("latin-1", errors="replace"), preexec_fn=_gdb_preexec)
        else:
            r = subprocess.run(args, capture_output=True, timeout=20, preexec_fn=_gdb_preexec)
        out = (r.stdout + b"\n" + r.stderr).decode("latin-1")
        hits = [ln for ln in out.splitlines()
                if ln.strip().startswith("0x") and (":" in ln) and ("0x" in ln.split(":", 1)[1])]
        if hits:
            res = [f"bytes at {addr}:"]
            res += [h for h in hits[:nbytes // 8 + 2]]
            vals = []
            for h in hits:
                for tok in h.split("\t")[1:]:
                    tok = tok.strip()
                    if tok.startswith("0x"):
                        vals.append(int(tok, 16))
            if vals:
                nl = [hex(v) for v in vals if v == 0x0a]
                un = [hex(v) for v in vals if v == 0x00]
                res.append(f"newline(0x0a) bytes: {nl or 'none'} | NUL(0x00) bytes: {un or 'none'}")
                if nl:
                    res.append("[POST-WRITE-CHECK-WARN] 含换行字节——写后检查会把 *(target+N)==0x0a 替换/触发分支，"
                               "调整写入长度 N 避开，或先写到可控缓冲区。")
            return "\n".join(res)
        return "未取到字节——地址可能无效/进程未到断点。gdb 尾部输出:\n" + out[-800:]
    except subprocess.TimeoutExpired:
        return "[TIMEOUT] gdb 20s —— 进程阻塞等输入（给 stdin 参数驱动到断点）。"


# ---- got_plt / libc_offsets / elf_plt_got：ELF 解析（pwntools）----

def _got_plt_impl(binary: str) -> str:
    p = subprocess.run(["objdump", "-R", binary], capture_output=True, text=True, timeout=60)
    relocs = []
    for l in p.stdout.splitlines():
        s = l.strip()
        # 匹配两种格式：offset 十六进制带 0x 前缀（旧工具），或 16 位补零（如 0000000000003d58）
        m = re.match(r"(0x[0-9a-f]{4,}|[0-9a-f]{16})\s+(\S+)\s+(\S+)", s)
        if m and m.group(2) != "TYPE":
            relocs.append({"offset": m.group(1), "type": m.group(2), "value": m.group(3)})
    return json.dumps(relocs, ensure_ascii=False)


def _libc_offsets_impl(libc_path: str, syms_str: str) -> str:
    from pwn import ELF
    libc = ELF(libc_path, checksec=False)
    syms = syms_str.split(",") if syms_str else []
    res = {}
    for s in syms:
        try:
            res[s] = hex(libc.symbols[s])
        except Exception:
            pass
    return json.dumps(res, ensure_ascii=False)


def _elf_plt_got_impl(binary: str, syms_str: str) -> str:
    from pwn import ELF
    elf = ELF(binary, checksec=False)
    syms = syms_str.split(",") if syms_str else []
    res = {"plt": {}, "got": {}, "symbols": {}}
    for s in syms:
        try:
            res["plt"][s] = hex(elf.plt[s])
        except Exception:
            pass
        try:
            res["got"][s] = hex(elf.got[s])
        except Exception:
            pass
        try:
            res["symbols"][s] = hex(elf.symbols[s])
        except Exception:
            pass
    return json.dumps(res, ensure_ascii=False)


# ---- cfg：angr 控制流图 ----

def _cfg_impl(binary: str) -> str:
    try:
        import angr
        p = angr.Project(binary, auto_load_libs=False)
        cfg = p.analyses.CFGFast()
        cg = cfg.kb.callgraph
        funcs = []
        for fn in list(cfg.kb.functions.values())[:60]:
            node = fn.addr
            callees = []
            if node in cg:
                for succ in list(cg.successors(node))[:10]:
                    cf = cfg.kb.functions.get(succ)
                    callees.append(cf.name if cf and cf.name else hex(succ))
            funcs.append({"name": fn.name or hex(fn.addr), "addr": hex(fn.addr),
                          "blocks": len(fn.block_addrs_set), "calls": callees})
        return json.dumps(funcs, ensure_ascii=False)
    except Exception as e:
        return json.dumps([{"error": repr(e)[:200]}], ensure_ascii=False)


# ---- probe_io steps：pwntools 交互序列 ----

# probe_io 在【独立子进程】跑（写临时 python 脚本 + subprocess）：
# target 崩溃 / pwntools 异常时只死子进程，agent 进程完全隔离
# （实测：agent 线程内跑 process，target SIGSEGV 曾连带 agent Abort）。
_PROBE_WORKER = r'''
import json, sys
from pwn import process, context
context.log_level = "critical"
binary, steps_json = sys.argv[1], sys.argv[2]
steps = json.loads(steps_json) if steps_json else []
out = []
def clip(s, head=300, tail=200):
    if len(s) <= head + tail + 20: return s
    return s[:head] + f"...(omitted {len(s) - head - tail} chars)... " + s[-tail:]
try:
    p = process(binary)
    for st in steps:
        ru = st.get("recv_until", "")
        if ru:
            data = p.recvuntil(ru.encode("latin-1", errors="replace"), timeout=3)
            out.append("RECV: " + clip(repr(data)))
        sd = st.get("send", "")
        if sd:
            p.sendline(sd.encode("latin-1", errors="replace"))
            out.append("SEND: " + repr(sd))
    try:
        rest = p.recv(timeout=2)
        if rest:
            out.append("RECV_TAIL: " + clip(repr(rest)))
    except Exception:
        pass
    try: p.close()
    except Exception: pass
except Exception as e:
    out.append(f"PROBE_ERROR: {type(e).__name__}: {str(e)[:200]}")
print("\n".join(out))
'''


def _probe_steps_impl(binary: str, steps_json: str) -> str:
    import subprocess as _sp
    import tempfile as _tf
    with _tf.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write(_PROBE_WORKER)
        script = f.name
    try:
        r = _sp.run(
            [sys.executable, script, binary, steps_json],
            capture_output=True, text=True, timeout=60,
        )
        out = (r.stdout or "").strip()
        err = (r.stderr or "").strip()
        if r.returncode != 0:
            # 子进程崩了（target 连带 / pwntools 异常）——agent 不受影响
            tail = "\n".join(err.splitlines()[-3:])
            return (out + f"\n[PROBE_EXIT rc={r.returncode}] " + tail[:400]).strip()
        return out or "(no output)"
    except _sp.TimeoutExpired:
        return "[PROBE_TIMEOUT] 60s 超时（子进程已杀）"
    finally:
        try:
            os.unlink(script)
        except OSError:
            pass


# ---- gdb 系列 ----

# GDB 子进程资源限制：0021 实测 GDB 分析崩溃/寄存器可吃 15GB RSS 直接 OOM-kill 主进程。
# RLIMIT_AS 4GB 卡死虚拟内存上限（超限 GDB 自身报错而非吃光宿主内存），
# RLIMIT_CORE 0 禁止 core dump（/work 曾积 53 个 core.* 残留）。
def _gdb_preexec():
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (4 << 30, 4 << 30))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _gdb_crash_impl(binary: str, payload_file: str, max_chars: int) -> str:
    cmds = ["set pagination off", f"run < {payload_file}", "info registers", "x/16xg $sp", "bt"]
    args = ["gdb", "-q", "-batch"]
    for c in cmds:
        args += ["-ex", c]
    args += ["--args", binary]
    try:
        # timeout 30s（原 60s 与题目 alarm(60) 同长——alarm 触发后 GDB 还在吃内存做收尾分析）
        r = subprocess.run(args, capture_output=True, timeout=30, preexec_fn=_gdb_preexec)
        out = (r.stdout + b"\n" + r.stderr).decode("latin-1")
    except subprocess.TimeoutExpired:
        out = "(gdb timed out)"
    res = {}
    m = re.search(r"Program received signal (\w+)[,:]([^\n]*)\n\s*(0x[0-9a-f]+) in", out)
    if m:
        res["signal"] = m.group(1)
        res["crash_addr"] = m.group(3)
        res["crash_loc"] = m.group(2).strip()
    else:
        m2 = re.search(r"Program terminated with signal (\w+)", out)
        if m2:
            res["signal"] = m2.group(1) + " (terminated)"
    res["raw_tail"] = out[-max(1, max_chars):]
    return json.dumps(res, ensure_ascii=False)


def _find_offset_impl(binary: str, length: int, max_chars: int) -> str:
    from pwn import cyclic, context
    context.log_level = "error"
    payload = cyclic(length)
    try:
        r = subprocess.run([binary], input=payload, capture_output=True, timeout=15)
        core_hint = r.stderr.decode("latin-1", "replace")[:max_chars]
        # 解析 PC（常见格式：SIGSEGV at 0x6161616j / 0x6161... in ??）
        m = re.search(r"(0x[0-9a-f]{6,16})", core_hint)
        if m:
            pc = int(m.group(1), 16)
            try:
                off = cyclic_find(pc)
                return f"PC=0x{pc:x}  OFFSET={off}"
            except Exception as ex:
                return f"cyclic_find error: {ex}"
        out = f"PC=UNKNOWN  ARCH={context.arch}"
        if core_hint:
            out += "\nstderr_tail: " + core_hint[-500:]
        return out
    except subprocess.TimeoutExpired:
        return "timeout (no crash within 15s)"
    except Exception as e:
        return f"error: {e}"


def _gdb_impl(binary: str, timeout_s: float, max_chars: int, stdin_data: str, cmds: list) -> str:
    stdin_file = ""
    if stdin_data:
        fd, stdin_file = tempfile.mkstemp(suffix=".bin")
        # LLM 可能传含非 latin-1 字符的 payload——errors=replace 防裸异常崩主进程
        os.write(fd, stdin_data.encode("latin-1", errors="replace"))
        os.close(fd)
    args = ["gdb", "-q", "-batch"]
    for c in cmds:
        if c.strip() == "run" and stdin_file:
            args += ["-ex", f"run < {stdin_file}"]
        else:
            args += ["-ex", c]
    args += ["--args", binary]
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout_s, preexec_fn=_gdb_preexec)
        out = (r.stdout + b"\n" + r.stderr).decode("latin-1")
        result = out[-max_chars:]
        has_bp = any(c.strip().startswith(("b ", "break", "b*", "tbreak")) for c in cmds)
        if has_bp:
            bp_hit = "Breakpoint 1," in out
            exited_normally = "exited normally" in out or "exited with code" in out
            if not bp_hit and (exited_normally or "Inferior" not in out):
                result += ("\n[GDB-HINT] 断点未命中。你的 stdin 序列没有驱动程序执行到断点所在代码路径。"
                           "不要用相同参数重调 gdb_run（结果不会变）——先检查："
                           "1) 菜单选项序列是否正确（对照 probe_io 学到的菜单 I/O 时序）；"
                           "2) scanf 期望的类型/格式（%lld 要十进制数、%llu 要无符号）；"
                           "3) stdin 是否足够长（程序可能在等待更多输入时被 EOF 截断）。"
                           "修改 stdin 序列后再调 gdb_run。")
        return result
    except subprocess.TimeoutExpired:
        return (f"gdb timed out ({timeout_s:.0f}s)。多半是程序 run 后阻塞——检查 stdin 是否提供了"
                "驱动程序到断点的输入序列；命令序列若含等待输入的交互命令也会卡。"
                "修改 commands/stdin 后重试，相同参数重调结果不变。")
    finally:
        if stdin_file and os.path.exists(stdin_file):
            os.unlink(stdin_file)


# ---- gadget 系列 ----

def _rop_impl(binary: str, keyword: str, max_results: int) -> str:
    try:
        p = subprocess.run(["ROPgadget", "--binary", binary], capture_output=True, text=True, timeout=120)
        lines = p.stdout.splitlines()
    except Exception as e:
        return json.dumps({"error": str(e)})
    if keyword:
        lines = [l for l in lines if keyword.lower() in l.lower()]
    return "\n".join(lines[:max(1, max_results)])


def _ret_impl(binary: str) -> str:
    try:
        p = subprocess.run(["ROPgadget", "--binary", binary, "--only", "ret"], capture_output=True, text=True, timeout=120)
        out = []
        for l in p.stdout.splitlines():
            m = re.match(r"(0x[0-9a-f]+)\s*:\s*ret\s*$", l.strip())
            if m:
                out.append({"addr": m.group(1), "insn": "ret"})
        return json.dumps(out, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---- run_binary：跑二进制 + xxd 风格输出 + 泄露段标注 ----

def _run_binary_impl(binary: str, stdin: bytes, timeout: float) -> str:
    try:
        p = subprocess.run([binary], input=stdin, capture_output=True, timeout=timeout,
                           cwd=os.path.dirname(binary) or ".")
        rc, out, err = p.returncode, (p.stdout or b""), (p.stderr or b"")
    except subprocess.TimeoutExpired as e:
        out = e.stdout if isinstance(e.stdout, (bytes, bytearray)) else b""
        err = e.stderr if isinstance(e.stderr, (bytes, bytearray)) else b""
        rc = -124
    MAX = 1500
    out_t = out[:MAX]
    parts = [f"rc={rc}  stdout_len={len(out)}" + ("  [TRUNCATED to 1500]" if len(out) > MAX else ""),
             "--- stdout (hex + ascii per line, 16B/行) ---"]
    for off in range(0, len(out_t), 16):
        chunk = out_t[off:off + 16]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        parts.append(f"{off:04x}  {hx:<47}  |{asc}|")
    # 泄露检测：非打印字节段（含 ≥2 个非打印、允许夹可打印）
    sus = []
    i, n = 0, len(out_t)
    while i < n:
        if out_t[i] >= 0x80 or (out_t[i] < 0x20 and out_t[i] not in (0x0a, 0x0d, 0x09)):
            st, j, nonprint, last_np = i, i, 0, -1
            while j < n:
                c = out_t[j]
                if c >= 0x80 or (c < 0x20 and c not in (0x0a, 0x0d, 0x09)):
                    nonprint += 1
                    last_np = j
                    j += 1
                elif 0x20 <= c < 0x7f:
                    j += 1
                else:
                    break
                if last_np >= 0 and j - last_np > 3:
                    break
            seg_end = min(j, (last_np + 4) if last_np >= 0 else j)
            if nonprint >= 2 and seg_end - st >= 2:
                sus.append((st, seg_end - st))
            i = max(j, i + 1)
        else:
            i += 1
    if sus:
        parts.append("--- [LEAK CANDIDATES] (非打印字节段=潜在泄露/二进制数据) ---")
        for st, ln in sus[:8]:
            seg = out_t[st:st + ln]
            ctx0, ctx1 = max(0, st - 4), min(len(out_t), st + ln + 4)
            parts.append(f"  offset {st:04x} len {ln}: {seg.hex()}  (context: {out_t[ctx0:ctx1].hex()})")
    err_s = err[:600].decode("latin-1", "replace").strip()
    if err_s:
        parts.append("--- stderr ---")
        parts.append(err_s)
    if rc == -124:
        parts.append("[TIMEOUT] 程序未在 timeout 内退出（可能在等更多输入）——查 stdin 序列长度。")
    return "\n".join(parts)


# ===========================================================================
# 工具集（backend 参数保留签名兼容——实际不再使用，agent 在容器内直接执行）
# ===========================================================================

def make_bin_tools(backend):
    @tool
    def checksec(binary: str) -> str:
        """检查二进制保护机制（NX/PIE/Canary/RELRO/FORTIFY/SHSTK/IBT）。"""
        b = shlex.quote(binary)
        r = backend.execute(f"checksec --file={b} 2>&1")
        return r.output

    @tool
    def elf_info(binary: str) -> str:
        """读 ELF 头/段/动态链接信息（file + readelf -h/-l）。"""
        b = shlex.quote(binary)
        r = backend.execute(
            f"file {b} && echo '===ELF HEADER===' && readelf -h {b} "
            f"&& echo '===SEGMENTS===' && readelf -l {b}"
        )
        return r.output

    @tool
    def identify_libc(binary: str) -> str:
        """识别二进制依赖的 libc 路径与版本字符串（ldd + strings）。"""
        b = shlex.quote(binary)
        cmd = (
            f"ldd {b} 2>/dev/null | grep -i libc; "
            "echo '===LIBC VERSION==='; "
            f"LIBC=$(ldd {b} 2>/dev/null | grep -o '/[^ ]*libc[^ ]*' | head -1); "
            'if [ -n "$LIBC" ]; then strings "$LIBC" | grep -E "GNU C Library|GLIBC [0-9]" | head -3; fi'
        )
        r = backend.execute(cmd)
        return r.output

    @tool
    def disassemble(binary: str, function: str = "", lines: int = 100) -> str:
        """反汇编（objdump -d -M intel --no-show-raw-insn，只留地址+助记符，去字节码省 context）。
        function: 只看某函数（如 'main' 'win'）；为空则看开头 lines 行。"""
        b = shlex.quote(binary)
        n = max(1, int(lines))
        if function:
            cmd = f"objdump -d -M intel --no-show-raw-insn {b} | awk '/<{function}>:/,/^$/' | head -{n}"
        else:
            cmd = f"objdump -d -M intel --no-show-raw-insn {b} | head -{n}"
        r = backend.execute(cmd)
        return r.output

    @tool
    def got_plt(binary: str) -> str:
        """列 GOT 重定位表。返回 JSON [{offset, type, value}]。"""
        return _got_plt_impl(binary)

    @tool
    def symbols(binary: str, filter: str = "", max_lines: int = 60) -> str:
        """列符号表（nm）。filter 过滤符号名；max_lines 返回行数上限（默认 60，可调大）。"""
        b = shlex.quote(binary)
        ml = max(int(max_lines), 1)
        if filter:
            r = backend.execute(f"nm {b} 2>/dev/null | grep -iE {shlex.quote(filter)} | head -{ml}")
        else:
            r = backend.execute(f"nm {b} 2>/dev/null | head -{ml}")
        return r.output

    @tool
    def sections(binary: str) -> str:
        """列 ELF 段表（readelf -S）。"""
        b = shlex.quote(binary)
        r = backend.execute(f"readelf -S {b}")
        return r.output

    @tool
    def libc_offsets(libc_path: str, symbols: str) -> str:
        """查 libc 符号偏移。返回 JSON {symbol: offset}。
        libc_path: libc 路径（identify_libc 获取）。
        symbols: **必填**，逗号分隔的符号名（如 "puts,system,environ"）——你指定查什么，无默认列表。
        要找 '/bin/sh' 字符串用 list_strings(libc_path, filter='/bin/sh')。"""
        return _libc_offsets_impl(libc_path, symbols)

    @tool
    def elf_plt_got(binary: str, symbols: str) -> str:
        """查二进制 PLT/GOT/symbols 地址。返回 JSON {plt:{}, got:{}, symbols:{}}。
        symbols: **必填**，逗号分隔（如 "puts,main,gets"）——你指定查什么，无固定列表。
        先用 symbols(binary) 或 nm 看有哪些符号，再指定。"""
        return _elf_plt_got_impl(binary, symbols)

    @tool
    def probe_io(binary: str, input: str = "", input_hex: str = "", payload_file: str = "", steps: str = "", max_lines: int = 40) -> str:
        """跑二进制探 I/O（banner/prompt/回显/交互时序），xxd 或 RECV/SEND 展示。写 PoC 前先 probe。

        === 使用须知（防浪费预算）===
        1. 【先 probe 一次学菜单时序，再写 gdb_run 的 stdin / PoC 脚本】——
           gdb_run 断点未命中多半是 stdin 菜单序列不对，回来对照本工具的 RECV/SEND。
        2. 同一参数【禁止重复调用】——结果不会变。改 steps/input 再调。
        3. steps 模式所有 recv 自带 timeout（3s/2s），绝不 hang。

        四种喂法（互斥，按优先 steps>payload_file>input_hex>input）：
        - `steps`: JSON 交互序列 `[{"recv_until":"<prompt>","send":"<input>"},...]`——
          pwntools 交互式：每步 recv_until 匹配串再 sendline，捕获全程 RECV/SEND。
        - `payload_file`: `cat payload_file | binary`（cat 结束→stdin EOF→read 提前返回）——阻塞型 read 非阻塞探测。
        - `input_hex`: hex 字符串，解码为二进制 pipe——二进制安全。
        - `input`: 简单文本（`echo input | binary`），非二进制。
        max_lines: xxd 输出行数上限（默认 40，可调大）。
        """
        b = shlex.quote(binary)
        ml = max(int(max_lines), 1)
        if steps:
            return _probe_steps_impl(binary, steps)
        if payload_file:
            pf = shlex.quote(payload_file)
            r = backend.execute(f"cat {pf} | {b} 2>&1 | xxd | head -{ml}")
        elif input_hex:
            hx = shlex.quote(input_hex)
            r = backend.execute(
                f'python3 -c "import sys; sys.stdout.buffer.write(bytes.fromhex({hx}))" | {b} 2>&1 | xxd | head -{ml}'
            )
        else:
            inp = shlex.quote(input or "AAAA")
            r = backend.execute(f"echo {inp} | {b} 2>&1 | xxd | head -{ml}")
        return r.output

    @tool
    def make_payload(parts: list, file_path: str) -> str:
        """构造 payload 写到 file_path，返回**路径 + 长度 + 32 字节预览**（不返回全 hex——长 payload 会占 LLM 上下文）。

        parts = [[data_str, repeat], ...]，每项 data_str 重复 repeat 次后**顺序拼接**。
        data_str 支持 \\xHH / \\n / \\t 等转义（如 "88\\x00\\xbdd" → 字节 88 00 bd 64...）。
        file_path: **必填**，写入路径（workspace 下，从 ## Binary 路径算 dirname + 唯一名，避免多任务并发冲突）。
        返回路径（配 `probe_io(payload_file=<路径>)` 喂给二进制）+ 长度 + 前 32 字节 hex 预览。
        """
        import codecs
        payload = b""
        try:
            for item in parts:
                data_str = str(item[0])
                repeat = int(item[1]) if len(item) > 1 else 1
                raw = codecs.decode(data_str, 'unicode_escape').encode('latin-1')
                payload += raw * max(0, repeat)
        except Exception as e:
            return f"make_payload error: {e}"
        try:
            with open(file_path, "wb") as f:
                f.write(payload)
        except Exception as e:
            return f"write error: {e}"
        return f"{file_path} len={len(payload)} preview_hex={payload[:32].hex()}"

    @tool
    def global_vars(binary: str, max_lines: int = 40) -> str:
        """查全局变量布局（readelf -sW，OBJECT 符号地址+大小）。max_lines 返回行数上限（默认 40，可调大）。"""
        b = shlex.quote(binary)
        r = backend.execute(f"readelf -sW {b} | awk '$4==\"OBJECT\"' | head -{max(int(max_lines), 1)}")
        return r.output

    @tool
    def cfg(binary: str) -> str:
        """用 angr 构建控制流图（CFG），返回函数列表 + 调用关系 JSON。
        [{name, addr, calls:[...]}]——供 S2 semantic 判控制流/函数调用。"""
        return _cfg_impl(binary)

    # === debug 工具（gdb）===
    @tool
    def gdb_run_crash(binary: str, payload_file: str, max_chars: int = 300) -> str:
        """用 gdb 跑二进制喂 payload 文件，返回崩溃现场：信号/寄存器/栈顶 16 项/bt。
        binary: 绝对路径；payload_file: payload 文件路径。max_chars: raw_tail 字符上限（默认 300，可调大）。"""
        return _gdb_crash_impl(binary, payload_file, max(int(max_chars), 1))

    @tool
    def find_offset(binary: str, length: int = 300, max_chars: int = 2500) -> str:
        """cyclic pattern 自动找返回地址偏移。返回 PC 值与偏移字节数。max_chars: 无 crash 时输出尾部字符上限。"""
        return _find_offset_impl(binary, max(1, int(length)), max(1, int(max_chars)))

    @tool
    def gdb_run(binary: str, commands: str, stdin: str = "", timeout: int = 10, max_chars: int = 4000) -> str:
        """跑自定义 gdb 命令序列（commands 分号分隔）。

        === 使用须知（防浪费预算）===
        1. 断点未命中时【禁止用相同参数重调本工具】（结果不会变）——
           先看输出里的 [GDB-HINT]，修正 stdin 菜单序列/格式后再调。
        2. stdin 是程序的 stdin 输入（如 "3\\n18446744073709551608\\n"）——
           自动 pipe 给程序（`run < stdin_file`），避免 gdb 交互式 hang。
           ★交互式程序（菜单驱动）run 前想清楚：stdin 给足驱动到断点的输入序列
           （对照 probe_io 学到的菜单时序，scanf 格式要对：%lld 十进制 / %llu 无符号）；
           忘了给 stdin → run 阻塞 → 超时白等。
        3. 命令里不要放交互式命令（如等待输入的 continue）。
        timeout: gdb 整体执行超时秒数（默认 10——零等待纪律；断点命中的正常
           调试 10s 足够。只有确实需要长跑的程序才调大，如 30）。
        max_chars 输出字符上限（默认 4000，可调大）。
        例：gdb_run(binary, "b *edit_cookie+0xb6; run; x/20gx $rdi", stdin="3\\n-8\\nAAAA")
        """
        cmds = [c.strip() for c in commands.split(";") if c.strip()]
        return _gdb_impl(binary, float(timeout), max(500, int(max_chars)), stdin, cmds)

    @tool
    def check_crash_log(binary: str, max_lines: int = 10) -> str:
        """查内核崩溃日志（dmesg）看 segfault/general protection fault 的 ip/地址。需 root。max_lines 返回行数上限。"""
        name = shlex.quote(binary.split("/")[-1])
        r = backend.execute(f"dmesg 2>&1 | grep -iE '{name}|segfault|general protection' | tail -{max(int(max_lines), 1)}")
        return r.output

    # === gadget 工具（ROPgadget）===
    @tool
    def search_rop_gadgets(binary: str, keyword: str = "", max_results: int = 40) -> str:
        """搜 ROP gadget（ROPgadget）。keyword 过滤；max_results 返回上限（默认 40，可调大）。"""
        return _rop_impl(binary, keyword, max(1, int(max_results)))

    @tool
    def find_ret_gadget(binary: str) -> str:
        """找纯 ret gadget（栈对齐用）。返回 JSON [{addr, insn}]，insn 严格 'ret'。"""
        return _ret_impl(binary)

    @tool
    def list_strings(binary: str, min_len: int = 4, filter: str = "", max_lines: int = 60) -> str:
        """列二进制可见字符串。**建议先无 filter 一次看全**，不要逐个 filter 探索（浪费工具预算）。
        filter: 只含此关键字的串；空=全列。max_lines: 返回行数上限（默认 60，可调大如 200）。
        只在全列表太长需缩小时才用 filter。"""
        b = shlex.quote(binary)
        cmd = f"strings -n {max(int(min_len), 1)} {b}"
        if filter:
            cmd += f" | grep -iF {shlex.quote(filter)}"
        r = backend.execute(cmd + f" | head -{max(int(max_lines), 1)}")
        return r.output

    @tool
    def run_binary(binary: str, stdin: str = "", stdin_hex: str = "", timeout: int = 10) -> str:
        """跑二进制喂 stdin 管道（subprocess.run，服务端 timeout 强制 kill——**绝不 hang**）。PoC 验证首选。

        === 使用须知 ===
        1. 同一 (binary, stdin, timeout) 【禁止重复调用】——结果不会变。
           结果不对就改 stdin/参数，不要原样重调浪费预算。
        2. ★禁用 execute 跑 `python -c` 内联 pwntools（recv 无 timeout 会 hang）——
           跑二进制一律用本工具。
        3. === pwntools 使用禁令 ===（write_file 写独立 PoC 脚本时同样适用）：
           禁止调用 p.interactive() 或任何阻塞式交互方法——会永久阻塞导致超时。
           替代：p.sendline(payload) 后立即 p.recvline() / p.recvall(timeout=5)；
           所有 pwntools I/O 必须带 timeout 参数（建议 ≤10 秒）；
           验证 shell 用 p.sendline(b"id; cat flag*; exit") + p.recvall(timeout=10)。
        4. === 零等待原则 ===：正常验证不应有 >20s 的等待。
           证据取完立即 p.close()/p.kill()，不要 poll(True) 等程序自然退出、
           不要等程序自身的 alarm(60)（exit -14/275=SIGALRM 是防挂机保护，
           不是要验证的行为）。脚本卡 >20s = recv 同步点/输入序列有问题，
           修脚本而不是加长 timeout。
        binary: 二进制路径；stdin: 文本（\\n/\\xHH 转义按 latin-1 解）；stdin_hex: hex（二进制安全，与 stdin 互斥优先）；
        timeout: 秒（默认 10，上限 15；超时 rc=-124）。返回 rc + stdout(hex+ascii, 截断 1500) + stdout_len + stderr(截断 600)。"""
        import codecs
        if stdin_hex:
            try:
                data = bytes.fromhex(stdin_hex)
            except ValueError as e:
                return f"run_binary error (bad hex): {e}"
        elif stdin:
            try:
                data = codecs.decode(stdin, "unicode_escape").encode("latin-1", errors="replace")
            except Exception as e:
                return f"run_binary error (bad stdin): {e}"
        else:
            data = b""
        to = max(1, min(int(timeout), 15))
        return _run_binary_impl(binary, data, to)

    @tool
    def run_script(path: str, timeout: int = 30, max_chars: int = 3000) -> str:
        """跑 exploit/poc 脚本（专用，替代 execute 跑 python3）。

        === 比裸 execute 的优势 ===
        1. 自动设 TERM=xterm + PWNLIB_NOTERM=1——消 _curses/terminfo 噪音；
        2. 最小过滤输出：只滤纯噪音（[x] debug / [DEBUG] recv/send / curses 警告），
           其余全保留；关键证据行（uid=/LEANAGENT_SUCCESS/flag{）超长截断时
           仍前置展示（--- key evidence --- 段）
           （=== 开头）+ Traceback/Error 及上下文，丢 debug 噪音行；
        3. 超时强杀返回 rc=-124 + [TIMEOUT] 提示（查 recv 同步点，别加 timeout 硬等）；
        4. cwd 自动切到脚本所在目录（脚本里的相对路径直接工作）。
        path: 脚本绝对路径；timeout: 秒（默认 30，上限 60）；
        max_chars: 摘要上限（默认 3000）。返回 rc + stdout/stderr 摘要。
        【跑脚本一律用本工具，不要 execute 拼命令】。"""
        return _run_script_impl(path, max(5, min(int(timeout), 60)), max(500, min(int(max_chars), 10000)))

    @tool
    def check_byte(binary: str, addr: str, nbytes: int = 8, stdin: str = "") -> str:
        """读目标二进制进程内任意地址的 N 字节（gdb 一条龙）。

        === 用途：写大 payload 前的"写后检查"预检 ===
        程序的读入函数常在 read 返回后检查/改写写入区末尾字节
        （如 *(target+N) 的换行/NUL 处理）。写大结构（伪造 FILE/ROP 链/
        堆 chunk）前，用本工具查 target+N 处的既有字节：
        - 若含 0x0a（换行）→ 写入会被改写/触发分支，返回 [POST-WRITE-CHECK-WARN]；
        - 若不可读 → 写入后崩溃。
        binary: 二进制路径；addr: 运行时绝对地址 0x..（PIE 需先泄 base）；
        nbytes: 读几字节（默认 8）；stdin: 驱动进程到断点的输入（可空）。
        在 main 断点处 dump（查写入前的既有内容）。"""
        return _check_byte_impl(binary, addr, int(nbytes), stdin)

    return [checksec, elf_info, identify_libc, disassemble, got_plt, symbols, sections,
            libc_offsets, elf_plt_got, probe_io, global_vars, cfg, make_payload,
            gdb_run_crash, find_offset, gdb_run, check_crash_log,
            search_rop_gadgets, find_ret_gadget, list_strings, run_binary,
            run_script, check_byte]
