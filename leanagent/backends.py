"""执行 backend 与容器生命周期。

架构：容器挂载本项目目录到 /work，agent 进程跑在容器内，用 LocalShellBackend
直接在容器内执行 gdb/pwntools（无 docker exec 跨边界）。宿主侧用
start_container 起带挂载 + GLM key 的容器，用 exec_in_container 在容器内跑命令
（编译样本、启动 cli、验证）。

DockerSandbox（宿主跨边界模式，备用）保留：agent 跑在宿主时经 wsl docker exec 操控。
"""
from __future__ import annotations

import os
import posixpath
import re
import subprocess
from pathlib import Path

from deepagents.backends import LocalShellBackend
from deepagents.backends.protocol import (
    ExecuteResponse,
    FileDownloadResponse,
    FileUploadResponse,
)
from deepagents.backends.sandbox import BaseSandbox

CONTAINER_WORKDIR = "/work"

_PASSTHROUGH_ENV = (
    "DASHSCOPE_API_KEY", "ZHIPU_API_KEY", "GLM_API_KEY",
    "GLM_BASE_URL", "GLM_MODEL", "GRADER_MODEL", "LEANAGENT_MAX_ITERATIONS",
)

_PATH_RE = re.compile(r"^/[A-Za-z0-9_./\-]+$")
_MAX_OUTPUT_BYTES = 50_000


def _validate_path(path: str) -> None:
    if not path.startswith("/"):
        raise ValueError(f"path must be absolute (start with /): {path!r}")
    if ".." in path.split("/"):
        raise ValueError(f"path must not contain '..': {path!r}")
    if not _PATH_RE.match(path):
        raise ValueError(f"path has disallowed characters: {path!r}")


# --------------------------------------------------------------------------- #
# 容器内 backend（主用）：agent 跑在容器内，直接本地执行。
# --------------------------------------------------------------------------- #
def make_local_backend(root_dir: str = CONTAINER_WORKDIR) -> LocalShellBackend:
    """容器内用的 backend：execute 直接在容器本地跑（agent 已在容器内）。"""
    return LocalShellBackend(
        root_dir=root_dir,
        virtual_mode=False,  # 显式 False，避免 deprecation warn
        timeout=300,
        inherit_env=True,
        max_output_bytes=12_000,  # 工具结果进 LLM context 的保险上限（减 context 占用）
    )


# --------------------------------------------------------------------------- #
# 容器生命周期（宿主侧调用）
# --------------------------------------------------------------------------- #
def start_container(
    image: str | None = None,
    mount_host: str | Path | None = None,
) -> str:
    """宿主侧：起带挂载 + GLM key 的常驻容器，返回 container_id。

    -v 把本项目目录挂到 /work；-e 把宿主的 GLM key 等透传进容器。
    不加 --network=none：agent 在容器内要联网调 GLM（dashscope）。
    seccomp=unconfined：防默认 seccomp 误伤 PoC 的 syscall。
    """
    from leanagent import config

    image = image or config.IMAGE
    mount_host = Path(mount_host) if mount_host else config.MOUNT_HOST
    wsl_mount = win_to_wsl_path(str(mount_host))
    env_args: list[str] = []
    for k in _PASSTHROUGH_ENV:
        v = os.environ.get(k)
        if v:
            env_args += ["-e", f"{k}={v}"]
    p = subprocess.run(
        [
            "wsl", "docker", "run", "-d", "--rm",
            "--security-opt", "seccomp=unconfined",
            "-v", f"{wsl_mount}:/work",
            *env_args,
            image,
        ],
        capture_output=True,
        timeout=300,  # 含镜像不在时自动 pull 的时间
    )
    if p.returncode != 0:
        err = p.stderr.decode("utf-8", "replace") if p.stderr else ""
        raise RuntimeError(f"docker run failed (image={image}): {err.strip()[:500]}")
    cid = p.stdout.decode("utf-8", "replace").strip()
    if not cid:
        raise RuntimeError("docker run returned no container id")
    return cid


CONTAINER_NAME = "leanagent-pwn"


def ensure_container(
    image: str | None = None,
    mount_host: str | Path | None = None,
) -> str:
    """幂等：常驻容器 leanagent-pwn——running 则复用；stopped 则 start；不存在则创建。

    不 --rm：容器常驻，stop 后仍在（可 restart），后续所有 exec 复用同一容器，
    不每次 start/stop。
    """
    from leanagent import config

    image = image or config.IMAGE
    mount_host = Path(mount_host) if mount_host else config.MOUNT_HOST
    wsl_mount = win_to_wsl_path(str(mount_host))
    env_args: list[str] = []
    for k in _PASSTHROUGH_ENV:
        v = os.environ.get(k)
        if v:
            env_args += ["-e", f"{k}={v}"]

    # 检测容器是否已存在（docker inspect 返回 true/false 或空）
    insp = subprocess.run(
        ["wsl", "docker", "inspect", "-f", "{{.State.Running}}", CONTAINER_NAME],
        capture_output=True, timeout=30,
    )
    state = insp.stdout.decode("utf-8", "replace").strip()
    if insp.returncode == 0 and state in ("true", "false"):
        if state != "true":
            subprocess.run(["wsl", "docker", "start", CONTAINER_NAME],
                           capture_output=True, timeout=60)
        return CONTAINER_NAME

    # 不存在，创建（常驻，不 --rm）
    p = subprocess.run(
        ["wsl", "docker", "run", "-d", "--name", CONTAINER_NAME,
         "--security-opt", "seccomp=unconfined",
         "-v", f"{wsl_mount}:/work",
         *env_args, image],
        capture_output=True, timeout=300,
    )
    if p.returncode != 0:
        err = p.stderr.decode("utf-8", "replace") if p.stderr else ""
        raise RuntimeError(f"docker run failed (name={CONTAINER_NAME}): {err.strip()[:500]}")
    return CONTAINER_NAME


def stop_container(container_id: str = CONTAINER_NAME) -> None:
    """停止容器（不删除；常驻模式下一般不调用，仅显式清理时用）。"""
    subprocess.run(["wsl", "docker", "stop", container_id],
                   capture_output=True, timeout=60)


def exec_in_container(
    container_id: str,
    command: str,
    *,
    timeout: int = 600,
    workdir: str = CONTAINER_WORKDIR,
) -> tuple[str, int]:
    """在容器内跑命令（宿主发起，经 wsl docker exec）。返回 (output, exit_code)。"""
    p = subprocess.run(
        ["wsl", "docker", "exec", "-i", "-w", workdir, container_id, "sh", "-c", command],
        capture_output=True,
        timeout=timeout,
    )
    out = p.stdout.decode("utf-8", "replace") if p.stdout else ""
    err = p.stderr.decode("utf-8", "replace") if p.stderr else ""
    if err:
        out = (out + "\n[stderr] " + err) if out else ("[stderr] " + err)
    return out, p.returncode


# --------------------------------------------------------------------------- #
# 路径转换（宿主侧用）
# --------------------------------------------------------------------------- #
def win_to_wsl_path(win_path: str) -> str:
    """D:\\foo -> /mnt/d/foo（WSL 侧路径，如 docker bind mount 源）。"""
    p = win_path.replace("\\", "/")
    if len(p) >= 2 and p[1] == ":":
        return f"/mnt/{p[0].lower()}{p[2:]}"
    return p


def win_to_container_path(win_path: str | Path) -> str:
    """宿主 Windows 路径 -> 容器内 /work 相对路径（基于 MOUNT_HOST 映射）。"""
    from leanagent import config

    mount = Path(config.MOUNT_HOST).resolve()
    p = Path(win_path).resolve()
    try:
        rel = p.relative_to(mount)
    except ValueError:
        raise ValueError(
            f"{win_path} 不在挂载目录 {mount} 内，无法映射到容器。"
            f"设 LEANAGENT_MOUNT 环境变量覆盖该目录。"
        ) from None
    return "/work/" + str(rel).replace("\\", "/")


# --------------------------------------------------------------------------- #
# DockerSandbox（备用：agent 跑在宿主时，经 wsl docker exec 跨边界执行）
# --------------------------------------------------------------------------- #
class DockerSandbox(BaseSandbox):
    """经 `wsl docker exec` 在隔离容器内执行命令的 sandbox backend（备用）。"""

    def __init__(self, container_id: str, *, default_timeout: int = 300) -> None:
        self._cid = container_id
        self._default_timeout = default_timeout

    @property
    def id(self) -> str:
        return f"docker:{self._cid}"

    def execute(self, command: str, *, timeout: int | None = None) -> ExecuteResponse:
        to = timeout if timeout is not None else self._default_timeout
        try:
            p = subprocess.run(
                ["wsl", "docker", "exec", "-i", self._cid, "sh", "-c", command],
                capture_output=True, timeout=to,
            )
        except subprocess.TimeoutExpired:
            return ExecuteResponse(output=f"Error: timed out after {to}s", exit_code=124)
        out = p.stdout.decode("utf-8", "replace") if p.stdout else ""
        err = p.stderr.decode("utf-8", "replace") if p.stderr else ""
        if err:
            out = (out + "\n[stderr] " + err) if out else ("[stderr] " + err)
        if p.returncode != 0:
            out = out.rstrip() + f"\n\nExit code: {p.returncode}"
        truncated = False
        if len(out) > _MAX_OUTPUT_BYTES:
            out = out[:_MAX_OUTPUT_BYTES] + f"\n... [truncated at {_MAX_OUTPUT_BYTES} bytes]"
            truncated = True
        return ExecuteResponse(output=out or "<no output>", exit_code=p.returncode, truncated=truncated)

    def upload_files(self, files: list[tuple[str, bytes]]) -> list[FileUploadResponse]:
        results: list[FileUploadResponse] = []
        for path, content in files:
            try:
                _validate_path(path)
                parent = posixpath.dirname(path) or "/"
                p = subprocess.run(
                    ["wsl", "docker", "exec", "-i", self._cid, "sh", "-c",
                     f"mkdir -p {parent} && cat > {path}"],
                    input=content, capture_output=True, timeout=120,
                )
                if p.returncode != 0:
                    err = p.stderr.decode("utf-8", "replace") if p.stderr else "unknown"
                    results.append(FileUploadResponse(path=path, error=f"write_failed: {err}"))
                else:
                    results.append(FileUploadResponse(path=path))
            except Exception as e:  # noqa: BLE001
                results.append(FileUploadResponse(path=path, error=f"{type(e).__name__}: {e}"))
        return results

    def download_files(self, paths: list[str]) -> list[FileDownloadResponse]:
        results: list[FileDownloadResponse] = []
        for path in paths:
            try:
                _validate_path(path)
                p = subprocess.run(
                    ["wsl", "docker", "exec", "-i", self._cid, "cat", path],
                    capture_output=True, timeout=120,
                )
                if p.returncode != 0:
                    err = p.stderr.decode("utf-8", "replace") if p.stderr else "unknown"
                    if b"No such file" in (p.stderr or b"") or b"cannot" in (p.stderr or b""):
                        results.append(FileDownloadResponse(path=path, content=None, error="file_not_found"))
                    else:
                        results.append(FileDownloadResponse(path=path, content=None, error=err))
                else:
                    results.append(FileDownloadResponse(path=path, content=p.stdout))
            except Exception as e:  # noqa: BLE001
                results.append(FileDownloadResponse(path=path, content=None, error=f"{type(e).__name__}: {e}"))
        return results
