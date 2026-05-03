#!/usr/bin/env python3
"""
plocate 代理脚本 - 增强版文件搜索工具

功能：
1. 调用系统 plocate 命令进行搜索
2. 智能检测 plocate 版本（原版 vs 补丁版 v200）
3. 补丁版：直接解析数据库输出的文件元数据
4. 原版：实时读取文件系统元信息并格式化显示
5. 默认只显示文件名，带 -L/--long 时显示详细信息
6. 其他参数全部透传给底层 plocate

使用方法：
    plocate.py [OPTION]... PATTERN...

    # 只显示文件名（默认）
    plocate.py nginx

    # 显示详细信息（时间、大小、标志位）
    plocate.py -L nginx
    plocate.py --long nginx

    # 其他参数透传
    plocate.py -i -L -b nginx
    plocate.py -d /custom/path/plocate.db -L nginx
    plocate.py -c nginx
"""

import os
import shutil
import stat
import subprocess
import sys
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

# ============================================================
# 常量定义（与 C++ 代码保持一致）
# ============================================================
FLAG_DIR = 1 << 63
FLAG_SYMLINK = 1 << 62
FLAG_HARDLINK = 1 << 61
FLAG_HIDDEN = 1 << 60
FLAG_EXEC = 1 << 59
FLAGS_MASK = 0xFF00000000000000
SIZE_MASK = 0x00FFFFFFFFFFFFFF


# ============================================================
# 数据模型
# ============================================================
@dataclass
class FileMeta:
    """文件元数据结构"""
    path: str
    size: int          # 真实文件大小（低56位）
    mtime_sec: int     # 修改时间（秒级时间戳）
    is_dir: bool = False
    is_symlink: bool = False
    is_hardlink: bool = False
    is_hidden: bool = False
    is_executable: bool = False

    @property
    def mtime_dt(self) -> datetime:
        """将 mtime_sec 转换为 datetime 对象（UTC）"""
        return datetime.fromtimestamp(self.mtime_sec, tz=timezone.utc)

    @property
    def mtime_iso(self) -> str:
        """返回 ISO 格式的时间字符串"""
        return self.mtime_dt.strftime("%Y-%m-%d %H:%M:%S")

    @property
    def size_human(self) -> str:
        """返回人类可读的文件大小"""
        if self.is_dir:
            return "<DIR>"
        size = self.size
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size < 1024:
                return f"{size:.1f}{unit}" if unit != "B" else f"{size}B"
            size /= 1024
        return f"{size:.1f}PB"

    @property
    def flags_str(self) -> str:
        """返回标志位字符串表示"""
        flags = []
        if self.is_dir:
            flags.append("DIR")
        if self.is_symlink:
            flags.append("LINK")
        if self.is_hardlink:
            flags.append("HARDLINK")
        if self.is_hidden:
            flags.append("HIDDEN")
        if self.is_executable:
            flags.append("EXEC")
        return "|".join(flags) if flags else "FILE"

    def format_line(self, show_details: bool = False, null_delim: bool = False) -> str:
        """格式化输出单行"""
        delim = "\0" if null_delim else "\n"
        if show_details:
            return (
                f"{self.mtime_iso}  "
                f"{self.size_human:>10}  "
                f"[{self.flags_str:<12}]  "
                f"{self.path}"
            ) + delim.rstrip("\n")
        return self.path + delim.rstrip("\n")


# ============================================================
# 核心解析函数
# ============================================================
def parse_size_encoded(size_encoded: int) -> Dict[str, Any]:
    """解析编码后的 size 字段，提取真实大小和标志位"""
    return {
        "size": size_encoded & SIZE_MASK,
        "is_dir": (size_encoded & FLAG_DIR) != 0,
        "is_symlink": (size_encoded & FLAG_SYMLINK) != 0,
        "is_hardlink": (size_encoded & FLAG_HARDLINK) != 0,
        "is_hidden": (size_encoded & FLAG_HIDDEN) != 0,
        "is_executable": (size_encoded & FLAG_EXEC) != 0,
    }


def parse_plocate_line(line: str) -> Optional[FileMeta]:
    """
    解析 plocate 命令行输出的单行（元数据格式）。

    输入格式：
        SIZE_ENCODED_HEX(16) + MTIME_HEX(16) + '|' + PATH
    """
    if "|" not in line:
        # 纯路径格式（原版无元数据）
        if line and line.startswith("/"):
            return FileMeta(path=line, size=0, mtime_sec=0)
        return None

    parts = line.split("|")
    if len(parts) < 2:
        return None

    meta_hex = parts[0]
    if len(meta_hex) < 32:
        return None

    try:
        size_encoded = int(meta_hex[:16], 16)
        mtime_sec = int(meta_hex[16:32], 16)
    except ValueError:
        return None

    path = urllib.parse.unquote("|".join(parts[1:]))

    meta_info = parse_size_encoded(size_encoded)
    return FileMeta(
        path=path,
        size=meta_info["size"],
        mtime_sec=mtime_sec,
        is_dir=meta_info["is_dir"],
        is_symlink=meta_info["is_symlink"],
        is_hardlink=meta_info["is_hardlink"],
        is_hidden=meta_info["is_hidden"],
        is_executable=meta_info["is_executable"],
    )


def stat_file_meta(path: str) -> Optional[FileMeta]:
    """
    通过文件系统 stat 获取文件元信息（用于原版 plocate 兼容）。

    如果文件不存在或无法访问，返回 None。
    """
    try:
        st = os.lstat(path)
    except (OSError, FileNotFoundError, PermissionError):
        return None

    is_dir = stat.S_ISDIR(st.st_mode)
    is_symlink = stat.S_ISLNK(st.st_mode)
    is_exec = (st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)) != 0
    is_hidden = os.path.basename(path).startswith(".")
    is_hardlink = not is_dir and st.st_nlink > 1

    return FileMeta(
        path=path,
        size=st.st_size if not is_dir else 0,
        mtime_sec=int(st.st_mtime),
        is_dir=is_dir,
        is_symlink=is_symlink,
        is_hardlink=is_hardlink,
        is_hidden=is_hidden,
        is_executable=is_exec,
    )


# ============================================================
# plocate 版本检测
# ============================================================
_plocate_version_cache: Optional[str] = None


def get_plocate_version(plocate_bin: str) -> str:
    """获取 plocate 版本信息（带缓存）"""
    global _plocate_version_cache
    if _plocate_version_cache is not None:
        return _plocate_version_cache

    try:
        proc = subprocess.run(
            [plocate_bin, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        version = proc.stdout.strip() if proc.stdout else ""
        _plocate_version_cache = version
        return version
    except Exception:
        _plocate_version_cache = ""
        return ""


def is_metadata_plocate(plocate_bin: str) -> bool:
    """
    检测 plocate 是否为补丁版（支持元数据输出）。

    策略：
    1. 执行 plocate --version 检查版本字符串是否包含补丁标识
    2. 或者尝试搜索一个已知路径，检查输出格式是否包含元数据
    """
    version = get_plocate_version(plocate_bin)
    # 补丁版在版本字符串中包含特定标识
    if "metadata" in version.lower():
        return True

    # 更可靠的检测：尝试搜索一个系统路径，检查输出格式
    # 使用 /etc 目录下的一个常见文件作为测试
    try:
        proc = subprocess.run(
            [plocate_bin, "-l", "1", "passwd"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if proc.stdout:
            first_line = proc.stdout.strip().split("\n")[0]
            # 补丁版输出格式: HEX(32)|PATH
            # 原版输出格式: /path/to/file
            if "|" in first_line and len(first_line.split("|")[0]) >= 32:
                return True
    except Exception:
        pass

    return False


# ============================================================
# plocate 命令执行
# ============================================================
def find_plocate_binary() -> str:
    """查找系统 plocate 可执行文件"""
    candidates = [
        "plocate",
        "/usr/local/bin/plocate",
        "/usr/bin/plocate",
    ]
    for candidate in candidates:
        path = shutil.which(candidate)
        if path:
            return path
    raise FileNotFoundError("找不到 plocate 可执行文件，请确保已安装")


def run_plocate(plocate_args: List[str]) -> subprocess.Popen:
    """执行 plocate 命令并返回进程对象"""
    plocate_bin = find_plocate_binary()
    cmd = [plocate_bin] + plocate_args
    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


# ============================================================
# 输出处理
# ============================================================
def process_output(
    proc: subprocess.Popen,
    show_details: bool = False,
    null_delim: bool = False,
    count_only: bool = False,
    use_stat_fallback: bool = False,
) -> int:
    """
    处理 plocate 输出，解析元数据并格式化显示。

    返回匹配的文件数量。
    """
    count = 0

    if proc.stdout is None:
        return 0

    try:
        for line in proc.stdout:
            line = line.rstrip("\n\r")
            if not line:
                continue

            meta = parse_plocate_line(line)
            if meta is None:
                continue

            # 如果是纯路径格式（原版 plocate）且需要详细信息，实时 stat
            if use_stat_fallback and show_details and meta.size == 0 and meta.mtime_sec == 0:
                stat_meta = stat_file_meta(meta.path)
                if stat_meta:
                    meta = stat_meta

            count += 1

            if count_only:
                continue

            try:
                print(meta.format_line(show_details, null_delim), end="")
                if null_delim:
                    print("\0", end="")
                else:
                    print()
            except BrokenPipeError:
                # 输出被管道消费者关闭（如 head -n 5），优雅退出
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                return count

    except KeyboardInterrupt:
        # 用户按 Ctrl+C，立即终止子进程并退出
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
        raise

    # 等待进程结束并检查错误
    returncode = proc.wait()
    if returncode != 0 and returncode != -15 and returncode != -9:
        # 忽略 SIGTERM(-15) 和 SIGKILL(-9) 导致的退出码
        if proc.stderr:
            stderr_output = proc.stderr.read()
            if stderr_output:
                print(stderr_output, file=sys.stderr)

    if count_only:
        print(count)

    return count


# ============================================================
# 参数解析
# ============================================================
def parse_arguments() -> "ArgsNamespace":
    """
    解析命令行参数。

    策略：
    1. 提取我们关心的参数（-L/--long）
    2. 其余参数全部透传给 plocate
    """
    args = sys.argv[1:]

    show_details = False
    null_delim = False
    count_only = False
    verbose_version = False
    plocate_args = []

    i = 0
    while i < len(args):
        arg = args[i]

        # 我们的自定义参数：-L / --long（显示详细信息）
        if arg in ("-L", "--long"):
            show_details = True
            i += 1
            continue

        if arg in ("-0", "--null"):
            null_delim = True
            plocate_args.append(arg)
            i += 1
            continue

        if arg in ("-c", "--count"):
            count_only = True
            plocate_args.append(arg)
            i += 1
            continue

        if arg == "--verbose-version":
            verbose_version = True
            i += 1
            continue

        # 其他参数（包括原生的 -l LIMIT、-d DBPATH 等）直接透传
        plocate_args.append(arg)
        i += 1

    return ArgsNamespace(
        show_details=show_details,
        null_delim=null_delim,
        count_only=count_only,
        verbose_version=verbose_version,
        plocate_args=plocate_args,
    )


class ArgsNamespace:
    def __init__(
        self,
        show_details: bool,
        null_delim: bool,
        count_only: bool,
        verbose_version: bool,
        plocate_args: List[str],
    ):
        self.show_details = show_details
        self.null_delim = null_delim
        self.count_only = count_only
        self.verbose_version = verbose_version
        self.plocate_args = plocate_args


def print_help() -> None:
    """打印帮助信息"""
    help_text = """Usage: plocate.py [OPTION]... PATTERN...

A wrapper for plocate with enhanced metadata display.

Custom options:
  -L, --long             show detailed info (mtime, size, flags)
      --verbose-version  show plocate version and patch detection info

Plocate options (passed through):
  -b, --basename         search only the file name portion of path names
  -c, --count            print number of matches instead of the matches
  -d, --database DBPATH  search for files in DBPATH
  -i, --ignore-case      search case-insensitively
  -l, --limit LIMIT      stop after LIMIT matches
  -0, --null             delimit matches by NUL instead of newline
  -N, --literal          do not quote filenames, even if printing to a tty
  -r, --regexp           interpret patterns as basic regexps (slow)
      --regex            interpret patterns as extended regexps (slow)
  -w, --wholename        search the entire path name (default; see -b)
      --help             print this help
      --version          print version information

Examples:
  plocate.py nginx                    # show filenames only
  plocate.py -L nginx                 # show detailed info
  plocate.py -i -L -b nginx           # case-insensitive, basename, show details
  plocate.py -l 10 -L nginx           # limit 10 results, show details
  plocate.py -d /path/db -L nginx     # use custom database
  plocate.py -c nginx                 # count matches only
"""
    print(help_text)


# ============================================================
# 主入口
# ============================================================
def main() -> int:
    # 处理 --help 和 --version
    if "--help" in sys.argv:
        print_help()
        return 0

    if "--version" in sys.argv:
        try:
            proc = run_plocate(["--version"])
            stdout, stderr = proc.communicate()
            if stdout:
                print(stdout, end="")
            if stderr:
                print(stderr, file=sys.stderr, end="")
            return proc.returncode
        except FileNotFoundError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    # 解析参数
    args = parse_arguments()

    # 处理 --verbose-version
    if args.verbose_version:
        try:
            plocate_bin = find_plocate_binary()
            version = get_plocate_version(plocate_bin)
            is_metadata = is_metadata_plocate(plocate_bin)
            print(f"plocate binary: {plocate_bin}")
            print(f"version: {version}")
            print(f"metadata: {is_metadata}")
            return 0
        except FileNotFoundError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    # 检查是否有搜索模式
    if not args.plocate_args:
        print("Error: no pattern specified", file=sys.stderr)
        print_help()
        return 1

    # 检测 plocate 版本
    plocate_bin = find_plocate_binary()
    is_metadata = is_metadata_plocate(plocate_bin)

    # 如果使用 -L 但检测到原版 plocate，给出提示
    if args.show_details and not is_metadata:
        print(
            "# Note: vanilla plocate detected, metadata fetched via stat() in real-time",
            file=sys.stderr,
        )

    # 执行 plocate
    try:
        proc = run_plocate(args.plocate_args)
        process_output(
            proc,
            args.show_details,
            args.null_delim,
            args.count_only,
            use_stat_fallback=not is_metadata,
        )
        return proc.returncode
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
