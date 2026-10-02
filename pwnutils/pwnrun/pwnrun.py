import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import logging
from pathlib import Path
from typing import Any
from pwnutils.utils import (
    resolve_libc_ld,
    detect_arch,
    qemu_binary_for_arch
)

logger = logging.getLogger(__name__)

def build_parser():
    parser = argparse.ArgumentParser(
        prog="pwnrun",
        description="Compile a C file with a cross-compiler matching a target libc's "
                    "arch, and run it against that exact libc/ld under qemu-user.",
    )
    parser.add_argument("source", help="path to the .c file to compile")
    parser.add_argument(
        "--libc", required=True,
        help="path to the target libc file (e.g. libc.so.6)",
    )
    parser.add_argument(
        "--ld", default=None,
        help="path to a matching dynamic loader (default: auto-detect an ld-*.so* in the "
             "same directory as --libc)",
    )
    parser.add_argument(
        "--out", default=None,
        help="path for the compiled binary (default: a temp file)",
    )
    parser.add_argument("--cc", default=None, help="override the cross-compiler to use")
    parser.add_argument("--no-run", action="store_true", help="just compile, don't run it afterward")
    parser.add_argument("exec_args", nargs=argparse.REMAINDER, help="arguments to pass to the compiled binary")
    return parser


# Extend this if you start pwning other architectures.
CC_BY_ARCH = {
    "i386": "i686-linux-gnu-gcc",
    "amd64": "x86_64-linux-gnu-gcc",
}

APT_PACKAGE_BY_ARCH = {
    "i386": "gcc-i686-linux-gnu",
    "amd64": "gcc-x86-64-linux-gnu",
}

def compile_sources(source: Path, cc: str, arch: str, out: str) -> Path:
    cc = cc or CC_BY_ARCH.get(arch)
    assert cc, f"no cross-compiler known for arch {arch!r}"
    assert shutil.which(cc), f"{cc!r} not found in PATH -- install it: sudo apt install {APT_PACKAGE_BY_ARCH.get(arch, cc)}"

    if out is None:
        _, filename = tempfile.mkstemp(suffix=".out")
        out_path = Path(filename)
    else:
        out_path = Path(out)

    cc_argv = [cc, "-g", "-no-pie", "-nostartfiles", "-o", str(out_path), str(source)]
    result = subprocess.run(cc_argv)
    assert result.returncode == 0, f"compilation failed"
    out_path.chmod(0o755)

    return out_path

def run_executable(executable: Path, libc_path: str, ld_path: str, arch: str, exec_args: Any) -> None:
    qemu = qemu_binary_for_arch(arch)
    assert shutil.which(qemu), f"{qemu!r} not found in PATH"

    qemu_argv = [qemu]
    if ld_path:
        # ld.so's --library-path takes a directory to search, not the libc file itself.
        libdir = os.path.dirname(os.path.abspath(libc_path))
        qemu_argv += [os.path.abspath(ld_path), "--library-path", libdir]
    qemu_argv += [str(executable.resolve())]
    qemu_argv += exec_args

    logger.info(f"running: {' '.join(qemu_argv)}")
    result = subprocess.call(qemu_argv)
    return result


def run(args: Any):
    source = Path(args.source)
    assert source.is_file(), f"source not found: {source}"

    assert os.path.isfile(args.libc), f"libc not found: {args.libc}"
    # Anchor ld auto-detection at the libc, not at the source file.
    libc_path, ld_path = resolve_libc_ld(binary_path=args.libc, libc=args.libc, ld=args.ld)
    arch = detect_arch(libc_path)

    executable = compile_sources(source, args.cc, arch, args.out)

    if args.no_run: return

    result = run_executable(executable, libc_path, ld_path, arch, args.exec_args)
    if not args.out: executable.unlink()
    sys.exit(result)
