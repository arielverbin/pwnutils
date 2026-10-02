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

# The cross-compiler's crt1.o calls __libc_start_main@GLIBC_2.34. Older libcs
# don't export that version, so against them we skip the start files and link
# this minimal _start instead: it passes argc/argv/envp to main, aligns the
# stack as the ABI requires, and calls exit() with main's return value.
MODERN_CRT_GLIBC_VERSION = b"GLIBC_2.34"

START_STUB_BY_ARCH = {
    "i386": """
    .text
    .globl _start
    .type _start, @function
_start:
    xorl  %ebp, %ebp
    movl  (%esp), %eax              # argc
    leal  4(%esp), %ecx             # argv
    leal  8(%esp,%eax,4), %edx      # envp = argv + argc + 1
    andl  $-16, %esp
    subl  $4, %esp                  # 4 + 3 pushed args keeps esp 16-aligned at the call
    pushl %edx
    pushl %ecx
    pushl %eax
    call  main
    movl  %eax, (%esp)
    call  exit
    hlt
    .section .note.GNU-stack,"",@progbits
""",
    "amd64": """
    .text
    .globl _start
    .type _start, @function
_start:
    xorl  %ebp, %ebp
    movl  (%rsp), %edi              # argc
    leaq  8(%rsp), %rsi             # argv
    leaq  8(%rsi,%rdi,8), %rdx      # envp = argv + argc + 1
    andq  $-16, %rsp
    call  main
    movl  %eax, %edi
    call  exit
    hlt
    .section .note.GNU-stack,"",@progbits
""",
}

def libc_supports_modern_crt(libc_path: str) -> bool:
    """True if the libc exports the __libc_start_main version the toolchain's crt1.o needs."""
    return MODERN_CRT_GLIBC_VERSION in Path(libc_path).read_bytes()

def resolve_compiler(cc: str, arch: str) -> str:
    cc = cc or CC_BY_ARCH.get(arch)
    assert cc, f"no cross-compiler known for arch {arch!r}"
    assert shutil.which(cc), f"{cc!r} not found in PATH -- install it: sudo apt install {APT_PACKAGE_BY_ARCH.get(arch, cc)}"
    return cc

def resolve_out_path(out: str) -> Path:
    if out is not None:
        return Path(out)
    _, filename = tempfile.mkstemp(suffix=".out")
    return Path(filename)

def write_start_stub(arch: str, directory: str) -> Path:
    stub = START_STUB_BY_ARCH.get(arch)
    assert stub, f"no _start stub for arch {arch!r}"
    stub_path = Path(directory) / "pwnrun_start.S"
    stub_path.write_text(stub)
    return stub_path

def compile_sources(source: Path, cc: str, arch: str, out: str, libc_path: str) -> Path:
    cc = resolve_compiler(cc, arch)
    out_path = resolve_out_path(out)
    cc_argv = [cc, "-g", "-no-pie", "-o", str(out_path), str(source)]

    with tempfile.TemporaryDirectory() as stub_dir:
        if not libc_supports_modern_crt(libc_path):
            logger.warning(
                "libc predates %s: linking a minimal _start instead of crt1.o. "
                "__libc_start_main is skipped, so the program's constructors/destructors won't run",
                MODERN_CRT_GLIBC_VERSION.decode(),
            )
            cc_argv += ["-nostartfiles", str(write_start_stub(arch, stub_dir))]

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

    executable = compile_sources(source, args.cc, arch, args.out, libc_path)

    if args.no_run: return

    result = run_executable(executable, libc_path, ld_path, arch, args.exec_args)
    if not args.out: executable.unlink()
    sys.exit(result)
