from pathlib import Path
from typing import Tuple
import os
import glob
import logging
from rich.console import Console
from rich.logging import RichHandler

console = Console(stderr=True)

def setup_logging(debug: bool = False) -> None:
    """Route all logging through rich. Tracebacks are only rendered in debug mode."""
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(message)s",
        handlers=[RichHandler(console=console, show_time=False, show_path=debug, rich_tracebacks=True)],
        force=True,
    )

def describe_exception(e: BaseException) -> str:
    """One-line, traceback-free description of an error for the user."""
    message = str(e).strip()
    if isinstance(e, AssertionError):
        # Our own validation failures: the message is written for the user already.
        return message or "assertion failed (run with --debug for details)"
    return f"{type(e).__name__}: {message}" if message else type(e).__name__

# pwntools ELF.arch value -> qemu-user binary name.
# Extend this if you start pwning other architectures.
QEMU_BY_ARCH = {
    "i386": "qemu-i386",
    "amd64": "qemu-x86_64",
    "arm": "qemu-arm",
    "thumb": "qemu-arm",
    "aarch64": "qemu-aarch64",
    "mips": "qemu-mips",
    "mips64": "qemu-mips64",
    "riscv32": "qemu-riscv32",
    "riscv64": "qemu-riscv64",
}

# Base names (without version/soname suffix) used to auto-discover a bundled
# libc/ld sitting next to the binary, when --libc/--ld aren't given explicitly.
LIBC_GLOBS = ["libc.so.6", "libc-*.so*", "libc.so*"]
LD_GLOBS = ["ld-linux*.so*", "ld-*.so*"]

def detect_arch(binary_path: Path) -> str:
    from pwn import ELF
    assert os.path.isfile(binary_path), f"file not found: {binary_path}"
    try:
        elf = ELF(str(binary_path), checksec=False)
    except Exception as e:
        # e.g. elftools' bare "Magic number does not match" for a non-ELF file.
        raise ValueError(f"{binary_path} is not a valid ELF file ({e})") from e
    return elf.arch

def qemu_binary_for_arch(arch):
    """Map a pwntools ELF.arch value (e.g. "i386"/"amd64") to its qemu-user binary name."""
    try:
        return QEMU_BY_ARCH[arch]
    except KeyError:
        raise ValueError(f"Unsupported arch {arch!r}; expected one of {sorted(QEMU_BY_ARCH)}")

def _find_sibling_matching_pattern(binary_path: str | None, patterns):
    """Return the first file matching one of `patterns` next to `binary_path`."""
    if binary_path is None: return None

    directory = os.path.dirname(os.path.abspath(binary_path)) or "."
    for pattern in patterns:
        matches = sorted(glob.glob(os.path.join(directory, pattern)))
        if matches:
            return matches[0]
    return None

def resolve_libc_ld(binary_path: str, libc=None, ld=None) -> Tuple[str, str]:
    """Resolve the libc/ld to run `binary_path` against: explicit paths win,
    otherwise auto-discover a bundled libc*.so*/ld-*.so* sitting next to it.
    """
    resolved_libc = (
        libc or
        _find_sibling_matching_pattern(binary_path, LIBC_GLOBS) or
        _find_sibling_matching_pattern(ld, LIBC_GLOBS)
    )
    resolved_ld = (
        ld or
        _find_sibling_matching_pattern(binary_path, LD_GLOBS) or
        _find_sibling_matching_pattern(libc, LD_GLOBS)
    )

    return resolved_libc, resolved_ld
