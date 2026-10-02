import argparse
import logging
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator, List, Optional
from pwnutils.utils import (
    resolve_libc_ld,
    detect_arch,
    qemu_binary_for_arch
)

logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pwngdb",
        description="Run a binary under qemu-user's gdbstub and attach gdb-multiarch, "
                    "stopped at the target binary's own code.",
    )
    parser.add_argument("binary", help="path to the target binary")
    parser.add_argument(
        "--libc", default=None,
        help="path to a libc to run against (default: auto-detect a libc*.so* next to the binary)",
    )
    parser.add_argument(
        "--ld", default=None,
        help="path to a matching dynamic loader (default: auto-detect an ld-*.so* next to the binary)",
    )
    parser.add_argument("--gdb", default="gdb-multiarch", help="gdb binary to launch (default: gdb-multiarch)")
    parser.add_argument(
        "--break", dest="break_symbol", default="main", metavar="SYMBOL",
        help="stop at this symbol in the target binary once it's mapped (default: main)",
    )
    parser.add_argument(
        "--no-break", dest="break_symbol", action="store_const", const=None,
        help="don't automatically break in the target binary (still loads its relocated symbols)",
    )
    parser.add_argument("exec_args", nargs=argparse.REMAINDER, help="arguments to pass to the binary")
    return parser


# How long to give qemu-user to open its gdbstub socket before gdb connects.
# qemu opens the listening socket before executing a single guest instruction,
# so a short fixed delay is enough. Probe-connecting instead would consume the
# gdbstub's single client slot before gdb itself gets to connect.
GDBSTUB_STARTUP_DELAY = 0.3
QEMU_TERMINATE_TIMEOUT = 3

# Runs inside gdb (via `-x`) after `target remote` has connected. Finds the
# real runtime load address of BINARY and stops at BREAK_SYMBOL there.
DISCOVERY_SCRIPT_TEMPLATE = '''
import gdb

BINARY = {binary!r}
TEXT_OFFSET = {text_offset!r}
BREAK_SYMBOL = {break_symbol!r}


def _mapped_base(path):
    try:
        maps = gdb.execute("info proc map", to_string=True)
    except gdb.error:
        return None
    for line in maps.splitlines():
        if line.rstrip().endswith(path):
            try:
                return int(line.split()[0], 16)
            except (ValueError, IndexError):
                pass
    return None


def _wait_for_mapping(path):
    # Not mapped yet -- we're likely sitting at ld.so's own entry point, before
    # it has mapped the real binary. Break on ld.so's rendezvous function
    # (called once the main executable's link-map entry exists) to catch the
    # earliest moment the real binary is mapped.
    try:
        discovery_bp = gdb.Breakpoint("_dl_debug_state", internal=True)
    except gdb.error:
        return None

    base = None
    for _ in range(20):
        base = _mapped_base(path)
        if base is not None:
            break
        try:
            gdb.execute("continue", to_string=True)
        except gdb.error:
            break
    discovery_bp.delete()
    return base


def _run():
    gdb.execute("set breakpoint pending off", to_string=True)

    base = _mapped_base(BINARY)
    if base is None:
        base = _wait_for_mapping(BINARY)

    if base is None:
        print("[pwngdb] could not locate {{}} in the process memory map; "
              "leaving you at the current stop".format(BINARY))
        return

    text_addr = base + TEXT_OFFSET
    gdb.execute('add-symbol-file "{{}}" {{}}'.format(BINARY, hex(text_addr)), to_string=True)
    print("[pwngdb] loaded symbols for {{}} at {{}} (base {{}})".format(
        BINARY, hex(text_addr), hex(base)))

    if BREAK_SYMBOL:
        try:
            gdb.execute("break {{}}".format(BREAK_SYMBOL))
            gdb.execute("continue")
        except gdb.error as e:
            print("[pwngdb] could not break on {{!r}}: {{}}".format(BREAK_SYMBOL, e))


_run()
'''


def text_offset_from_load(binary_path: Path) -> int:
    """Offset of .text from the start of the binary's lowest PT_LOAD segment.

    For a PIE binary the lowest PT_LOAD's vaddr is 0, so this is just .text's
    link-time address. A non-PIE binary is loaded at its absolute link-time
    address, so subtracting elf.load_addr here (and adding the observed runtime
    base back inside gdb) keeps the same "base + offset" formula correct for
    both, without double-counting the base.
    """
    from pwn import ELF
    elf = ELF(str(binary_path), checksec=False)
    section = elf.get_section_by_name(".text")
    text_addr = section.header["sh_addr"] if section is not None else 0
    return text_addr - elf.load_addr

def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def assert_in_path(tool: str) -> None:
    assert shutil.which(tool), f"{tool!r} not found in PATH"

def build_qemu_argv(qemu: str, port: int, binary_path: Path,
                    libc: Optional[str], ld: Optional[str], exec_args: List[str]) -> List[str]:
    qemu_argv = [qemu, "-g", str(port)]
    if ld:
        libdir = str(Path(libc or ld).resolve().parent)
        qemu_argv += [str(Path(ld).resolve()), "--library-path", libdir]
    qemu_argv += [str(binary_path.resolve())]
    qemu_argv += exec_args
    return qemu_argv

def build_gdb_argv(gdb: str, port: int, script_path: Path) -> List[str]:
    # The binary is deliberately NOT passed as gdb's exec-file: gdb detects the
    # actually running image (ld.so, if any) from the remote target, and the
    # discovery script registers the binary's symbols at their relocated
    # address. Passing both leaves gdb with two conflicting `main` symbols, and
    # the wrong (unrelocated) one tends to be hit first.
    return [gdb, "-q", "-ex", f"target remote :{port}", "-x", str(script_path)]

@contextmanager
def discovery_script(binary_path: Path, break_symbol: Optional[str]) -> Generator[Path, None, None]:
    """Write the gdb discovery script to a temp file, removed on exit."""
    script = DISCOVERY_SCRIPT_TEMPLATE.format(
        binary=str(binary_path.resolve()),
        text_offset=text_offset_from_load(binary_path),
        break_symbol=break_symbol,
    )
    with tempfile.NamedTemporaryFile(mode="w", suffix="_pwngdb.py", delete=False) as script_file:
        script_file.write(script)
    script_path = Path(script_file.name)
    try:
        yield script_path
    finally:
        script_path.unlink(missing_ok=True)

def stop_qemu(qemu_proc: subprocess.Popen) -> None:
    if qemu_proc.poll() is not None:
        return
    qemu_proc.terminate()
    try:
        qemu_proc.wait(timeout=QEMU_TERMINATE_TIMEOUT)
    except subprocess.TimeoutExpired:
        qemu_proc.kill()

@contextmanager
def qemu_gdbstub(qemu_argv: List[str]) -> Generator[subprocess.Popen, None, None]:
    """Launch qemu-user with its gdbstub enabled, terminated on exit."""
    logger.debug(f"running: {' '.join(qemu_argv)}")
    # Detach qemu into its own session so Ctrl+C at the terminal, which goes to
    # the whole foreground process group, does NOT reach it. Otherwise qemu's
    # default SIGINT handler kills it out from under gdb. gdb stays in the
    # foreground group and turns Ctrl+C into a remote "interrupt" request.
    qemu_proc = subprocess.Popen(qemu_argv, start_new_session=True)
    try:
        time.sleep(GDBSTUB_STARTUP_DELAY)
        assert qemu_proc.poll() is None, f"{qemu_argv[0]} exited early with code {qemu_proc.returncode}"
        yield qemu_proc
    finally:
        stop_qemu(qemu_proc)

def run_gdb(gdb_argv: List[str]) -> int:
    logger.debug(f"running: {' '.join(gdb_argv)}")
    # Ignore SIGINT in this wrapper while gdb owns the foreground, so a Ctrl+C
    # inside gdb doesn't tear qemu down from under it.
    old_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        return subprocess.call(gdb_argv)
    finally:
        signal.signal(signal.SIGINT, old_handler)


def run(args: Any):
    binary_path = Path(args.binary)
    assert binary_path.is_file(), f"binary not found: {binary_path}"

    arch = detect_arch(binary_path)
    qemu = qemu_binary_for_arch(arch)
    assert_in_path(args.gdb)
    assert_in_path(qemu)

    libc, ld = resolve_libc_ld(str(binary_path), args.libc, args.ld)
    port = free_port()
    logger.debug(f"arch={arch} port={port}")

    qemu_argv = build_qemu_argv(qemu, port, binary_path, libc, ld, args.exec_args)
    with discovery_script(binary_path, args.break_symbol) as script_path:
        with qemu_gdbstub(qemu_argv):
            run_gdb(build_gdb_argv(args.gdb, port, script_path))
