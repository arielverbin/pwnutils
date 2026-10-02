import argparse
import os
from datetime import datetime
from pwn import context, log, process, remote
from pwnutils.utils import (
    QEMU_BY_ARCH,
    resolve_libc_ld,
    qemu_binary_for_arch
)

class BasePwnAttacker:
    """Base class for pwn exercise attacker scripts.

    Subclasses must:
      - set EXPLOIT_NAME (str) -- also used as the default local binary name
      - set BINARY_ARCH (str)  -- a key of QEMU_BY_ARCH, e.g. "amd64"/"i386"
      - override attack()

    Subclasses may override build_parser() to add exercise-specific CLI flags,
    e.g.:

        @classmethod
        def build_parser(cls):
            parser = super().build_parser()
            group = parser.add_argument_group(cls.EXPLOIT_NAME)
            group.add_argument("--chunk-size", type=int, default=24, help="...")
            return parser
    """

    EXPLOIT_NAME = None
    BINARY_ARCH = None
    DEFAULT_REMOTE = None

    # ---- CLI ---------------------------------------------------------

    @classmethod
    def build_parser(cls):
        name = cls.EXPLOIT_NAME or cls.__name__
        parser = argparse.ArgumentParser(description=f"{name} Attacker")
        parser.add_argument("--verbose", action="store_true", help="verbose (debug) pwntools logging")

        subparsers = parser.add_subparsers(dest="mode", required=True, help="Execution mode")

        test_kwargs = dict(
            action="store_true",
            help="drop into an interactive session right after launch",
        )

        p_local = subparsers.add_parser("local", help="Run the binary locally under qemu-user")
        p_local.add_argument(
            "-b", "--binary", default=cls.EXPLOIT_NAME,
            help=f"path to target binary (default: ./{cls.EXPLOIT_NAME} in the current directory)",
        )
        p_local.add_argument(
            "--libc", default=None,
            help="path to a libc to run against (default: auto-detect a libc*.so* next to the binary)",
        )
        p_local.add_argument(
            "--ld", default=None,
            help="path to a matching dynamic loader (default: auto-detect an ld-*.so* next to the binary)",
        )
        p_local.add_argument("-t", "--test", **test_kwargs)

        p_remote = subparsers.add_parser("remote", help="Connect to a remote host")
        p_remote.add_argument("-t", "--test", **test_kwargs)
        if cls.DEFAULT_REMOTE:
            p_remote.add_argument("--host", default=cls.DEFAULT_REMOTE[0], help="remote host")
            p_remote.add_argument("--port", type=int, default=cls.DEFAULT_REMOTE[1], help="remote port")
        else:
            p_remote.add_argument("--host", required=True, help="remote host")
            p_remote.add_argument("--port", type=int, required=True, help="remote port")

        return parser

    def _log_startup(self, args):
        desc = f"Exploit {self.EXPLOIT_NAME} - Attack Script"
        info = {"DATE": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

        test_suffix = "/TEST" if args.test else ""
        if args.mode == "local":
            info["MODE"] = f"LOCAL{test_suffix}"
            info["BINARY"] = args.binary
            info["ARCH"] = self.BINARY_ARCH
        else:
            info["MODE"] = f"REMOTE{test_suffix}"
            info["HOST"] = f"{args.host}:{args.port}"

        known = {"mode", "binary", "libc", "ld", "test", "host", "port", "verbose"}
        for key, value in vars(args).items():
            if key not in known:
                info[key.upper()] = value

        print("=" * 72)
        print(desc)
        for key, value in info.items():
            print(f"{key}:\t\t{value}")
        print("=" * 72, end="\n\n")

    # ---- setup -----------------------------------------------------------

    def __init__(self, args):
        self.args = args
        self.mode = args.mode
        context.log_level = "debug" if args.verbose else "info"
        self._log_startup(args)

        if self.mode == "local":
            self.binary = args.binary
            context.binary = self.binary
            self.p = self._start_local(args)
        elif self.mode == "remote":
            self.binary = getattr(args, "binary", None)
            self.p = remote(args.host, args.port)
        else:
            raise ValueError(f"Unknown mode {self.mode!r}")

        self.test_only = args.test

    @classmethod
    def _qemu_binary(cls):
        if not cls.BINARY_ARCH:
            raise ValueError(f"{cls.__name__}.BINARY_ARCH must be set (one of {sorted(QEMU_BY_ARCH)})")
        try:
            return qemu_binary_for_arch(cls.BINARY_ARCH)
        except ValueError:
            raise ValueError(
                f"Unsupported BINARY_ARCH {cls.BINARY_ARCH!r} on {cls.__name__}; "
                f"expected one of {sorted(QEMU_BY_ARCH)}"
            )

    def _start_local(self, args):
        qemu = self._qemu_binary()

        libc, ld = resolve_libc_ld(self.binary, args.libc, args.ld)
        argv = [qemu]
        if ld:
            libdir = os.path.dirname(os.path.abspath(libc or ld))
            argv += [os.path.abspath(ld), "--library-path", libdir]
        argv += [os.path.abspath(self.binary)]

        log.info(f"Launching: {' '.join(argv)}")
        return process(argv)

    # ---- override these ----------------------------------------------

    def attack(self):
        raise NotImplementedError(f"{type(self).__name__} must implement attack()")

    def interactive(self):
        self.p.interactive()

    # ---- post-exploit sanity check ------------------------------------

    def post_exploit(self):
        """Confirm the attack actually landed a shell by running a few
        commands and checking their output. Prints them on success; raises
        RuntimeError if the shell doesn't look real.
        """
        commands = [b"uname -a", b"date", b"whoami", b'cat /home/`whoami`/flag']
        outputs = {}
        for cmd in commands:
            self.p.sendline(cmd)
            outputs[cmd.decode()] = self.p.recv(timeout=2).decode(errors="replace").strip()

        if "Linux" not in outputs["uname -a"]:
            raise RuntimeError(
                f"post-exploit sanity check failed. The attack likely didn't land a shell"
            )

        log.success("Attack succeeded!")
        log.success('-----------------')
        for cmd, output in outputs.items():
            log.success(f"{cmd.upper()}: {output!r}")
        log.success('-----------------')
        return outputs
