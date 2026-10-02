import argparse
import re
import logging
import shutil
from pwnutils.utils import detect_arch
from pathlib import Path
from typing import Any

logger = logging.getLogger("pwninit")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pwninit",
        description="Scaffold a new pwn exercise folder ready to exploit under qemu-user.",
    )

    parser.add_argument("pwn_name", help="exercise name; must be a valid Python identifier and directory name")
    parser.add_argument("-b", "--binary", required=True, help="path to the target binary to pwn")
    parser.add_argument("-l", "--libc", default=None, help="path to a given matching libc (optional)")
    parser.add_argument("-o", "--out-dir", default=".", help="where to create pwn_<name>/ (default: cwd)")
    parser.add_argument("--force", action="store_true", help="overwrite an existing pwn_<name> directory")
    parser.add_argument(
        "--skip-libc-fetch", action="store_true",
        help="copy the libc as-is; don't try to unstrip it or fetch a matching ld",
    )
    return parser


ATTACK_SCRIPT_TEMPLATE = '''#!/usr/bin/env python3
from pwn import *
from pwnutils.pwninit import BasePwnAttacker


class {class_name}(BasePwnAttacker):
    EXPLOIT_NAME = "{name}"
    BINARY_ARCH = "{arch}"

    # Uncomment to add exercise-specific CLI flags (available as self.args.<name>):
    # @classmethod
    # def build_parser(cls):
    #     parser = super().build_parser()
    #     group = parser.add_argument_group(cls.EXPLOIT_NAME)
    #     group.add_argument("--chunk-size", type=int, default=24, help="...")
    #     return parser

    def attack(self):
        # Have fun pwning {name}!
        pass


if __name__ == "__main__":
    argparser = {class_name}.build_parser()
    attacker = {class_name}(argparser.parse_args())
    if not attacker.test_only:
        attacker.attack()
        attacker.post_exploit()
    attacker.interactive()
'''


def validate_exercise_name(name: str) -> None:
    assert name, "exercise name must not be empty"
    assert re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$").match(name), (
        f"exercise name {name!r} is not a valid Python identifier "
        "(must match [A-Za-z_][A-Za-z0-9_]*) -- rename it yourself, e.g. "
        f"{re.sub(r'[^A-Za-z0-9_]', '_', name)!r}"
    )

def setup_pwn_folder(out_dir: Path, pwn_name: str, force: bool) -> Path:
    dest_dir = out_dir / f"pwn_{pwn_name}"
    if dest_dir.exists():
        assert force, f"{dest_dir} already exists (pass --force to overwrite)"
    else:
        dest_dir.mkdir(parents=True)

    return dest_dir

def unstrip_libc(libc_path: Path) -> None:
    import pwnlib.libcdb as libcdb
    try:
        if libcdb.unstrip_libc(str(libc_path)):
            logger.info("unstripped libc debug symbols")
        else:
            logger.warning("could not unstrip libc (no debug info found) -- continuing with the stripped libc")
    except Exception as e:
        logger.warning("libc unstrip failed: %s", e)

def fetch_dynamic_loader(pwn_dir: Path, libc_path: Path) -> None:
    import pwnlib.libcdb as libcdb
    try:
        libs_dir = libcdb.download_libraries(str(libc_path), unstrip=False)
    except Exception as e:
        libs_dir = None
        logger.warning("fetching matching libraries failed: %s", e)

    if not libs_dir:
        logger.warning("could not auto-fetch a matching dynamic loader")
        return

    ld_candidates = sorted(Path(libs_dir).glob("ld-*"))
    if not ld_candidates:
        logger.warning("fetched libraries but found no ld-* file in %s", libs_dir)
        return

    ld_src = ld_candidates[0]
    ld_dest = pwn_dir / ld_src.name
    shutil.copy2(ld_src, ld_dest)
    ld_dest.chmod(0o755)
    logger.info("fetched dynamic loader -> %s", ld_dest.name)

def setup_pwn_libc(pwn_dir: Path, *, libc_path: Path, skip_libc_fetch: bool) -> None:
    """ Copy the libc into pwn_dir.
    Best-effort: unstrip it, try to fetch a matching dynamic loader. """

    dest_libc = pwn_dir / "libc.so.6"
    shutil.copy2(libc_path, dest_libc)
    dest_libc.chmod(0o644)
    logger.info("copied libc -> %s", dest_libc.name)
    if skip_libc_fetch:
        logger.warning("skipping libc unstrip and dynamic loader fetch")
        return

    import pwnlib.libcdb as libcdb
    unstrip_libc(dest_libc)
    fetch_dynamic_loader(pwn_dir, libc_path)

def setup_pwn_binary(pwn_name: str, pwn_dir: Path, *, binary_path: Path) -> None:
    assert binary_path.is_file(), f"binary not found: {binary_path}"
    dest_binary = pwn_dir / pwn_name
    shutil.copy2(binary_path, dest_binary)
    dest_binary.chmod(0o755)
    logger.info("copied binary -> %s", dest_binary.name)

def setup_pwn_template(pwn_dir: Path, pwn_name: str, arch: str) -> None:
    # avoid .capitalize() which also lowers the rest of the letters
    class_name = pwn_name[0].upper() + pwn_name[1:] + "Attacker"
    attack_script = pwn_dir / f"{pwn_name.lower()}_attack.py"
    attack_script.write_text(
        ATTACK_SCRIPT_TEMPLATE.format(class_name=class_name, name=pwn_name, arch=arch)
    )
    attack_script.chmod(0o755)
    logger.info("wrote %s (class %s)", attack_script.name, class_name)


def run(args: Any):
    validate_exercise_name(args.pwn_name)
    pwn_dir = setup_pwn_folder(Path(args.out_dir), args.pwn_name, args.force)
    setup_pwn_binary(args.pwn_name, pwn_dir, binary_path=Path(args.binary))

    if args.libc is not None:
        setup_pwn_libc(pwn_dir, libc_path=Path(args.libc), skip_libc_fetch=args.skip_libc_fetch)

    arch = detect_arch(args.binary)
    logger.info("detected arch: %s", arch)
    setup_pwn_template(pwn_dir, args.pwn_name, arch)

    logger.info("DONE -- %s/", pwn_dir)
    return pwn_dir