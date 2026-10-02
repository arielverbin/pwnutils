# pwnutils

Small CLI for setting up cross-compile pwnable exercises, running or debugging them against the challenge's exact libc, under `qemu-user`. That means the same workflow on any host: an x86 challenge runs fine on an ARM machine.

```
pwnutils [--debug] {init,run,gdb} ...
```

| Module | What it does |
| --- | --- |
| `init` | Scaffolds a `pwn_<name>/` folder: copies the binary and libc, tries to unstrip the libc and fetch a matching `ld`, and writes an attack script template. |
| `run`  | Runs a binary against a given libc/ld. Given a `.c` file, it first cross-compiles it for the libc's arch. |
| `gdb`  | Starts the binary under qemu's gdbstub and attaches `gdb-multiarch`, with the binary's symbols loaded at their real address and a breakpoint on `main`. |

## Getting started

Install the system tools (Debian/Ubuntu):

```sh
sudo apt install qemu-user gdb-multiarch gcc-i686-linux-gnu gcc-x86-64-linux-gnu
```

Install pwnutils into a virtualenv:

```sh
python3 -m venv .pwnvenv && source .pwnvenv/bin/activate
pip install -e ./pwnutils
```

Then set up your first exercise:

```sh
pwnutils init applestore -b ./applestore --libc ./libc_32.so.6
cd pwn_applestore
./applestore_attack.py local -t      # launch it and drop straight into interactive mode
```

Write your exploit in `attack()` inside the generated script, then run it locally or remotely:

```sh
./applestore_attack.py local
./applestore_attack.py remote --host chall.example.com --port 10104
```

## Examples

Debug the exercise, stopping at `main` (libc and ld are picked up from the same folder):

```sh
pwnutils gdb ./applestore
pwnutils gdb --break handler ./applestore
```

Try out heap behaviour of that exact libc with a quick C sandbox:

```sh
pwnutils run --libc ./pwn_applestore/libc.so.6 ./sandbox/sandbox.c
```

Run a prebuilt binary against a libc, passing it arguments:

```sh
pwnutils run --libc ./pwn_applestore/libc.so.6 ./pwn_applestore/applestore arg1 arg2
```

## Notes

- **Supported compilers.** `run` knows the cross-compilers for `i386` and `amd64`. For other arches, pass one with `--cc`.
