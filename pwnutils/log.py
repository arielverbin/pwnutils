import logging
from rich.console import Console
from rich.logging import RichHandler

console = Console(stderr=True)

OWN_LOGGER = "pwnutils"
DEPENDENCY_LOG_LEVEL = logging.WARNING

class DependencyLevelFilter(logging.Filter):
    """Pass our own records at whatever level is enabled; dependencies' only from DEPENDENCY_LOG_LEVEL up.

    Needed as a handler filter (not just a root level) because a logger level only
    applies where a record is created: pwnlib sets its logger to level 1, so its
    DEBUG records would otherwise propagate straight into our handler.
    """
    def filter(self, record: logging.LogRecord) -> bool:
        return record.name.split(".")[0] == OWN_LOGGER or record.levelno >= DEPENDENCY_LOG_LEVEL

def quiet_pwntools() -> None:
    """Make pwntools emit only warnings, and only through our rich handler."""
    from pwn import context
    # pwnlib decides whether to emit a record by context.log_level, not by logger levels.
    context.log_level = DEPENDENCY_LOG_LEVEL
    # Drop pwnlib's own stdout handler so its warnings aren't printed twice.
    pwnlib_logger = logging.getLogger("pwnlib")
    for handler in list(pwnlib_logger.handlers):
        pwnlib_logger.removeHandler(handler)

def setup_logging(debug: bool = False) -> None:
    """Route all logging through rich. Tracebacks are only rendered in debug mode."""
    handler = RichHandler(console=console, show_time=False, show_path=debug, rich_tracebacks=True)
    handler.addFilter(DependencyLevelFilter())
    logging.basicConfig(level=DEPENDENCY_LOG_LEVEL, format="%(message)s", handlers=[handler], force=True)
    logging.getLogger(OWN_LOGGER).setLevel(logging.DEBUG if debug else logging.INFO)
    quiet_pwntools()

def describe_exception(e: BaseException) -> str:
    """One-line, traceback-free description of an error for the user."""
    message = str(e).strip()
    if isinstance(e, AssertionError):
        # Our own validation failures: the message is written for the user already.
        return message or "assertion failed (run with --debug for details)"
    return f"{type(e).__name__}: {message}" if message else type(e).__name__
