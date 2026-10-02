import argparse
import sys
import logging

import pwnutils.pwninit as pwninit
import pwnutils.pwnrun as pwnrun
import pwnutils.pwngdb as pwngdb

from pwnutils.utils import setup_logging, describe_exception

logger = logging.getLogger(__name__)

supported_modules = [ pwninit, pwnrun, pwngdb ]

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pwnutils",
        description="Useful utils for setting up pwnable exercises and cross-platform debugging.",
    )
    parser.add_argument("--debug", action="store_true", help="debug logging and full tracebacks on errors")

    subparsers = parser.add_subparsers(
        dest="module",
        required=True,
    )

    for module in supported_modules:
        module_parser = module.build_parser()
        subparser = subparsers.add_parser(
            module.name,
            parents=[module_parser],
            add_help=False,
        )
        subparser.set_defaults(handler=module.run)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    setup_logging(args.debug)
    try:
        args.handler(args)
    except KeyboardInterrupt:
        logger.error("interrupted")
        return 130
    except Exception as e:
        if args.debug:
            logger.exception(describe_exception(e))
        else:
            logger.error(describe_exception(e))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
