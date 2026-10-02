import argparse
import sys
import logging

import pwnutils.pwninit as pwninit
import pwnutils.pwnrun as pwnrun
import pwnutils.pwngdb as pwngdb

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

supported_modules = [ pwninit, pwnrun, pwngdb ]

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pwnutils",
        description="Useful utils for setting up pwnable exercises and cross-platform debugging.",
    )

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


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.handler(args)
    except Exception as e:
        logger.exception(e)


if __name__ == "__main__":
    sys.exit(main())
