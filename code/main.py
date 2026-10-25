"""Main CLI entry point for Ghost Data Still Exists solution."""

import sys
from pathlib import Path

# Add the 'code' directory to sys.path so 'ghost_audit' can be imported without
# colliding with Python's standard library 'code' module.
CODE_DIR = Path(__file__).resolve().parent
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

from ghost_audit.cli import main as cli_main  # noqa: E402


def main() -> int:
    args = sys.argv[1:]
    if not args:
        # Default convenience: if run with no args, run 'inspect'
        return cli_main(["inspect"])
    return cli_main(args)


if __name__ == "__main__":
    sys.exit(main())
