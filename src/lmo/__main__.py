"""Allow ``python -m lmo`` to invoke the same CLI as the console script."""

from lmo.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
