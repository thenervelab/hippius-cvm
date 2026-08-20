#!/usr/bin/env python3
"""Django's command-line utility for the vali project.

Run from the `vali/` directory (the one that contains this file). The
project package is also named `vali` — settings module is `vali.settings`.
"""

import os
import sys


def main() -> None:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "vali.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Activate the project venv "
            "(uv venv + uv pip install -e .[dev]) before running manage.py."
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
