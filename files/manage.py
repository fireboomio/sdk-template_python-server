#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import importlib
import os
import sys


def main():
    """Run administrative tasks."""
    sys.path.append(os.path.dirname(os.getcwd()))
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'sdk_python.settings')
    try:
        importlib.import_module('custom_py.generated', package=".")
        importlib.import_module('custom_py.src.plugins', package=".")
        from custom_py.src.types import config as types_config
        from django.core.management.commands.runserver import Command as Runserver
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc

    Runserver.default_addr = types_config.server_listen_address
    Runserver.default_port = types_config.server_listen_port

    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()
