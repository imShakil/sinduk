"""
CLI entry point forwarding to sinduk.cli.
"""

from sinduk.cli import cli

__all__ = ["cli"]

if __name__ == "__main__":
    cli()
