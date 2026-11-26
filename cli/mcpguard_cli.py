"""Deprecated import path. The CLI lives in ``cli.axiom_cli``; this module only forwards to it."""
from cli.axiom_cli import *  # noqa: F401,F403
from cli.axiom_cli import app  # noqa: F401

if __name__ == "__main__":
    app()
