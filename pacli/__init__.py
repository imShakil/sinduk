"""
pacli-tool has been renamed to sinduk.
This transition package installs sinduk as a dependency.
"""

import warnings

warnings.warn(
    "pacli-tool has been renamed to sinduk. Please install and use 'sinduk' directly: pip install sinduk",
    DeprecationWarning,
    stacklevel=2,
)

try:
    from importlib.metadata import version, PackageNotFoundError

    __version__ = version("pacli-tool")
except PackageNotFoundError:
    __version__ = "1.5.0"
