from typing import Optional
from importlib.metadata import version, PackageNotFoundError, metadata, PackageMetadata

__metadata__: Optional[PackageMetadata]

try:
    __version__ = version("sinduk")
    __metadata__ = metadata("sinduk")
except PackageNotFoundError:
    try:
        __version__ = version("pacli-tool")
        __metadata__ = metadata("pacli-tool")
    except PackageNotFoundError:
        __version__ = "Unknown"
        __metadata__ = None
