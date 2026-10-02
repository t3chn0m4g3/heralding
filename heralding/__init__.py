from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

try:
    version = _pkg_version("heralding")
except PackageNotFoundError:  # running from a source checkout without install
    version = "2.0.0"
