''' Python API for Physics-Lab-AR '''

import sys
import os

_vendor_dir = os.path.join(os.path.dirname(__file__), 'vendor')
if os.path.exists(_vendor_dir) and _vendor_dir not in sys.path:
    sys.path.insert(0, _vendor_dir)

try:
    import requests
    import executing
    import typing_extensions
    _vendored_deps_available = True
except ImportError:
    _vendored_deps_available = False
    try:
        import requests
        import executing
        import typing_extensions
    except ImportError as e:
        raise ImportError(
            f"Cannot import required dependencies: {e}\n"
            f"Please run 'python vendor_deps.py' to vendor dependencies, "
            f"or install dependencies: pip install typing-extensions requests==2.32.3 executing==2.2.0"
        )

from .physicsLab_version import __version__
# 操作实验
from .element import search_experiment, Experiment
from ._core import (
    ElementBase,
    get_current_experiment,
    elementXYZ_to_native,
    native_to_elementXYZ,
    ElementXYZ,
)
# 实验, 标签类型
from .enums import ExperimentType, Category, Tag, OpenMode, WireColor, GetUserMode
# 电学实验
from .circuit import *
# 天体物理实验
from .celestial import *
# 电与磁实验
from .electromagnetism import *
# physicsLab自定义异常类
from .errors import *
from . import _warn

from physicsLab.plAR import *
from physicsLab.utils import *

from physicsLab import web
from physicsLab import lib
from physicsLab import music

import platform

if not os.path.exists(Experiment.SAV_PATH_DIR):
    if platform.system() == "Windows":
        _warn.warning("Have you installed Physics-Lab-AR?")
    os.makedirs(Experiment.SAV_PATH_DIR)

del platform
del _warn
del _vendor_dir
