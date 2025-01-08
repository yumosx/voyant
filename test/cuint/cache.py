import sys
from pathlib import Path
from cuint import SRC, CModule

CFLAGS = ["-g"]

sys.modules[__name__] = CModule.compile(SRC / Path(__file__).stem, cflags=CFLAGS)