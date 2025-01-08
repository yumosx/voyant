# https://p403n1x87.github.io/running-c-unit-tests-with-pytest.html

import os
import sys
from subprocess import PIPE, STDOUT, run, check_output
from types import FunctionType
from pathlib import Path
from test.cuint import SRC

class SG(Exception):
	pass

class CUintTestFailure(Exception):
	pass

def pytest_pycollect_makeitem(collector, name, obj):
    if (
        not os.getenv("PYTEST_CUNIT")
        and isinstance(obj, FunctionType)
        and name.startswith("test_")
    ):
        obj.__cunit__ = (str(collector.fspath), name)

def cuint(module: str, name: str, full_name: str):
	def _(*_, **__):
		test = f"{module}::{name}"
		env = os.environ.copy()
		env["PYTEST_CUNIT"] = full_name
		result = run([sys.argv[0], "-svv", test], stdout=PIPE, stderr=PIPE, env=env)
		if result.returncode == 0:
			return
		elif result.returncode == -11:
			binary_name = Path(module).stem.replace("test_", "")
			raise SG((SRC/binary_name).with_suffix(".so"))	
		raise CUintTestFailure("\n" + result.stdout.decode())
	
	return _

def pytest_collection_modifyitems(session, config, items) -> None:
	if test_name := os.getenv("PYTEST_CUINT"):
		items[:] = [_ for _ in items if _.name == test_name]
		return
	for item in items:
		if hasattr(item._obj, "__cuint__"):
			item._obj = cuint(*item._obj.__cuint__, full_name=item.name)

def gdb(cmds: list[str], *args: str) -> str:
	return check_output(
		["gdb", "-q", "bash"]
		+ [_ for cs in (("-ex", _) for _ in cmds) for _ in cs]
		+ list(args),
		stderr=STDOUT,
	).decode()

def bt(binary: Path) -> str:
	if Path("core").is_file():
		return gdb(["bt full", "q"], str(binary), "core")
	return "No core dump available."