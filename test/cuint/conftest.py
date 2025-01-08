# https://p403n1x87.github.io/running-c-unit-tests-with-pytest.html

import os
import sys
from subprocess import PIPE, STDOUT, run, check_output
from types import FunctionType
from pathlib import Path
from shutil import rmtree
from cuint import SRC

class SegmentationFault(Exception):
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

def cunit(module: str, name: str, full_name: str):
	def _(*_, **__):
		test = f"{module}::{name}"
		env = os.environ.copy()
		env["PYTEST_CUNIT"] = full_name
		result = run([sys.argv[0], "-svv", test], stdout=PIPE, stderr=PIPE, env=env)
		match result.returncode:
			case 0:
				return
			case -11:
				binary_name = Path(module).stem.replace("test_", "")
				soPath = (SRC / binary_name).with_suffix(".so")
				raise SegmentationFault(bt(soPath))

		if result.returncode == 0:
			return


		raise CUintTestFailure("\n" + result.stdout.decode())
	
	return _

def pytest_collection_modifyitems(session, config, items) -> None:
	if test_name := os.getenv("PYTEST_CUINT"):
		items[:] = [_ for _ in items if _.name == test_name]
		return
	for item in items:
		if hasattr(item._obj, "__cunit__"):
			item._obj = cunit(*item._obj.__cunit__, full_name=item.name)

def gdb(cmds: list[str], *args: str) -> str:
	return check_output(
		["gdb", "-q", "-batch"]
		+ [_ for cs in (("-ex", _) for _ in cmds) for _ in cs]
		+ list(args),
		stderr=STDOUT,
	).decode()


def apport_unpack(report: Path, target_dir: Path):
    return check_output(
        ["apport-unpack", str(report), str(target_dir)],
        stderr=STDOUT,
    ).decode()


def bt(binary: Path) -> str:
	if Path("core").is_file():
		return gdb(["bt full", "q"], str(binary), "core")
	
	crash_dir = Path("/var/crash")
	if crash_dir.is_dir():
		crashes = list(crash_dir.glob("*.crash"))
		print(crashes)
		if crashes:
			crash = crashes[-1]
			target_dir = Path(crash.stem)
			apport_unpack(crash, target_dir)

			result = gdb(["bt full", "q"], str(binary), target_dir / "CoreDump")

			crash.unlink()
			rmtree(str(target_dir))

			return result
	
	return "No core dump available."