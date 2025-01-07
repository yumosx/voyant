# https://p403n1x87.github.io/running-c-unit-tests-with-pytest.html

from pathlib import Path
from subprocess import PIPE, STDOUT, run

HERE = Path(__file__).resolve().parent
TEST = HERE.parent
ROOT = TEST.parent
SRC = ROOT / "lang"

def CompilationError(Exception):
	pass

def compile(source: Path, cflags=[], ladd=[]):
	binary = source.with_suffix(".so")
	result = run(
		["gcc", "-shared", *cflags, "-o", str(binary), str(source), *ldadd],
		stdout=PIPE,
		stderr=STDOUT,
		cwd=SRC,
	)
	if result.returncode == 0:
		return
	raise CompilationError(result.stdout.decode())
