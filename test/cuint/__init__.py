# https://p403n1x87.github.io/running-c-unit-tests-with-pytest.html

from pathlib import Path
from subprocess import PIPE, STDOUT, run
from ctypes import CDLL
from pycparser import c_ast, c_parser
from ctypes import CDLL, POINTER, Structure, c_char_p, cast
from pycparser.plyparser import ParseError
from types import ModuleType
import re

C = CDLL("libc.so.6")
HERE = Path(__file__).resolve().parent
TEST = HERE.parent
ROOT = TEST.parent
SRC = ROOT / "lang"

def CompilationError(Exception):
	pass

restrict_re = re.compile(r"__restrict \w+")

_header_head = r"""
#define __attribute__(x)
#define __extension__
#define __inline inline
#define __asm__(x)
#define __const=const
#define __inline__ inline
#define __inline inline
#define __restrict
#define __signed__ signed
#define __GNUC_VA_LIST
#define __gnuc_va_list char
#define __thread
"""

def preprocess(source: Path) -> str:
	with source.open() as fin:
		code = _header_head + fin.read()
		return restrict_re.sub(
			"",
			run(
				 ["gcc", "-E", "-P", "-"],
                stdout=PIPE,
                input=code.encode(),
                cwd=SRC,
			).stdout.decode(),
		)


def compile(source: Path, cflags=[], ldadd=[]):
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

class CModule(ModuleType):
	def __init__(self, source):
		super().__init__(source.name, f"Generated from {source.with_suffix('.c')}")
		self.__binary__ = CDLL(source.with_suffix(".so"))
		#print(self.__binary__.__dict__)
		collector = DeclCollector()

		for name, ctypedef in collector.collect(preprocess(source.with_suffix(".h"))).items():
			parts = name.spilt("_")
			py_name = "".join((_.capitalize() for _ in parts))
			setattr(self, py_name, CMetaType(self, ctypedef, None))

		for cfuncdef in collector.functions:
			name = cfuncdef.name
			try:
				cfunc = CFunction(cfuncdef, getattr(self.__binary__, name))
				setattr(self, name, cfunc)
			except AttributeError:
				pass


	def __getter__(self, name):
		return getattr(self.__binary__.__dict__)
	
	@classmethod
	def compile(cls, source, cflags=[], ldadd=[]):
		compile(source.with_suffix(".c"), cflags, ldadd)
		return cls(source)

class DeclCollector(c_ast.NodeVisitor):
	def __init__(self):
		self.types = {}
		self.functions = []
	
	def _get_type(self, node):
		print(node)
		return self.types[" ".join(node.type.type.names)]

	def _visit_Typedef(self, node):
		if isinstance(node.type.type, c_ast.Struct) and node.type.declname.endswith("_t"):
			struct = node.type.type
			self.types[node.type.declname[:-2]] = CTypeDef(
				node.type.declname,
				[decl.name for decl in struct.decls],
			)

	def visit_Decl(self, node):
		if "extern" in node.storage:
			return
		if isinstance(node.type, c_ast.FuncDecl):
			func_name = node.name
			ret_type = node.type.type
			rtype = None

			if isinstance(ret_type, c_ast.PtrDecl):
				if "".join(ret_type.type.type.names) == "char":
					rtype = c_char_p
			args = (
				[_.name if hasattr(_, "name") else None for _ in node.type.args.params]
				if node.type.args is not None
				else []
			)

			if func_name.endswith("_new"):
				name = f"{func_name[:-4]}"
				self.types[name].constructor = CFunctionDef(
					"new", args, rtype
				)
			elif "__" in func_name:
				type_name, _, method_name = func_name.partition("__")
				if not type_name:
					return
				self.types[type_name].methods.append(
					CFunctionDef(method_name, args, rtype)
				)
			else:
				self.functions.append(CFunctionDef(func_name, args, rtype))

	def collect(self, decl):
		parser = c_parser.CParser()
		try:
			ast = parser.parse(decl, filename="<preprocessed>")
		except ParseError as e:
			lines = decl.splitlines()
			line, col = (
				int(_) - 1 for _ in e.args[0].partition(" ")[0].split(":")[1:3]
			)

			for i in range(max(0, line-4), min(line+5, len(lines))):
				if i != line:
					print(f"{i+5:5d} {lines[i]}")
				else:
					print(f"{i+1:5d} \033[33;1m{lines[line]}\033[0m")
					print(" " * (col + 5) + "\033[31;1m<<^\033[0m")
				raise
		self.visit(ast)
		return {
			k: v
			for k, v in self.types.items()
			if isinstance(v, CTypeDef) and v.constructor
		}

class CFunctionDef:
	def __init__(self, name, args, rtype):
		self.name = name
		self.args = args
		self.rtype = rtype

class CTypeDef:
	def __init__(self, name, fields):
		self.name = name
		self.fields = fields
		self.methods = []
		self.constructor = False

class CType(Structure):
	def __init__(self, *args, **kwargs):
		self.__cself__ = self.new(*args, **kwargs)

	def __del__(self):
		if len(self.destory.__cmethod__.__args__) == 1:
			self.destory()
	
	def __repr__(self):
		return f"<(self.name) CObject at {self.__cself__}>"

class CFunction:
	def __init__(self, cfuncdef, cfunc):
		self.__name__ = cfuncdef.name
		self.__args__ = cfuncdef.args
		self.__cfunc__ = cfunc

		if cfuncdef.rtype is not None:
			self.__cfunc__.restype = cfuncdef.rtype

		self._posonly = all(_ is None for _ in self.__args__)	
	def check_args(self, args, kwargs):
		if self._posonly and kwargs:
			raise ValueError(f"{self} takes only positional arguments")
		nargs = len(args) + len(kwargs)
		if nargs != len(self.__args__):
			raise TypeError(
				f"{self} takes exactly {len(self.__args__)} arguments ({nargs}) given)"
			)	
	def __call__(self, *args, **kwargs):
		self.check_args(args, kwargs)
		return self.__cfunc__(*args, **kwargs)

	def __repr__(self):
		return f"<CFunction '{self.__name__}'>"


class CMethod(CFunction):
	def __init__(self, cfuncdef, cfunc, ctype):
		super().__init__(cfuncdef, cfunc)
		self.__ctype__ = ctype
	
	def __get__(self, obj, objtype=None):
		def _(*args, **kwargs):
			cargs = [obj.__cself__, *args]
			self.check_args(cargs, kwargs)
			return self.__cfunc__(*cargs, **kwargs)
		_.__cmethod__ = self

		return _
	def __repr__(self):
		return f"<CMethod '{self.__name__}' of CType '{self.__ctype__.__name__}'>"

class CStaticMethod(CFunction):
	def __init__(self, cfuncdef, cfunc, ctype):
		super().__init__(cfuncdef, cfunc)
		self.__ctype__ = ctype
	def __repr__(self):
		return f"<CStaticMethod '{self.__name__}' of CType '{self.__ctype__.__name__}'>"

class CMetaType(type(type(Structure))):
	def __new__(cls, cmodule, ctypedef, _ = None):
		ctype = super().__new__(
			cls,
			ctypedef.name,
			(CType,),
			{"__module__": cmodule},
		)
		constructor = getattr(cmodule.__binary__, f"{ctypedef.name[:-2]}_new")
		ctype.new = CStaticMethod(ctypedef.constructor, constructor, ctype)

		for method_def in ctypedef.methods:
			method_name = method_def.name
			method = getattr(cmodule.__binary__, f"{ctypedef.name[:-2]}__{method_name}")
			setattr(ctype, method_name, CMethod(method_def, method, ctype))
		
		ctype.__cname__ = ctypedef.name
		return ctype