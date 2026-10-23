"""AST parsing helpers for Python and JavaScript/TypeScript code.

Provides syntax-tree traversal for Python (using standard library `ast`)
and JavaScript/TypeScript (using `esprima` with fallback to regex).

Comments and string literals are ignored by AST traversal, dramatically
reducing false positives from documentation or comments.
"""
from __future__ import annotations

import ast
import logging
from dataclasses import dataclass
from typing import Any, Callable, Generator

try:
    import esprima
    HAVE_ESPRIMA = True
except ImportError:
    HAVE_ESPRIMA = False

log = logging.getLogger("patchpilot.ast")


@dataclass
class AstCall:
    name: str                   # e.g., "eval", "subprocess.run", "os.system"
    line: int                   # 1-based line number
    args: list[Any]             # raw AST argument nodes
    kwargs: dict[str, Any]      # keyword arguments (names -> AST node or val)
    node: Any                   # the raw AST call node
    is_literal_arg: bool        # True if the first argument is a static literal


# ---------------------------------------------------------------- Python AST

def _get_py_call_name(node: ast.AST) -> str:
    """Extract a dotted function name from an ast.Call node func."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        value_name = _get_py_call_name(node.value)
        return f"{value_name}.{node.attr}" if value_name else node.attr
    return ""


def _is_py_literal(node: ast.AST) -> bool:
    """Check if node is a constant literal value."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub, ast.Not, ast.Invert)):
        return _is_py_literal(node.operand)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_is_py_literal(elt) for elt in node.elts)
    if isinstance(node, ast.Dict):
        return all(_is_py_literal(k) for k in node.keys if k) and all(_is_py_literal(v) for v in node.values)
    return False


def parse_python_ast(content: str) -> ast.AST | None:
    """Safely parse Python code into an AST; returns None on SyntaxError."""
    try:
        return ast.parse(content)
    except Exception:
        return None


def find_python_calls(tree: ast.AST) -> Generator[AstCall, None, None]:
    """Find all function calls in a Python AST."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_name = _get_py_call_name(node.func)
            kwargs: dict[str, Any] = {}
            for kw in node.keywords:
                if kw.arg:
                    kwargs[kw.arg] = kw.value

            first_arg_literal = False
            if node.args:
                first_arg_literal = _is_py_literal(node.args[0])

            yield AstCall(
                name=call_name,
                line=getattr(node, "lineno", 1),
                args=list(node.args),
                kwargs=kwargs,
                node=node,
                is_literal_arg=first_arg_literal,
            )


# ---------------------------------------------------------------- JS/TS AST

def _get_js_callee_name(node: Any) -> str:
    """Extract identifier name from an esprima callee node."""
    if not node:
        return ""
    ntype = getattr(node, "type", "")
    if ntype == "Identifier":
        return getattr(node, "name", "")
    if ntype == "MemberExpression":
        obj = _get_js_callee_name(getattr(node, "object", None))
        prop_node = getattr(node, "property", None)
        prop = getattr(prop_node, "name", "") if getattr(prop_node, "type", "") == "Identifier" else ""
        return f"{obj}.{prop}" if obj and prop else (prop or obj)
    return ""


def _is_js_literal(node: Any) -> bool:
    """Check if JS node is a simple Literal or static template without interpolation."""
    if not node:
        return True
    ntype = getattr(node, "type", "")
    if ntype == "Literal":
        return True
    if ntype == "TemplateLiteral":
        # Expressions inside ${...} mean it's dynamic
        exprs = getattr(node, "expressions", [])
        return len(exprs) == 0
    if ntype == "ArrayExpression":
        elements = getattr(node, "elements", [])
        return all(_is_js_literal(e) for e in elements if e)
    return False


def _walk_js(node: Any, visitor: Callable[[Any], None], visited: set[int] | None = None, depth: int = 0) -> None:
    """Recursive AST walker for esprima nodes with cycle and depth protection."""
    if depth > 100 or node is None or isinstance(node, (str, int, float, bool)):
        return
    if visited is None:
        visited = set()

    obj_id = id(node)
    if obj_id in visited:
        return
    visited.add(obj_id)

    if isinstance(node, list):
        for item in node:
            _walk_js(item, visitor, visited, depth + 1)
        return

    if hasattr(node, "type"):
        try:
            visitor(node)
        except Exception as e:
            log.debug("Visitor error on node %s: %s", getattr(node, "type", "unknown"), e)

        node_dict = getattr(node, "__dict__", None)
        if isinstance(node_dict, dict):
            for key, val in node_dict.items():
                if key not in ("loc", "range", "tokens", "comments"):
                    _walk_js(val, visitor, visited, depth + 1)


def parse_js_ast(content: str) -> Any | None:
    """Safely parse JavaScript/JSX into an AST with esprima; returns None if not installed or on syntax error."""
    if not HAVE_ESPRIMA:
        return None
    try:
        # Enable JSX and module parsing
        return esprima.parseModule(content, {"loc": True, "jsx": True, "tolerant": True})
    except Exception:
        try:
            return esprima.parseScript(content, {"loc": True, "jsx": True, "tolerant": True})
        except Exception:
            return None


def find_js_calls(tree: Any) -> Generator[AstCall, None, None]:
    """Find all function calls and `new Function(...)` invocations in an esprima AST."""
    calls: list[AstCall] = []

    def visit(node: Any) -> None:
        ntype = getattr(node, "type", "")
        if ntype in ("CallExpression", "NewExpression"):
            callee = getattr(node, "callee", None)
            call_name = _get_js_callee_name(callee)
            loc = getattr(node, "loc", None)
            line = loc.start.line if loc and hasattr(loc, "start") else 1
            args = getattr(node, "arguments", []) or []

            first_arg_literal = False
            if args:
                first_arg_literal = _is_js_literal(args[0])

            calls.append(AstCall(
                name=call_name,
                line=line,
                args=args,
                kwargs={},
                node=node,
                is_literal_arg=first_arg_literal,
            ))

    _walk_js(tree, visit)
    for c in calls:
        yield c
