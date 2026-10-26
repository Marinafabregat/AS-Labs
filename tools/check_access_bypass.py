# tools/check_access_bypass.py
"""
Static check: finds access decisions made outside XACML.

Flags:
1. COMPARE:     comparisons on role / ban / blacklist state outside authz.py.
2. MANUAL-403:  HTTP 403 raised by hand instead of through enforce().
                (401 is authentication, not authorization, so it is not checked.)
3. NO-XACML:    endpoints that never reach enforce(), can() or xacml_decide(),
                directly or through a helper defined in the same file.

Run from the project root: python3 tools/check_access_bypass.py
Exit code: 0 if clean, 1 if any finding.
"""
import ast
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
FILES = [
    ROOT / "main.py",
    ROOT / "auth.py",
    *sorted((ROOT / "routes").glob("*.py")),
]

# Attribute or variable names that carry authorization state.
SENSITIVE_NAMES = {"role", "is_banned", "is_blacklisted", "UserRole"}

# Literal role names. Comparing against these outside authz.py is a bypass risk.
SENSITIVE_STRINGS = {"admin", "moderator", "user"}

# Functions that delegate the decision to XACML.
GUARDS = {"enforce", "can", "xacml_decide", "require_private_items_access"}

# Endpoints that expose no protected data and therefore need no decision.
ALLOWLIST = {
    "login_page",
    "register_page",
    "logout",
    "cancel_link",
    "google_login",
    "link_account_page",
}

# Status codes that represent an authorization decision.
FORBIDDEN_STATUS_NAMES = {"403", "status.HTTP_403_FORBIDDEN"}

HTTP_METHODS = {"get", "post", "put", "patch", "delete"}

problems = 0


def report(path: pathlib.Path, lineno: int, kind: str, text: str) -> None:
    global problems
    problems += 1
    print(f"[{kind}] {path.relative_to(ROOT)}:{lineno}  {text}")


def called_names(node: ast.AST) -> set[str]:
    """Return the names of every function or method called inside a node."""
    names = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            func = child.func
            if isinstance(func, ast.Name):
                names.add(func.id)
            elif isinstance(func, ast.Attribute):
                names.add(func.attr)
    return names


def is_endpoint(fn: ast.AST) -> bool:
    """True if the function is decorated with a router or app HTTP method."""
    return any(
        isinstance(d, ast.Call) and getattr(d.func, "attr", "") in HTTP_METHODS
        for d in fn.decorator_list
    )


def check_file(path: pathlib.Path) -> None:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    lines = source.splitlines()

    # 1. Comparisons on sensitive attributes or literal role names.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue

        names = {
            n.attr if isinstance(n, ast.Attribute) else n.id
            for n in ast.walk(node)
            if isinstance(n, (ast.Attribute, ast.Name))
        }
        strings = {
            n.value
            for n in ast.walk(node)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)
        }

        if (names & SENSITIVE_NAMES) or (strings & SENSITIVE_STRINGS):
            report(path, node.lineno, "COMPARE", lines[node.lineno - 1].strip())

    # 2. HTTP 403 raised by hand.
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call)):
            continue
        if getattr(node.exc.func, "id", "") != "HTTPException":
            continue

        for kw in node.exc.keywords:
            if kw.arg == "status_code" and ast.unparse(kw.value) in FORBIDDEN_STATUS_NAMES:
                report(path, node.lineno, "MANUAL-403", lines[node.lineno - 1].strip())

    # 3. Endpoints without an authorization call.
    functions = {
        n.name: n
        for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    # Helpers defined in this file that call a guard (one level deep).
    guarded_helpers = {
        name for name, fn in functions.items()
        if called_names(fn) & GUARDS
    }

    for name, fn in functions.items():
        if not is_endpoint(fn) or name in ALLOWLIST:
            continue

        if not (called_names(fn) & (GUARDS | guarded_helpers)):
            report(path, fn.lineno, "NO-XACML", f"endpoint {name}()")


def main() -> int:
    for path in FILES:
        if path.exists():
            check_file(path)

    print()
    if problems == 0:
        print("OK: no access decisions found outside XACML.")
        return 0

    print(f"{problems} finding(s). Review each one.")
    return 1


if __name__ == "__main__":
    sys.exit(main())