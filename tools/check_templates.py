import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATE_DIRS = [ROOT / "templates"]

PATTERNS = [
    (re.compile(r"\.role\b"), "role check"),
    (re.compile(r"\bis_banned\b"), "ban state"),
    (re.compile(r"\bis_blacklisted\b"), "blacklist state"),
    (re.compile(r"\bis_owner\b"), "ownership computed outside XACML"),
    (re.compile(r"\bis_staff\b"), "staff check"),
    (re.compile(r"""==\s*['"](admin|moderator|user)['"]"""), "literal role comparison"),
    (re.compile(r"/uploads/"), "direct upload URL bypasses XACML"),
]

problems = 0


def main() -> int:
    global problems

    for directory in TEMPLATE_DIRS:
        if not directory.exists():
            continue

        for path in sorted(directory.rglob("*.html")):
            for lineno, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                for pattern, reason in PATTERNS:
                    if pattern.search(line):
                        problems += 1
                        rel = path.relative_to(ROOT)
                        print(f"[TEMPLATE] {rel}:{lineno}  ({reason})  {line.strip()}")

    print()
    if problems == 0:
        print("OK: no access decisions found in templates.")
        return 0

    print(f"{problems} finding(s). Replace each with a flag computed by XACML.")
    return 1


if __name__ == "__main__":
    sys.exit(main())