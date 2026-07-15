from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[2]
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
SKIPPED_PREFIXES = ("http://", "https://", "mailto:", "#")


def local_targets(markdown_file: Path) -> list[Path]:
    text = markdown_file.read_text(encoding="utf-8")
    targets: list[Path] = []

    for raw_target in MARKDOWN_LINK.findall(text):
        target = raw_target.strip().strip("<>").split("#", 1)[0]
        if not target or target.startswith(SKIPPED_PREFIXES):
            continue

        decoded = unquote(target)
        targets.append((markdown_file.parent / decoded).resolve())

    return targets


def main() -> int:
    missing: list[tuple[Path, Path]] = []

    for markdown_file in ROOT.rglob("*.md"):
        for target in local_targets(markdown_file):
            if not target.exists():
                missing.append((markdown_file.relative_to(ROOT), target))

    if missing:
        print("Broken local Markdown links found:")
        for source, target in missing:
            print(f"- {source}: {target}")
        return 1

    print("All local Markdown links are valid.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
