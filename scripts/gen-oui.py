#!/usr/bin/env python3
"""Regenerate crates/core/src/oui_db.rs from the IEEE OUI registry.

    python scripts/gen-oui.py [path/to/oui.txt]

Fetches https://standards-oui.ieee.org/oui/oui.txt when no path is given.
Run from the repo root; re-run when coverage complaints appear.
"""

import re
import sys
import urllib.request
from pathlib import Path

OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"
OUT = Path("crates/core/src/oui_db.rs")
LINE = re.compile(r"^([0-9A-F]{2})-([0-9A-F]{2})-([0-9A-F]{2})\s+\(hex\)\t+(.*)$")


def sanitize(vendor: str) -> str:
    vendor = vendor.replace("\\", "").replace('"', "'")
    return "".join(c for c in vendor if 32 <= ord(c) < 127).strip()


def main() -> None:
    src = sys.argv[1] if len(sys.argv) > 1 else None
    if src:
        text = Path(src).read_text(encoding="utf-8", errors="replace")
    else:
        text = urllib.request.urlopen(OUI_URL, timeout=120).read().decode(
            "utf-8", errors="replace"
        )

    entries: dict[str, str] = {}
    for line in text.splitlines():
        m = LINE.match(line)
        if not m:
            continue
        prefix = (m.group(1) + m.group(2) + m.group(3)).lower()
        vendor = sanitize(m.group(4))
        if prefix and vendor:
            entries.setdefault(prefix, vendor)

    with OUT.open("w", newline="\n") as f:
        f.write("//! OUI prefix -> vendor, generated from the IEEE registry.\n")
        f.write("//! Regenerate with `python scripts/gen-oui.py`. Do not edit.\n\n")
        f.write("/// Sorted `(prefix as lowercase 6-byte ASCII hex, vendor)`.\n")
        f.write("pub(crate) static OUI_DB: &[([u8; 6], &str)] = &[\n")
        for k in sorted(entries):
            f.write(f'    (*b"{k}", "{entries[k]}"),\n')
        f.write("];\n")
    print(f"{len(entries)} OUI entries -> {OUT}")


if __name__ == "__main__":
    main()
