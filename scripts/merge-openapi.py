#!/usr/bin/env python3
"""Append paths and components from one OpenAPI document onto another.

Both inputs are files (JSON or YAML). Nothing about Keycloak is hardcoded.
"""

import argparse
import json
import sys
from pathlib import Path


def load(path: Path):
    text = path.read_text()
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        return json.loads(text)
    import yaml
    return yaml.safe_load(text)


def dump(document, path: Path) -> None:
    if path.suffix.lower() in {".yaml", ".yml"}:
        import yaml
        path.write_text(yaml.safe_dump(document, sort_keys=False, allow_unicode=True))
        return
    path.write_text(json.dumps(document, indent=2) + "\n")


def append_map(base: dict, extra: dict, label: str) -> None:
    for key, value in extra.items():
        if key in base and base[key] != value:
            raise SystemExit(f"{label} '{key}' already exists and differs")
        base.setdefault(key, value)


def merge(base: dict, extra: dict) -> dict:
    append_map(base.setdefault("paths", {}), extra.get("paths") or {}, "path")
    components = base.setdefault("components", {})
    for name, section in (extra.get("components") or {}).items():
        if isinstance(section, dict):
            append_map(components.setdefault(name, {}), section, f"component {name}")
        elif name in components and components[name] != section:
            raise SystemExit(f"component '{name}' already exists and differs")
        else:
            components.setdefault(name, section)
    return base


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base", type=Path, help="OpenAPI document to append into")
    parser.add_argument("extra", type=Path, help="OpenAPI document whose paths and components are appended")
    parser.add_argument("-o", "--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        dump(merge(load(args.base), load(args.extra)), args.output)
    except ModuleNotFoundError:
        sys.exit("YAML input or output needs PyYAML: pip install pyyaml")


if __name__ == "__main__":
    main()
