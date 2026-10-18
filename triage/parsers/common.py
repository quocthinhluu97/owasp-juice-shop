"""Shared helpers for the scanner parsers: load JSON, check required keys. Every failure is a ParseError."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from triage.model import ParseError


def load_json(path: Path) -> Any:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ParseError(f"{path}: cannot read ({exc.strerror})") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ParseError(f"{path}: not valid JSON (line {exc.lineno})") from exc


def require_keys(obj: Any, keys: tuple[str, ...], where: str) -> None:
    if not isinstance(obj, dict):
        raise ParseError(f"{where}: expected an object")
    missing = [k for k in keys if k not in obj]
    if missing:
        raise ParseError(f"{where}: missing required key(s): {', '.join(missing)}")
