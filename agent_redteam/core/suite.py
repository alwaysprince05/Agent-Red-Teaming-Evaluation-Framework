"""Suite loading and validation from YAML/JSON files."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from agent_redteam.core.schemas import TestCase

_SUFFIXES = (".yaml", ".yml", ".json")


class SuiteError(ValueError):
    """Raised when a suite file is missing, unreadable or contains invalid test cases."""


def _load_file(path: Path) -> list[dict]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SuiteError(f"cannot read suite file {path}: {exc}") from exc
    try:
        if path.suffix.lower() == ".json":
            data = json.loads(text)
        else:
            data = yaml.safe_load(text)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise SuiteError(f"invalid syntax in {path}: {exc}") from exc
    if data is None:
        return []
    if isinstance(data, dict):
        data = data.get("test_cases", [])
    if not isinstance(data, list):
        raise SuiteError(f"{path}: expected a list of test cases or a 'test_cases' mapping")
    return data


def load_suite(path: str | Path) -> list[TestCase]:
    """Load and validate all test cases in a suite file. Raises SuiteError on any problem."""
    p = Path(path)
    if p.suffix.lower() not in _SUFFIXES:
        raise SuiteError(f"unsupported suite format {p.suffix!r} (use .yaml/.yml/.json)")
    raw_cases = _load_file(p)
    if not raw_cases:
        raise SuiteError(f"{p}: suite contains no test cases")
    cases: list[TestCase] = []
    errors: list[str] = []
    seen: set[str] = set()
    for i, raw in enumerate(raw_cases):
        try:
            case = TestCase.model_validate(raw)
        except Exception as exc:  # pydantic ValidationError or TypeError
            errors.append(f"  case #{i + 1}: {exc}")
            continue
        if case.id in seen:
            errors.append(f"  case #{i + 1}: duplicate id {case.id!r}")
            continue
        seen.add(case.id)
        cases.append(case)
    if errors:
        raise SuiteError(f"{p}: {len(errors)} invalid test case(s):\n" + "\n".join(errors))
    return cases
