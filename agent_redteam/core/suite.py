"""Suite Loader — Reads and validates attack test suites from YAML or JSON files.

This file loads test suites — the files that contain all the attack test cases.
A suite file lists the attacks to run, their categories, and the policies to check.

What it does:
  1. Reads a YAML or JSON file from disk.
  2. Parses each test case and validates it (correct format, required fields, valid IDs).
  3. Checks for duplicate IDs.
  4. Returns a list of validated TestCase objects ready for the engine to execute.

If anything is wrong (missing file, bad format, invalid test case), it raises
a SuiteError with a clear message explaining exactly what went wrong.

Supported formats: .yaml, .yml, .json
"""

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
