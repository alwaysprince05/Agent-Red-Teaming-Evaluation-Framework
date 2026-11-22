"""Taxonomy — maps the framework's attack categories to the OWASP Top 10 for LLM
Applications (2025 edition).

Each category maps to one primary entry, optionally followed by related ones.
The mapping is used in reports, the findings CSV and the web UI.
"""

from __future__ import annotations

OWASP_LLM_2025 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
}

CATEGORY_OWASP: dict[str, tuple[str, ...]] = {
    "prompt_injection": ("LLM01", "LLM07"),
    "jailbreak": ("LLM01",),
    "data_leakage": ("LLM02",),
    "unsafe_tool_use": ("LLM06",),
    "multi_turn_manipulation": ("LLM01",),
    "indirect_injection": ("LLM01",),
}


def owasp_ids(category: str) -> list[str]:
    """OWASP LLM ids for a category, primary first. Unknown categories map to none."""
    return list(CATEGORY_OWASP.get(category, ()))


def owasp_entries(category: str) -> list[dict[str, str]]:
    return [{"id": i, "name": OWASP_LLM_2025[i]} for i in owasp_ids(category)]
