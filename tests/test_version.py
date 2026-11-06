"""Version consistency: the package, pyproject and REST API must report the same version."""

import tomllib
from pathlib import Path

from agent_redteam import __version__
from agent_redteam.api.main import app

ROOT = Path(__file__).resolve().parents[1]


def test_versions_match():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["version"] == __version__
    assert app.version == __version__
