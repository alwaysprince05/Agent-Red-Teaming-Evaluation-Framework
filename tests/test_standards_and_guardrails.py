"""Tests for the OWASP mapping, run provenance, the protected-domain guardrail,
the authorization flag for URL targets and the /experiments endpoint.
"""

import csv
import hashlib
import json
import time

import pytest
from fastapi.testclient import TestClient

from agent_redteam import __version__
from agent_redteam.adapters.base import TargetNotAuthorizedError, is_protected_host, validate_external_target
from agent_redteam.adapters.mock_agent import MockAgent
from agent_redteam.api.main import BUILTIN_SUITE_PATH, app
from agent_redteam.core.runner import RunOptions, execute_run
from agent_redteam.core.schemas import AttackCategory
from agent_redteam.core.taxonomy import CATEGORY_OWASP, OWASP_LLM_2025, owasp_entries
from agent_redteam.reports.generate import generate_findings_csv, generate_markdown_report

client = TestClient(app)


def _run(tmp_path, profile="weak"):
    return execute_run(
        BUILTIN_SUITE_PATH, MockAgent(profile), RunOptions(rate_limit_s=0, output_dir=tmp_path)
    )


class TestTaxonomy:
    def test_every_category_is_mapped(self):
        assert set(CATEGORY_OWASP) == {c.value for c in AttackCategory}

    def test_ids_are_known(self):
        for ids in CATEGORY_OWASP.values():
            assert ids and all(i in OWASP_LLM_2025 for i in ids)

    def test_expected_primary_ids(self):
        assert owasp_entries("unsafe_tool_use")[0] == {"id": "LLM06", "name": "Excessive Agency"}
        assert owasp_entries("data_leakage")[0]["id"] == "LLM02"
        assert owasp_entries("prompt_injection")[0]["id"] == "LLM01"
        assert owasp_entries("unknown") == []


class TestProvenance:
    def test_findings_carry_owasp_ids(self, tmp_path):
        _rid, summary, _r, _rec = _run(tmp_path)
        assert summary.findings
        for f in summary.findings:
            assert f.owasp and f.owasp[0] == CATEGORY_OWASP[f.category][0]

    def test_finding_ids_are_stable_across_runs(self, tmp_path):
        _, first, _, _ = _run(tmp_path / "a")
        _, second, _, _ = _run(tmp_path / "b")
        assert [f.id for f in first.findings] == [f.id for f in second.findings]
        assert len({f.id for f in first.findings}) == len(first.findings)

    def test_summary_is_stamped(self, tmp_path):
        _, summary, _, _ = _run(tmp_path)
        assert summary.framework_version == __version__
        assert summary.suite_sha256 == hashlib.sha256(BUILTIN_SUITE_PATH.read_bytes()).hexdigest()

    def test_reports_include_owasp_and_stamp(self, tmp_path):
        _, summary, _, _ = _run(tmp_path)
        md = generate_markdown_report(summary, [], tmp_path / "r.md").read_text()
        assert "OWASP LLM Top 10:** LLM01 Prompt Injection" in md
        assert "Suite SHA-256" in md and __version__ in md
        rows = list(csv.reader((generate_findings_csv(summary, tmp_path / "f.csv")).open()))
        assert rows[0][-1] == "owasp_llm"
        assert all(r[-1].startswith("LLM") for r in rows[1:])


class TestProtectedHosts:
    @pytest.mark.parametrize("host", [
        "whitehouse.gov", "army.mil", "mit.edu", "un.int", "www.india.gov.in", "mod.gov.uk",
        "iitb.ac.in", "portal.nic.in", "WWW.NASA.GOV.",
    ])
    def test_blocked(self, host):
        assert is_protected_host(host)

    @pytest.mark.parametrize("host", [
        "example.com", "int.example.com", "gov.example.com", "localhost", "127.0.0.1", "api.openai.com",
        "edu.example.org",
    ])
    def test_not_blocked(self, host):
        assert not is_protected_host(host)

    def test_guardrail_cannot_be_overridden(self):
        with pytest.raises(TargetNotAuthorizedError, match="cannot be turned off"):
            validate_external_target(
                "https://chat.example.gov/agent", allow_external=True, host_allowlist=["chat.example.gov"]
            )

    def test_normal_external_host_still_works_when_allowed(self):
        url = "https://agent.example.com/v1"
        assert validate_external_target(url, allow_external=True, host_allowlist=["agent.example.com"]) == url


class TestUrlTargetAuthorization:
    def test_url_target_needs_authorization(self, tmp_path):
        r = client.post(
            "/runs", json={"target": "http://127.0.0.1:9/agent", "output_dir": str(tmp_path / "runs")}
        )
        assert r.status_code == 400
        assert "authorized" in r.json()["detail"]

    def test_authorized_loopback_target_is_accepted(self, tmp_path):
        r = client.post(
            "/runs",
            json={"target": "http://127.0.0.1:9/agent", "authorized": True, "timeout_s": 2,
                  "rate_limit_s": 0, "output_dir": str(tmp_path / "runs")},
        )
        assert r.status_code == 202
        run_id = r.json()["run_id"]
        deadline = time.time() + 60
        while client.get(f"/runs/{run_id}").json()["status"] == "running" and time.time() < deadline:
            time.sleep(0.1)
        # nothing listens on port 9, so every case is an error, never a pass
        body = client.get(f"/runs/{run_id}").json()
        assert body["status"] == "completed"
        assert body["metrics"]["errors"] == body["metrics"]["total_cases"]

    def test_protected_domain_refused_even_when_authorized(self, tmp_path):
        r = client.post(
            "/runs",
            json={"target": "https://bot.example.gov/agent", "authorized": True,
                  "allow_external_targets": True, "allowed_hosts": ["bot.example.gov"],
                  "output_dir": str(tmp_path / "runs")},
        )
        assert r.status_code == 400
        assert "guardrail" in r.json()["detail"]


class TestApiFields:
    def test_config_categories_have_owasp(self):
        cats = client.get("/config").json()["categories"]
        assert all(c["owasp"] and c["owasp"][0]["id"].startswith("LLM") for c in cats)

    def test_details_rows_have_owasp_and_stamp(self, tmp_path):
        r = client.post(
            "/runs", json={"target": "mock:weak", "rate_limit_s": 0, "output_dir": str(tmp_path / "runs")}
        )
        run_id = r.json()["run_id"]
        deadline = time.time() + 30
        while client.get(f"/runs/{run_id}").json()["status"] == "running" and time.time() < deadline:
            time.sleep(0.1)
        d = client.get(f"/runs/{run_id}/details", params={"output_dir": str(tmp_path / "runs")}).json()
        assert d["framework_version"] == __version__
        assert len(d["suite_sha256"]) == 64
        assert all(row["owasp"] for row in d["cases"])
        assert all(f["owasp"] for f in d["findings"])


class TestExperiments:
    def test_reads_published_summaries(self, tmp_path, monkeypatch):
        data = {
            "model": "test-model", "base_url": "http://127.0.0.1:11434/v1", "repeats": 3,
            "targets": {
                "llm:weak": {"fixed_asr": [0.8, 0.7, 0.9], "fixed_errors": [0, 1, 0],
                             "adaptive": {"total_executed": 9, "total_violations": 6,
                                          "categories_attacked": ["jailbreak"], "planner": "llm"}},
                "llm:strong": {"fixed_asr": [0.3, 0.3, 0.3], "fixed_errors": [0, 0, 0]},
            },
        }
        (tmp_path / "llm_experiment_20260101.json").write_text(json.dumps(data))
        (tmp_path / "llm_experiment_broken.json").write_text("{not json")
        monkeypatch.setenv("AGENT_REDTEAM_RESULTS_DIR", str(tmp_path))
        out = client.get("/experiments").json()
        assert len(out) == 1
        weak = out[0]["targets"]["llm:weak"]
        assert out[0]["model"] == "test-model" and out[0]["date"] == "20260101"
        assert weak["mean_asr"] == 0.8 and weak["min_asr"] == 0.7 and weak["max_asr"] == 0.9
        assert weak["adaptive"]["violations"] == 6
        assert out[0]["targets"]["llm:strong"]["adaptive"]["executed"] is None

    def test_missing_directory_is_empty(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AGENT_REDTEAM_RESULTS_DIR", str(tmp_path / "nope"))
        assert client.get("/experiments").json() == []

    def test_repo_results_are_served(self, monkeypatch):
        monkeypatch.delenv("AGENT_REDTEAM_RESULTS_DIR", raising=False)
        out = client.get("/experiments").json()
        assert out and out[0]["model"] == "qwen2.5:3b"
