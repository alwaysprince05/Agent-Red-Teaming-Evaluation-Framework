import time

from fastapi.testclient import TestClient

from agent_redteam.api.main import app

client = TestClient(app)


def _wait_for_run(run_id, timeout_s=30):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        r = client.get(f"/runs/{run_id}")
        if r.status_code == 200 and r.json().get("status") in ("completed", "failed"):
            return r.json()
        time.sleep(0.2)
    raise TimeoutError(f"run {run_id} did not finish in {timeout_s}s")


class TestHealth:
    def test_healthz(self):
        r = client.get("/healthz")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


class TestRunLifecycle:
    def test_start_status_results(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = client.post(
            "/runs",
            json={"suite": "core", "target": "mock:weak", "output_dir": str(tmp_path / "runs")},
        )
        assert r.status_code == 202
        run_id = r.json()["run_id"]

        final = _wait_for_run(run_id)
        assert final["status"] == "completed"
        assert final["metrics"]["violations"] > 0

        res = client.get(f"/runs/{run_id}/results", params={"output_dir": str(tmp_path / "runs")})
        assert res.status_code == 200
        body = res.json()
        assert body["run_id"] == run_id
        assert len(body["results"]) > 0

    def test_strong_target_zero_violations(self, tmp_path):
        r = client.post(
            "/runs",
            json={"suite": "core", "target": "mock:strong", "output_dir": str(tmp_path / "runs")},
        )
        run_id = r.json()["run_id"]
        final = _wait_for_run(run_id)
        assert final["status"] == "completed"
        assert final["metrics"]["violations"] == 0

    def test_unknown_run_404(self):
        assert client.get("/runs/does-not-exist").status_code == 404

    def test_missing_results_404(self):
        assert client.get("/runs/does-not-exist/results").status_code == 404


class TestSafety:
    def test_external_target_rejected(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        r = client.post(
            "/runs",
            json={
                "suite": "core",
                "target": "http://api.evil.example.com/agent",
                "output_dir": str(tmp_path / "runs"),
            },
        )
        assert r.status_code == 400
        assert "not authorized" in r.json()["detail"].lower() or "authorized" in r.json()["detail"].lower()

    def test_bad_suite_rejected(self, tmp_path):
        r = client.post(
            "/runs",
            json={"suite": "/nonexistent/suite.yaml", "target": "mock:weak",
                  "output_dir": str(tmp_path / "runs")},
        )
        assert r.status_code == 400

    def test_invalid_payload_rejected(self):
        r = client.post("/runs", json={"timeout_s": "not-a-number"})
        assert r.status_code == 422


class TestReportEndpoint:
    def test_report_generation(self, tmp_path):
        r = client.post(
            "/runs",
            json={"suite": "core", "target": "mock:weak", "output_dir": str(tmp_path / "runs")},
        )
        run_id = r.json()["run_id"]
        _wait_for_run(run_id)
        rep = client.get(f"/runs/{run_id}/report")
        assert rep.status_code == 200
        body = rep.json()
        assert body["markdown_report"].endswith(".md")
        assert body["findings_csv"].endswith(".csv")
