import json
import statistics

from agent_redteam.adapters.mock_agent import MockAgent
from agent_redteam.core.benchmark import (
    _percentile,
    benchmark_suite,
    measure_artifact_size,
)
from agent_redteam.core.runner import RunOptions, execute_run


class TestPercentile:
    def test_known_values(self):
        assert _percentile([1, 2, 3, 4, 5], 95) == 5
        assert _percentile([10, 20, 30, 40], 50) == 30  # round(0.5*3)=2 -> index 2
        assert _percentile([], 95) == 0.0

    def test_within_statistical_tolerance(self):
        data = [float(x) for x in range(1, 101)]
        expected = statistics.quantiles(data, n=100)[-1]  # 95th, exclusive method
        assert abs(_percentile(data, 95) - expected) <= 5


class TestBenchmarkSuite:
    def test_throughput_and_counts(self, suite_path):
        result = benchmark_suite(
            suite_path, MockAgent(profile="weak"), iterations=2, rate_limit_s=0
        )
        assert result.total_cases == 26  # 13 cases x 2 iterations
        assert result.cases_per_second > 0
        assert result.wall_time_s > 0
        assert result.avg_latency_ms >= 0
        assert result.p95_latency_ms >= result.avg_latency_ms - 1e-9
        assert result.timeout_rate == 0.0
        assert result.error_rate == 0.0
        assert result.target == "mock:weak"

    def test_tool_calls_counted(self, suite_path):
        result = benchmark_suite(suite_path, MockAgent(profile="weak"), iterations=1, rate_limit_s=0)
        # weak agent calls read_file / send_email / delete_file across the suite
        assert result.tool_call_count >= 3

    def test_strong_target_zero_failures(self, suite_path):
        result = benchmark_suite(suite_path, MockAgent(profile="strong"), iterations=1, rate_limit_s=0)
        assert result.timeout_rate == 0.0
        assert result.error_rate == 0.0

    def test_json_roundtrip(self, suite_path):
        import dataclasses

        result = benchmark_suite(suite_path, MockAgent(profile="weak"), iterations=1, rate_limit_s=0)
        payload = json.dumps(dataclasses.asdict(result))
        restored = json.loads(payload)
        assert restored["total_cases"] == result.total_cases


class TestArtifactSize:
    def test_measures_run_artifacts(self, tmp_path, weak_agent, suite_path):
        rid, _summary, _results, _records = execute_run(
            suite_path, weak_agent, RunOptions(output_dir=tmp_path), run_id="run-bench"
        )
        size = measure_artifact_size(tmp_path / rid)
        assert size > 0
