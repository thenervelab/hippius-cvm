"""Metrics rendering + Pushgateway push semantics."""

from __future__ import annotations

from apps.synthetic import metrics


def test_render_emits_help_type_and_labels() -> None:
    ms = metrics.MetricSet()
    ms.gauge("hippius_synthetic_e2e_success", 1, help_text="ok")
    ms.gauge("hippius_synthetic_e2e_stage_success", 0, stage="boot")
    ms.gauge("hippius_synthetic_e2e_stage_success", 1, stage="launch")
    text = ms.render()
    assert "# HELP hippius_synthetic_e2e_success ok" in text
    assert "# TYPE hippius_synthetic_e2e_success gauge" in text
    assert "hippius_synthetic_e2e_success 1" in text
    # Same metric name declares HELP/TYPE only once.
    assert text.count("# TYPE hippius_synthetic_e2e_stage_success gauge") == 1
    assert 'hippius_synthetic_e2e_stage_success{stage="boot"} 0' in text
    assert 'hippius_synthetic_e2e_stage_success{stage="launch"} 1' in text


def test_grouping_path_encodes_key() -> None:
    path = metrics._grouping_path("synthetic-monitor", {"tier": "full", "distro": "cs10"})
    # sorted keys → distro before tier.
    assert path == "metrics/job/synthetic-monitor/distro/cs10/tier/full"


def test_push_selects_put_on_success_post_on_failure(monkeypatch) -> None:
    seen: dict[str, str] = {}

    class _Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b""

    def fake_urlopen(req, timeout=0):
        seen["method"] = req.get_method()
        seen["url"] = req.full_url
        return _Resp()

    monkeypatch.setattr(metrics.urllib.request, "urlopen", fake_urlopen)

    ms = metrics.MetricSet()
    ms.gauge("x", 1)
    assert metrics.push(
        ms, gateway_url="http://gw:9091", job="j", grouping_key={"tier": "light"}, replace=True
    )
    assert seen["method"] == "PUT"
    assert seen["url"] == "http://gw:9091/metrics/job/j/tier/light"

    assert metrics.push(
        ms, gateway_url="http://gw:9091", job="j", grouping_key={"tier": "light"}, replace=False
    )
    assert seen["method"] == "POST"


def test_push_empty_gateway_is_noop_success() -> None:
    ms = metrics.MetricSet()
    ms.gauge("x", 1)
    assert metrics.push(ms, gateway_url="", job="j", grouping_key={}, replace=True) is True


def test_push_never_raises_on_network_error(monkeypatch) -> None:
    def boom(req, timeout=0):
        raise OSError("connection refused")

    monkeypatch.setattr(metrics.urllib.request, "urlopen", boom)
    ms = metrics.MetricSet()
    ms.gauge("x", 1)
    # A push failure must not propagate (it can't be allowed to mask the probe).
    assert (
        metrics.push(ms, gateway_url="http://gw:9091", job="j", grouping_key={}, replace=True)
        is False
    )
