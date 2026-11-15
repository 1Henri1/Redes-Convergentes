import statistics
from types import SimpleNamespace

import pytest

from sdn_ddos.config import DetectorConfig
from sdn_ddos.detector import DestinationConnectionDetector, DestinationPpsDetector
from sdn_ddos.models import DetectionStatus


def make_config(**overrides):
    values = {
        "baseline_samples": 5,
        "history_size": 20,
        "threshold_factor": 3.0,
        "min_rate_factor": 1.5,
        "minimum_pps": 10.0,
        "required_anomalies": 2,
    }
    values.update(overrides)
    return DetectorConfig(**values)


def train(detector, values):
    result = None
    for value in values:
        result = detector.evaluate(value)
    return result


def test_destination_builds_its_own_baseline():
    detector = DestinationPpsDetector(make_config())

    result = train(detector, [100, 100, 100, 100, 100])

    assert result.status is DetectionStatus.BASELINE
    assert result.baseline_size == 5


def test_destination_uses_mean_plus_three_sigma_with_minimum_guard():
    detector = DestinationPpsDetector(make_config())
    train(detector, [100, 100, 100, 100, 100])

    result = detector.evaluate(140)

    assert result.status is DetectionStatus.NORMAL
    assert result.mean == pytest.approx(100)
    assert result.std == pytest.approx(0)
    assert result.limit == pytest.approx(150)


def test_persistent_destination_anomaly_requests_block():
    detector = DestinationPpsDetector(make_config())
    train(detector, [100, 100, 100, 100, 100])

    first = detector.evaluate(200)
    second = detector.evaluate(200)

    assert first.status is DetectionStatus.ANOMALY
    assert not first.should_block
    assert second.status is DetectionStatus.ANOMALY
    assert second.should_block


def test_anomalies_do_not_enter_destination_baseline():
    detector = DestinationPpsDetector(make_config())
    train(detector, [100, 100, 100, 100, 100])

    detector.evaluate(200)
    result = detector.evaluate(100)

    assert result.status is DetectionStatus.NORMAL
    assert result.mean == pytest.approx(100)


def test_each_destination_can_have_a_different_baseline():
    server_a = DestinationPpsDetector(make_config())
    server_b = DestinationPpsDetector(make_config())
    train(server_a, [100, 100, 100, 100, 100])
    train(server_b, [300, 300, 300, 300, 300])

    result_a = server_a.evaluate(140)
    result_b = server_b.evaluate(350)

    assert result_a.status is DetectionStatus.NORMAL
    assert result_b.status is DetectionStatus.NORMAL
    assert result_a.mean == pytest.approx(100)
    assert result_b.mean == pytest.approx(300)


def test_zero_baseline_uses_absolute_pps_floor():
    detector = DestinationPpsDetector(make_config(minimum_pps=10))
    train(detector, [0, 0, 0, 0, 0])

    result = detector.evaluate(8)

    assert result.status is DetectionStatus.NORMAL
    assert result.limit == pytest.approx(10)


def test_new_destination_collects_five_real_baseline_cycles():
    detector = DestinationPpsDetector(make_config())

    assert not detector.baseline_ready
    for cycle in range(4):
        result = detector.evaluate(0)
        assert result.status is DetectionStatus.BASELINE
        assert result.baseline_size == cycle + 1
        assert not detector.baseline_ready

    result = detector.evaluate(0)
    assert result.status is DetectionStatus.BASELINE
    assert result.baseline_size == 5
    assert detector.baseline_ready

    # A sexta janela já é avaliada contra a baseline de cinco ciclos.
    result = detector.evaluate(20)
    assert result.status is DetectionStatus.ANOMALY
    assert result.mean == pytest.approx(0)
    assert result.limit == pytest.approx(10)


def test_bytes_detector_uses_relative_limit_without_absolute_pps_floor():
    detector = DestinationPpsDetector(make_config(minimum_pps=10.0))
    train(detector, [10000, 10000, 10000, 10000, 10000])

    first = detector.evaluate(20000, minimum_rate=0.0)
    second = detector.evaluate(20000, minimum_rate=0.0)

    assert first.status is DetectionStatus.ANOMALY
    assert first.limit == pytest.approx(15000)
    assert not first.should_block
    assert second.status is DetectionStatus.ANOMALY
    assert second.should_block


def test_bytes_detector_does_not_use_pps_absolute_floor():
    detector = DestinationPpsDetector(make_config(minimum_pps=10.0))
    train(detector, [2, 2, 2, 2, 2])

    result = detector.evaluate(3.0, minimum_rate=0.0)

    assert result.status is DetectionStatus.NORMAL
    assert result.limit == pytest.approx(3.0)


def connection(pps, bps):
    return SimpleNamespace(pps=pps, bps=bps)


def test_connection_detector_uses_destination_mean_and_std_for_every_origin():
    detector = DestinationConnectionDetector(make_config())
    normal = {f"10.0.0.{i}": connection(10, 100) for i in range(1, 11)}
    detector.evaluate(normal, 1)

    rates = dict(normal)
    rates["10.0.0.10"] = connection(30, 300)
    first = detector.evaluate(rates, 2)

    assert first["10.0.0.10"]["PPS"].status is DetectionStatus.ANOMALY
    assert first["10.0.0.10"]["PPS"].mean == pytest.approx(120 / 11)
    assert first["10.0.0.10"]["PPS"].std == pytest.approx(20 / (11 ** 0.5), rel=0.02)
    assert first["10.0.0.10"]["PPS"].limit == pytest.approx((120 / 11) + 3 * statistics.stdev([10] * 10 + [30]))
    assert first["10.0.0.10"]["BYTES/S"].status is DetectionStatus.ANOMALY
    assert not first["10.0.0.10"]["PPS"].should_block

    second = detector.evaluate(rates, 3)
    assert second["10.0.0.10"]["PPS"].should_block
    assert second["10.0.0.10"]["BYTES/S"].should_block


def test_two_origins_have_shared_destination_threshold_and_high_spread():
    detector = DestinationConnectionDetector(make_config())
    rates = {
        "10.0.0.1": connection(10, 100),
        "10.0.0.2": connection(30, 300),
    }

    first = detector.evaluate(rates, 1)
    second = detector.evaluate(rates, 2)

    assert first["10.0.0.2"]["PPS"].status is DetectionStatus.NORMAL
    assert first["10.0.0.2"]["PPS"].mean == pytest.approx(20)
    assert first["10.0.0.2"]["PPS"].limit > 30
    assert second["10.0.0.2"]["PPS"].status is DetectionStatus.NORMAL


def test_uniform_increase_is_not_individual_dos():
    detector = DestinationConnectionDetector(make_config())
    normal = {f"10.0.0.{i}": connection(10, 100) for i in range(1, 11)}
    detector.evaluate(normal, 1)

    increased = {src: connection(20, 200) for src in normal}
    result = detector.evaluate(increased, 2)

    assert all(item["PPS"].status is DetectionStatus.NORMAL for item in result.values())
    assert all(item["BYTES/S"].status is DetectionStatus.NORMAL for item in result.values())


def test_outlier_streak_resets_when_origin_returns_to_normal():
    detector = DestinationConnectionDetector(make_config())
    normal = {f"10.0.0.{i}": connection(10, 100) for i in range(1, 5)}
    detector.evaluate(normal, 1)

    attacked = dict(normal)
    attacked["10.0.0.4"] = connection(30, 300)
    detector.evaluate(attacked, 2)
    result = detector.evaluate(normal, 3)

    assert result["10.0.0.4"]["PPS"].status is DetectionStatus.NORMAL
    assert result["10.0.0.4"]["PPS"].mean == pytest.approx(10)



def test_aggregate_detector_can_skip_anomalous_baseline_samples():
    detector = DestinationPpsDetector(make_config())
    for _ in range(4):
        detector.evaluate(100)
    skipped = detector.evaluate(500, update_baseline=False)

    assert skipped.status is DetectionStatus.BASELINE
    assert skipped.baseline_size == 4

    ready = detector.evaluate(100)
    assert ready.status is DetectionStatus.BASELINE
    assert ready.baseline_size == 5
