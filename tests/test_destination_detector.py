import pytest

from sdn_ddos.config import DetectorConfig
from sdn_ddos.detector import DestinationPpsDetector
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
