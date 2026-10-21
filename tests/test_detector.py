import pytest

from sdn_ddos.config import DetectorConfig
from sdn_ddos.detector import AnomalyDetector
from sdn_ddos.models import DetectionStatus

IP1 = "10.0.0.1"
IP2 = "10.0.0.2"


@pytest.fixture
def detector():
    return AnomalyDetector(
        DetectorConfig(
            baseline_samples=5,
            required_anomalies=2,
        )
    )


def train(detector, ip=IP1, value=10.0, times=5):
    for _ in range(times):
        detector.evaluate(ip, value)


def test_first_ip_builds_global_baseline(detector):
    for i in range(5):
        result = detector.evaluate(IP1, 10.0)
        assert result.status is DetectionStatus.BASELINE
        assert result.baseline_size == i + 1


def test_other_ip_is_checked_immediately(detector):
    train(detector)

    result = detector.evaluate(IP2, 500.0)

    assert result.status is DetectionStatus.ANOMALY


def test_normal_traffic_updates_global_history(detector):
    train(detector)

    result = detector.evaluate(IP2, 10.0)

    assert result.status is DetectionStatus.NORMAL
    assert result.mean == pytest.approx(10.0)


def test_anomalies_do_not_pollute_global_history(detector):
    train(detector)

    detector.evaluate(IP2, 500.0)
    result = detector.evaluate(IP2, 10.0)

    assert result.status is DetectionStatus.NORMAL
    assert result.mean == pytest.approx(10.0)


def test_blocks_after_consecutive_anomalies(detector):
    train(detector)

    first = detector.evaluate(IP2, 500.0)
    second = detector.evaluate(IP2, 500.0)

    assert first.status is DetectionStatus.ANOMALY
    assert not first.should_block
    assert second.should_block


def test_normal_traffic_resets_anomaly_streak(detector):
    train(detector)

    detector.evaluate(IP2, 500.0)
    detector.evaluate(IP2, 10.0)
    result = detector.evaluate(IP2, 500.0)

    assert not result.should_block


def test_first_ip_alone_initializes_baseline():
    detector = AnomalyDetector(
        DetectorConfig(baseline_samples=5)
    )

    detector.evaluate(IP1, 10.0)
    other_result = detector.evaluate(IP2, 500.0)
    assert other_result.status is DetectionStatus.BASELINE

    for _ in range(4):
        detector.evaluate(IP1, 10.0)

    result = detector.evaluate(IP2, 500.0)
    assert result.status is DetectionStatus.ANOMALY
