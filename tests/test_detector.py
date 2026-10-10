import pytest

from sdn_ddos.config import DetectorConfig
from sdn_ddos.detector import AnomalyDetector
from sdn_ddos.models import DetectionStatus

IP = "10.0.0.1"


@pytest.fixture
def detector():
    return AnomalyDetector(DetectorConfig(baseline_samples=5, required_anomalies=2))


def _train(detector, value=10.0, times=5):
    for _ in range(times):
        detector.evaluate(IP, value)


def test_first_samples_build_baseline(detector):
    result = detector.evaluate(IP, 10.0)
    assert result.status is DetectionStatus.BASELINE
    assert result.baseline_size == 1


def test_normal_traffic_is_not_flagged(detector):
    _train(detector)
    assert detector.evaluate(IP, 10.0).status is DetectionStatus.NORMAL


def test_blocks_only_after_consecutive_anomalies(detector):
    _train(detector)
    first = detector.evaluate(IP, 500.0)
    second = detector.evaluate(IP, 500.0)
    assert first.status is DetectionStatus.ANOMALY and not first.should_block
    assert second.should_block and second.consecutive_anomalies == 2


def test_normal_sample_resets_streak(detector):
    _train(detector)
    detector.evaluate(IP, 500.0)
    detector.evaluate(IP, 10.0)
    assert not detector.evaluate(IP, 500.0).should_block


def test_anomalies_do_not_pollute_baseline(detector):
    _train(detector)
    detector.evaluate(IP, 500.0)
    assert detector.evaluate(IP, 10.0).mean == pytest.approx(10.0)


def test_streak_restarts_after_block(detector):
    _train(detector)
    detector.evaluate(IP, 500.0)
    assert detector.evaluate(IP, 500.0).should_block
    assert not detector.evaluate(IP, 500.0).should_block


def test_ips_are_tracked_independently(detector):
    _train(detector)
    assert detector.evaluate("10.0.0.2", 500.0).status is DetectionStatus.BASELINE
