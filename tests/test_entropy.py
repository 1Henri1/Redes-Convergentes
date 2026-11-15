import pytest

from sdn_ddos.config import DetectorConfig
from sdn_ddos.entropy import DestinationEntropyDetector, shannon_entropy


def test_entropy_is_zero_for_single_source():
    entropy, normalized, sources, packets = shannon_entropy({"10.0.0.1": 50})
    assert entropy == pytest.approx(0.0)
    assert normalized == pytest.approx(0.0)
    assert sources == 1
    assert packets == 50


def test_uniform_four_sources_have_two_bits_of_entropy():
    entropy, normalized, sources, packets = shannon_entropy({
        "10.0.0.1": 10,
        "10.0.0.2": 10,
        "10.0.0.3": 10,
        "10.0.0.4": 10,
    })
    assert entropy == pytest.approx(2.0)
    assert normalized == pytest.approx(1.0)
    assert sources == 4
    assert packets == 40


def test_zero_packet_sources_are_ignored():
    entropy, normalized, sources, packets = shannon_entropy({
        "10.0.0.1": 10,
        "10.0.0.2": 0,
    })
    assert entropy == pytest.approx(0.0)
    assert normalized == pytest.approx(0.0)
    assert sources == 1
    assert packets == 10


def test_distributed_entropy_is_detected_without_polluting_baseline():
    detector = DestinationEntropyDetector(
        DetectorConfig(baseline_samples=3, history_size=10)
    )
    for _ in range(3):
        result = detector.evaluate({"10.0.0.1": 20, "10.0.0.2": 20})
    assert result.baseline_ready

    result = detector.evaluate({
        "10.0.0.1": 10,
        "10.0.0.2": 10,
        "10.0.0.3": 10,
        "10.0.0.4": 10,
    }, update_baseline=False)

    assert result.anomalous
    assert result.source_count == 4
    assert result.entropy_bits == pytest.approx(2.0)
    assert result.baseline_size == 3


def test_entropy_alone_does_not_classify_one_source_as_distributed():
    detector = DestinationEntropyDetector(
        DetectorConfig(baseline_samples=2, history_size=10)
    )
    detector.evaluate({"10.0.0.1": 10, "10.0.0.2": 10})
    detector.evaluate({"10.0.0.1": 10, "10.0.0.2": 10})

    result = detector.evaluate({"10.0.0.1": 100}, update_baseline=False)
    assert not result.anomalous
    assert result.source_count == 1


def test_normal_entropy_updates_baseline():
    detector = DestinationEntropyDetector(
        DetectorConfig(baseline_samples=2, history_size=10)
    )
    detector.evaluate({"10.0.0.1": 10, "10.0.0.2": 10})
    detector.evaluate({"10.0.0.1": 10, "10.0.0.2": 10})

    result = detector.evaluate({"10.0.0.1": 12, "10.0.0.2": 12})
    assert not result.anomalous
    assert result.baseline_size == 3


def test_entropy_spike_requests_block_after_required_consecutive_windows():
    detector = DestinationEntropyDetector(
        DetectorConfig(
            baseline_samples=3, history_size=10, required_anomalies=2,
            minimum_entropy_factor=1.5,
        )
    )
    for _ in range(3):
        detector.evaluate({"10.0.0.1": 20})

    spike = {
        "10.0.0.1": 10, "10.0.0.2": 10,
        "10.0.0.3": 10, "10.0.0.4": 10,
    }
    first = detector.evaluate(spike, update_baseline=False)
    second = detector.evaluate(spike, update_baseline=False)

    assert first.anomalous and first.consecutive_anomalies == 1
    assert not first.should_block
    assert second.anomalous and second.consecutive_anomalies == 2
    assert second.should_block
    assert second.baseline_size == 3


def test_normal_entropy_resets_anomaly_streak():
    detector = DestinationEntropyDetector(
        DetectorConfig(
            baseline_samples=2, history_size=10, required_anomalies=2,
            minimum_entropy_factor=1.5,
        )
    )
    detector.evaluate({"10.0.0.1": 10, "10.0.0.2": 10})
    detector.evaluate({"10.0.0.1": 10, "10.0.0.2": 10})
    spike = {"10.0.0.1": 10, "10.0.0.2": 10, "10.0.0.3": 10}

    first = detector.evaluate(spike, update_baseline=False)
    normal = detector.evaluate({"10.0.0.1": 10}, update_baseline=False)
    last = detector.evaluate(spike, update_baseline=False)

    assert first.anomalous and first.consecutive_anomalies == 1
    assert not normal.anomalous
    assert last.anomalous and last.consecutive_anomalies == 1
    assert not last.should_block



def test_empty_and_single_source_windows_do_not_enter_entropy_baseline():
    detector = DestinationEntropyDetector(
        DetectorConfig(baseline_samples=5, history_size=10)
    )

    empty = detector.evaluate({})
    single = detector.evaluate({"10.0.0.1": 10})
    assert empty.baseline_size == 0
    assert single.baseline_size == 0
    assert not empty.baseline_ready
    assert not single.baseline_ready

    result = None
    for _ in range(5):
        result = detector.evaluate({
            "10.0.0.1": 10,
            "10.0.0.2": 10,
            "10.0.0.3": 10,
            "10.0.0.4": 10,
        })

    assert result is not None and result.baseline_ready
    assert result.baseline_size == 5
    assert result.mean == pytest.approx(2.0)
    assert result.std == pytest.approx(0.0)


def test_baseline_completion_sample_is_not_added_twice():
    detector = DestinationEntropyDetector(
        DetectorConfig(baseline_samples=3, history_size=10)
    )
    counts = {"10.0.0.1": 10, "10.0.0.2": 10}

    detector.evaluate(counts)
    detector.evaluate(counts)
    result = detector.evaluate(counts)

    assert result.baseline_ready
    assert result.baseline_size == 3
    assert result.mean == pytest.approx(1.0)
    assert result.std == pytest.approx(0.0)
