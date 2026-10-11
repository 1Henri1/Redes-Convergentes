import pytest

from sdn_ddos.traffic_meter import PortRateCalculator


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


@pytest.fixture
def clock():
    return FakeClock()


def test_first_reading_has_no_rate(clock):
    assert PortRateCalculator(clock).update((1, 1), 100, 10_000) is None


def test_rate_is_delta_over_elapsed(clock):
    meter = PortRateCalculator(clock)
    meter.update((1, 1), 100, 10_000)
    clock.now = 5
    rate = meter.update((1, 1), 150, 12_500)
    assert rate.pps == pytest.approx(10.0)
    assert rate.bps == pytest.approx(500.0)
    assert rate.delta_packets == 50


def test_counter_reset_is_ignored_and_rebased(clock):
    meter = PortRateCalculator(clock)
    meter.update((1, 1), 1000, 1000)
    clock.now = 5
    assert meter.update((1, 1), 10, 10) is None  # switch reiniciou
    clock.now = 10
    assert meter.update((1, 1), 60, 60).pps == pytest.approx(10.0)


def test_forget_switch_only_drops_that_switch(clock):
    meter = PortRateCalculator(clock)
    meter.update((1, 1), 0, 0)
    meter.update((2, 1), 0, 0)
    meter.forget_switch(1)
    clock.now = 1
    assert meter.update((1, 1), 10, 10) is None
    assert meter.update((2, 1), 10, 10) is not None
