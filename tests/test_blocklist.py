from sdn_ddos.blocklist import BlockList


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_blocked_until_duration_elapses():
    clock = FakeClock()
    blocklist = BlockList(30, clock)
    blocklist.block("10.0.0.1")
    assert blocklist.is_blocked("10.0.0.1")
    clock.now += 30
    assert not blocklist.is_blocked("10.0.0.1")


def test_is_blocked_has_no_side_effects():
    clock = FakeClock()
    blocklist = BlockList(5, clock)
    blocklist.block("10.0.0.1")
    clock.now += 10
    blocklist.is_blocked("10.0.0.1")
    assert len(blocklist) == 1


def test_pop_expired_returns_and_removes_only_expired():
    clock = FakeClock()
    blocklist = BlockList(10, clock)
    blocklist.block("10.0.0.1")
    clock.now += 6
    blocklist.block("10.0.0.2")
    clock.now += 6
    assert blocklist.pop_expired() == ["10.0.0.1"]
    assert blocklist.is_blocked("10.0.0.2")
    assert blocklist.pop_expired() == []
