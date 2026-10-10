import pytest

from sdn_ddos.config import DetectorConfig
from sdn_ddos.exceptions import ConfigurationError
from sdn_ddos.host_table import HostTable


def test_defaults_are_valid():
    assert DetectorConfig().block_time == 30


@pytest.mark.parametrize(
    "overrides",
    [
        {"block_time": 0},        # 0 = bloqueio permanente no OpenFlow
        {"block_time": 70000},    # estoura o uint16
        {"baseline_samples": 1},  # stdev precisa de 2+ amostras
        {"history_size": 3},
        {"monitor_interval": 0},
        {"min_rate_factor": 0.5},
    ],
)
def test_invalid_values_are_rejected(overrides):
    with pytest.raises(ConfigurationError):
        DetectorConfig(**overrides)


def test_from_env_overrides_and_casts():
    cfg = DetectorConfig.from_env({"SDN_DDOS_BLOCK_TIME": "60", "SDN_DDOS_MONITOR_INTERVAL": "2.5"})
    assert cfg.block_time == 60 and cfg.monitor_interval == 2.5


def test_from_env_rejects_garbage():
    with pytest.raises(ConfigurationError):
        DetectorConfig.from_env({"SDN_DDOS_BLOCK_TIME": "abc"})


def test_host_table_is_scoped_per_switch():
    table = HostTable()
    table.learn_mac(1, "aa", 3)
    table.learn_ip(1, "10.0.0.1", 3)
    assert table.port_for_mac(2, "aa") is None
    assert table.ip_for_port(2, 3) is None
    assert table.ip_for_port(1, 3) == "10.0.0.1"


def test_host_table_ignores_unspecified_ip_and_forgets_switch():
    table = HostTable()
    table.learn_ip(1, "0.0.0.0", 1)
    assert table.ip_for_port(1, 1) is None
    table.learn_ip(1, "10.0.0.1", 1)
    table.forget_switch(1)
    assert table.ip_for_port(1, 1) is None
