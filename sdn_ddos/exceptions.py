"""Exceções específicas do projeto."""


class SdnDdosError(Exception):
    """Classe base de todas as exceções levantadas por este pacote."""


class ConfigurationError(SdnDdosError):
    """Levantada quando um parâmetro de configuração é inválido."""
