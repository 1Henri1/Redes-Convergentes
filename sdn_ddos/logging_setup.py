"""Configuração de logging do projeto."""

import logging
import os
import sys
from typing import Optional

from .exceptions import ConfigurationError

LOGGER_NAME = "sdn_ddos"
LOG_LEVEL_ENV = "SDN_DDOS_LOG_LEVEL"


def configure_logging(level: Optional[str] = None) -> logging.Logger:
    """Configura (de forma idempotente) o logger do projeto.

    Só o logger ``sdn_ddos`` é configurado, e não o root: assim os logs
    verbosos do próprio OS-Ken não poluem a saída do controlador.

    Args:
        level: Nível (``DEBUG``, ``INFO``...). Padrão: ``$SDN_DDOS_LOG_LEVEL``
            ou ``INFO``.

    Returns:
        O logger configurado.

    Raises:
        ConfigurationError: Se o nível informado não existir.
    """
    level_name = (level or os.environ.get(LOG_LEVEL_ENV, "INFO")).upper()
    numeric_level = logging.getLevelName(level_name)
    if not isinstance(numeric_level, int):
        raise ConfigurationError(f"Nível de log inválido: {level_name!r}")

    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(numeric_level)
    logger.propagate = False

    # Evita handlers duplicados se a função for chamada mais de uma vez.
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            logging.Formatter("%(asctime)s | %(levelname)-7s | %(message)s", "%H:%M:%S")
        )
        logger.addHandler(handler)
    return logger
