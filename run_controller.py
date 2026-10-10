#!/usr/bin/env python3
"""Ponto de entrada: inicia o controlador SDN.

Uso (na raiz do projeto, com o ambiente virtual ativo)::

    python run_controller.py

Equivalente a ``osken-manager sdn_ddos.app``.
"""

import logging
import sys

from os_ken.base import app_manager

from sdn_ddos.exceptions import SdnDdosError
from sdn_ddos.logging_setup import configure_logging

APP_MODULE = "sdn_ddos.app"


def main() -> int:
    """Inicia o OS-Ken com a aplicação do projeto.

    Returns:
        Código de saída do processo (0 = encerramento normal).
    """
    logger = configure_logging()
    try:
        app_manager.AppManager.get_instance().run_apps([APP_MODULE])
    except KeyboardInterrupt:
        logger.info("Controlador encerrado pelo usuário.")
    except SdnDdosError as exc:
        # Erros previstos (ex.: configuração inválida): mensagem limpa, sem traceback.
        logger.error("Erro de configuração: %s", exc)
        return 2
    except Exception:  # noqa: BLE001
        logging.getLogger(logger.name).exception("Erro fatal no controlador")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
