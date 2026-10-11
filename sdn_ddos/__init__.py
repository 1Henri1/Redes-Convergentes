"""Controlador SDN com detecção estatística de DDoS e bloqueio temporário.

Este ``__init__`` é deliberadamente vazio de imports: os módulos de domínio
(``detector``, ``blocklist``, ``traffic_meter``...) não dependem do OS-Ken e
devem poder ser importados (e testados) sem ele instalado.
"""

__version__ = "1.0.0"
