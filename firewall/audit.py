"""Registro de auditoría append-only con cadena SHA-256.

La implementación vive en el núcleo universal (`cfzt/ledger.py`); este módulo la reexporta
para el firewall y los Policy Packs.
"""
from cfzt.ledger import GENESIS, AuditLogSHA256, _canonico, _hash  # noqa: F401
