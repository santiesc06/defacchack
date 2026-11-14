"""Registro de Policy Packs. Agregar un dominio = escribir un pack y registrarlo aquí."""
from __future__ import annotations

import importlib

from .base import DecisionPack, EjecucionRechazada, PolicyPack, RegistroAccion  # noqa: F401

PACKS = {
    "pagos_iso42001": ("firewall.packs.pagos_iso42001", "PackPagosISO42001"),
    "devops_cloud": ("firewall.packs.devops_cloud", "PackDevOpsCloud"),
}
PACK_POR_DEFECTO = "pagos_iso42001"


def crear_pack(pack_id: str, reloj) -> PolicyPack:
    if pack_id not in PACKS:
        raise ValueError(f"Policy Pack desconocido: {pack_id}. Disponibles: {', '.join(PACKS)}")
    modulo, clase = PACKS[pack_id]
    return getattr(importlib.import_module(modulo), clase)(reloj)


def listar_packs() -> list[dict]:
    out = []
    for pid, (modulo, clase) in PACKS.items():
        c = getattr(importlib.import_module(modulo), clase)
        out.append({"id": pid, "nombre": c.nombre, "descripcion": c.descripcion})
    return out
