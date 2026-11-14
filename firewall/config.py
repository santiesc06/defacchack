"""Parámetros de política (Matriz 3) y constantes.

Los montos son ejemplos parametrizables en COP (Matriz 3). Su modificación sigue el
control de cambios (ISO 27001 8.32): ningún agente puede escribir este módulo.
"""
from __future__ import annotations

import os
from enum import StrEnum
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNTIME_DIR = Path(os.environ.get("CFZT_RUNTIME_DIR", ROOT / "runtime"))

# --- Matriz 3: umbrales (COP) -------------------------------------------------------
UMBRAL_BAJO_COP = 2_000_000        # hasta aquí, riesgo bajo -> Analista + Tesorero
UMBRAL_ALTO_COP = 20_000_000       # más de esto -> + Director financiero
DIAS_CUENTA_RECIENTE = 30          # cuenta modificada en los últimos N días
HORAS_VIGENCIA_FIRMA = 48          # las firmas vencen -> EXPIRADA
DIAS_RESTRICCION_SOD_CAMBIO_CUENTA = 30

SALDO_INICIAL_COP = 250_000_000


class Rol(StrEnum):
    ANALISTA_CXP = "ANALISTA_CXP"
    TESORERO = "TESORERO"
    DIRECTOR_FINANCIERO = "DIRECTOR_FINANCIERO"
    ADMIN_PROVEEDORES = "ADMIN_PROVEEDORES"
    OFICIAL_SEGURIDAD = "OFICIAL_SEGURIDAD"
    ADMIN_PLATAFORMA = "ADMIN_PLATAFORMA"
    AUDITOR = "AUDITOR"


ROLES_QUE_PUEDEN_RECHAZAR = frozenset({Rol.ANALISTA_CXP, Rol.TESORERO, Rol.DIRECTOR_FINANCIERO,
                                       Rol.OFICIAL_SEGURIDAD})

ETIQUETA_ROL = {
    Rol.ANALISTA_CXP: "Analista de cuentas por pagar",
    Rol.TESORERO: "Tesorero",
    Rol.DIRECTOR_FINANCIERO: "Director financiero",
    Rol.ADMIN_PROVEEDORES: "Administrador de proveedores",
    Rol.OFICIAL_SEGURIDAD: "Oficial de seguridad y cumplimiento",
    Rol.ADMIN_PLATAFORMA: "Administrador de plataforma",
    Rol.AUDITOR: "Auditor",
}

# --- Proveedor LLM (P1) --------------------------------------------------------------
LLM_PROVIDER = os.environ.get("CFZT_LLM", "local").lower()      # local | groq | gemini
LLM_MODEL = os.environ.get("CFZT_LLM_MODEL", "")


def formato_cop(monto: int | None) -> str:
    if not isinstance(monto, int) or isinstance(monto, bool):
        return "—"
    return "$" + f"{monto:,}".replace(",", ".") + " COP"
