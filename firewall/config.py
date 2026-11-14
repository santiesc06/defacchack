"""Parámetros de política (Matriz 3) y constantes.

Los montos son ejemplos parametrizables en COP (Matriz 3). Su modificación sigue el
control de cambios (ISO 27001 8.32): ningún agente puede escribir este módulo.
"""
from __future__ import annotations

import os
from enum import StrEnum
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def cargar_env(ruta: Path = ROOT / ".env") -> None:
    """Lee el archivo .env de la raíz. Las variables ya definidas en la terminal tienen prioridad.
    CFZT_SIN_ENV=1 lo ignora (lo usan las pruebas y el validador de bases)."""
    if os.environ.get("CFZT_SIN_ENV") or not ruta.exists():
        return
    for linea in ruta.read_text(encoding="utf-8").splitlines():
        linea = linea.strip()
        if not linea or linea.startswith("#") or "=" not in linea:
            continue
        clave, valor = linea.split("=", 1)
        clave = clave.strip().removeprefix("export ").strip()
        valor = valor.strip()
        if valor.startswith(f"{clave}="):  # tolera el error común CLAVE=CLAVE="valor"
            valor = valor[len(clave) + 1:].strip()
        if len(valor) >= 2 and valor[0] == valor[-1] and valor[0] in "'\"":
            valor = valor[1:-1]
        if clave:
            os.environ.setdefault(clave, valor)


cargar_env()
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


class Modo(StrEnum):
    """Configuraciones comparables (misma base de código, mismos escenarios).

    Sirven para responder: ¿cada componente funciona por sí solo?, ¿la arquitectura completa gana a
    un único modelo que verifica?
    """
    COMPLETO = "COMPLETO"              # Sanitizer + PEP determinista + firmas humanas
    SOLO_PEP = "SOLO_PEP"              # PEP + firmas, sin Sanitizer semántico
    SOLO_SANITIZER = "SOLO_SANITIZER"  # el Sanitizer bloquea si el riesgo es ALTO; si no, se paga directo
    SOLO_LLM = "SOLO_LLM"              # un único modelo revisa correo + propuesta + maestro y decide
    SIN_DEFENSA = "SIN_DEFENSA"        # confianza implícita: la herramienta va directo al servicio de pagos


DESCRIPCION_MODO = {
    Modo.COMPLETO: "Sanitizer + PEP determinista + firmas humanas",
    Modo.SOLO_PEP: "PEP determinista + firmas, sin Sanitizer",
    Modo.SOLO_SANITIZER: "Solo el Sanitizer: bloquea riesgo ALTO, el resto se paga sin más controles",
    Modo.SOLO_LLM: "Solo un modelo verificador (LLM-como-juez): aprueba o bloquea, sin Sanitizer ni PEP",
    Modo.SIN_DEFENSA: "Sin defensa: confianza implícita en los agentes",
}
MODOS_CON_PEP = frozenset({Modo.COMPLETO, Modo.SOLO_PEP})
MODOS_CON_SANITIZER = frozenset({Modo.COMPLETO, Modo.SOLO_SANITIZER})


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


class RolDevOps(StrEnum):
    """Roles del Policy Pack devops_cloud (Oficial de Seguridad, Admin de plataforma y Auditor son universales)."""
    DEVOPS_SENIOR = "DEVOPS_SENIOR"
    LIDER_SRE = "LIDER_SRE"
    INGENIERO_SOPORTE = "INGENIERO_SOPORTE"


ETIQUETA_ROL.update({
    RolDevOps.DEVOPS_SENIOR: "Ingeniero DevOps Senior",
    RolDevOps.LIDER_SRE: "Líder SRE / Seguridad",
    RolDevOps.INGENIERO_SOPORTE: "Ingeniero de soporte (triaje)",
})
ROLES_QUE_PUEDEN_RECHAZAR = ROLES_QUE_PUEDEN_RECHAZAR | {RolDevOps.DEVOPS_SENIOR, RolDevOps.LIDER_SRE}


def etiqueta_rol(rol: str) -> str:
    return ETIQUETA_ROL.get(rol, str(rol))

# --- Proveedor LLM (P1) --------------------------------------------------------------
LLM_PROVIDER = os.environ.get("CFZT_LLM", "local").lower()      # local | groq | gemini
LLM_MODEL = os.environ.get("CFZT_LLM_MODEL", "")


def formato_cop(monto: int | None) -> str:
    if not isinstance(monto, int) or isinstance(monto, bool):
        return "—"
    return "$" + f"{monto:,}".replace(",", ".") + " COP"
