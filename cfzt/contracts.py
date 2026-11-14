"""Contratos mínimos de Context Firewall Zero-Trust.

Regla de confianza del prototipo:
- NO confiable: todo lo que produce un agente o un documento externo
  (A2AMessage, ActionRequest, etiquetas del Sanitizer).
- Confiable (dentro del límite del prototipo): lo que mantiene el entorno de
  ejecución (ExecutionContext, Authorization). Ningún agente los construye.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


class Scope(StrEnum):
    REVIEW = "review"  # leer, extraer, resumir. No habilita ninguna herramienta que escriba.
    PAY = "pay"        # exactamente un pago simulado con parámetros fijados por el usuario.


class Operation(StrEnum):
    PAY = "pay"


class Reason(StrEnum):
    ALLOWED = "ALLOWED"
    UNKNOWN_OPERATION = "UNKNOWN_OPERATION"
    AGENT_NOT_PERMITTED = "AGENT_NOT_PERMITTED"
    INVALID_ARGS = "INVALID_ARGS"
    NO_AUTHORIZATION = "NO_AUTHORIZATION"
    SCOPE_INSUFFICIENT = "SCOPE_INSUFFICIENT"
    PAYEE_MISMATCH = "PAYEE_MISMATCH"
    AMOUNT_MISMATCH = "AMOUNT_MISMATCH"
    CURRENCY_MISMATCH = "CURRENCY_MISMATCH"
    AUTHORIZATION_CONSUMED = "AUTHORIZATION_CONSUMED"


@dataclass(frozen=True)
class ExecutionContext:
    """Lo fija el orquestador al despachar cada llamada.

    Identidad SIMULADA: agent_id lo asigna el orquestador según qué componente
    invoca (llamada interna en el mismo proceso). No hay autenticación
    criptográfica entre agentes.
    """
    task_id: str
    user_id: str
    agent_id: str


@dataclass(frozen=True)
class Authorization:
    """Permiso explícito del usuario, creado solo por el orquestador a partir
    del canal del usuario (CLI). Un A2AMessage o un modelo no pueden crearlo.

    scope=REVIEW no lleva parámetros de pago.
    scope=PAY fija beneficiario, monto (unidades menores, entero) y moneda; un solo uso.
    """
    task_id: str
    user_id: str
    scope: Scope
    payee_id: str | None = None
    amount_minor: int | None = None
    currency: str | None = None
    auth_id: str = field(default_factory=lambda: _new_id("auth"))


@dataclass(frozen=True)
class A2AMessage:
    """Mensaje agente a agente (contrato local, sin protocolo estándar).

    `fields` son datos extraídos (no instrucciones). `risk_label` es una señal
    del Sanitizer para revisión: jamás otorga permisos. `claimed_sender` se
    registra pero se ignora para autorizar; la identidad la fija el orquestador.
    """
    task_id: str
    fields: dict[str, Any]
    risk_label: str | None = None
    claimed_sender: str | None = None
    msg_id: str = field(default_factory=lambda: _new_id("msg"))


@dataclass(frozen=True)
class ActionRequest:
    """Propuesta de acción emitida por un agente. NO confiable.

    No contiene identidad ni permisos: solo la operación y sus argumentos, que el
    PEP valida y copia antes de ejecutar.
    """
    operation: str
    args: dict[str, Any]
    rationale: str = ""  # texto libre del agente, solo para auditoría
    request_id: str = field(default_factory=lambda: _new_id("req"))


@dataclass(frozen=True)
class PaymentArgs:
    """Argumentos ya validados por el PEP. Son los que se ejecutan."""
    payee_id: str
    amount_minor: int
    currency: str


@dataclass(frozen=True)
class Decision:
    request_id: str
    task_id: str
    agent_id: str
    allowed: bool
    reason: Reason
    detail: str = ""
    auth_id: str | None = None
    args: PaymentArgs | None = None
