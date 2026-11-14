"""Policy Enforcement Point determinista delante del registro simulado.

Decide SOLO con estado del entorno de ejecución:
  - ExecutionContext (identidad simulada del agente, tarea, usuario),
  - AuthorizationStore (autorizaciones explícitas del usuario),
  - permisos por agente.
Nada de lo que viaja en el ActionRequest (rationale, etiquetas, texto) cuenta
como permiso. Los argumentos se validan, se copian a PaymentArgs y esa misma
copia es la que se ejecuta.
"""
from __future__ import annotations

import re
from typing import Any, Mapping

from .contracts import (ActionRequest, Authorization, Decision, ExecutionContext,
                        Operation, PaymentArgs, Reason, Scope)
from .ledger import SimulatedLedger

PAYEE_RE = re.compile(r"^[A-Z0-9-]{3,40}$")
ALLOWED_CURRENCIES = frozenset({"COP", "USD"})
MAX_AMOUNT_MINOR = 10**12

DEFAULT_AGENT_PERMISSIONS: Mapping[str, frozenset[Operation]] = {
    "finance-agent": frozenset({Operation.PAY}),
    "reader-agent": frozenset(),
}


class AuthorizationStore:
    """Estado del orquestador. Solo el orquestador (canal del usuario) llama a grant()."""

    def __init__(self) -> None:
        self._by_task: dict[str, list[Authorization]] = {}
        self._consumed: set[str] = set()

    def grant(self, auth: Authorization) -> Authorization:
        if auth.scope is Scope.PAY:
            ok = parse_payment_args({"payee_id": auth.payee_id, "amount_minor": auth.amount_minor,
                                     "currency": auth.currency})
            if isinstance(ok, str):
                raise ValueError(f"autorización de pago inválida: {ok}")
        self._by_task.setdefault(auth.task_id, []).append(auth)
        return auth

    def for_task(self, task_id: str, user_id: str) -> list[Authorization]:
        return [a for a in self._by_task.get(task_id, []) if a.user_id == user_id]

    def is_consumed(self, auth_id: str) -> bool:
        return auth_id in self._consumed

    def consume(self, auth_id: str) -> None:
        self._consumed.add(auth_id)


def parse_payment_args(raw: Any) -> PaymentArgs | str:
    """Devuelve PaymentArgs validados o un texto con el motivo del rechazo."""
    if not isinstance(raw, Mapping):
        return "args no es un objeto"
    if set(raw) != {"payee_id", "amount_minor", "currency"}:
        return f"campos esperados payee_id, amount_minor, currency; recibidos {sorted(raw)}"
    payee, amount, currency = raw["payee_id"], raw["amount_minor"], raw["currency"]
    if not isinstance(payee, str) or not PAYEE_RE.fullmatch(payee):
        return "payee_id con formato inválido"
    if type(amount) is not int or not (0 < amount <= MAX_AMOUNT_MINOR):
        return "amount_minor debe ser entero positivo"
    if not isinstance(currency, str) or currency not in ALLOWED_CURRENCIES:
        return "moneda no permitida"
    return PaymentArgs(payee_id=payee, amount_minor=amount, currency=currency)


class PolicyEnforcementPoint:
    def __init__(self, authorizations: AuthorizationStore, ledger: SimulatedLedger,
                 agent_permissions: Mapping[str, frozenset[Operation]] = DEFAULT_AGENT_PERMISSIONS):
        self._auth = authorizations
        self._ledger = ledger
        self._writer = ledger.issue_writer()  # el PEP es el único escritor del registro
        self._perms = agent_permissions
        self.audit: list[Decision] = []

    def submit(self, ctx: ExecutionContext, request: ActionRequest) -> Decision:
        decision = self._decide(ctx, request)
        if decision.allowed:
            assert decision.args is not None and decision.auth_id is not None
            self._auth.consume(decision.auth_id)
            self._ledger.record(self._writer, task_id=ctx.task_id, request_id=request.request_id,
                                auth_id=decision.auth_id, args=decision.args)
        self.audit.append(decision)
        return decision

    def _decide(self, ctx: ExecutionContext, req: ActionRequest) -> Decision:
        def deny(reason: Reason, detail: str = "", auth_id: str | None = None) -> Decision:
            return Decision(req.request_id, ctx.task_id, ctx.agent_id, False, reason, detail, auth_id)

        try:
            op = Operation(req.operation)
        except ValueError:
            return deny(Reason.UNKNOWN_OPERATION, f"operación {req.operation!r}")
        if op not in self._perms.get(ctx.agent_id, frozenset()):
            return deny(Reason.AGENT_NOT_PERMITTED, f"{ctx.agent_id} no puede {op}")

        args = parse_payment_args(req.args)
        if isinstance(args, str):
            return deny(Reason.INVALID_ARGS, args)

        auths = self._auth.for_task(ctx.task_id, ctx.user_id)
        if not auths:
            return deny(Reason.NO_AUTHORIZATION, "sin autorización del usuario para esta tarea")
        pay_auths = [a for a in auths if a.scope is Scope.PAY]
        if not pay_auths:
            return deny(Reason.SCOPE_INSUFFICIENT, "el usuario solo autorizó revisar")
        live = [a for a in pay_auths if not self._auth.is_consumed(a.auth_id)]
        if not live:
            return deny(Reason.AUTHORIZATION_CONSUMED, "la autorización de pago ya se usó",
                        pay_auths[0].auth_id)

        for a in live:
            if (a.payee_id, a.amount_minor, a.currency) == (args.payee_id, args.amount_minor, args.currency):
                return Decision(req.request_id, ctx.task_id, ctx.agent_id, True, Reason.ALLOWED,
                                "coincide con la autorización del usuario", a.auth_id, args)

        a = live[0]  # informar la primera discrepancia contra la primera autorización vigente
        if args.payee_id != a.payee_id:
            return deny(Reason.PAYEE_MISMATCH, f"autorizado {a.payee_id}, solicitado {args.payee_id}", a.auth_id)
        if args.amount_minor != a.amount_minor:
            return deny(Reason.AMOUNT_MISMATCH, f"autorizado {a.amount_minor}, solicitado {args.amount_minor}",
                        a.auth_id)
        return deny(Reason.CURRENCY_MISMATCH, f"autorizado {a.currency}, solicitado {args.currency}", a.auth_id)
