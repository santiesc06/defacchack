"""Registro de pagos simulado. En memoria; no toca dinero, red ni archivos reales.

Invariante de escritura única: el registro emite UNA credencial de escritura y
solo a quien la pide primero (el PEP, al construirse). Cualquier otra escritura
falla. Esto protege contra errores de cableado dentro del proceso, no contra
código malicioso en el mismo proceso (límite declarado).
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from .contracts import PaymentArgs


@dataclass(frozen=True)
class LedgerEntry:
    entry_id: int
    task_id: str
    request_id: str
    auth_id: str
    payee_id: str
    amount_minor: int
    currency: str


class LedgerWriteError(RuntimeError):
    pass


class SimulatedLedger:
    def __init__(self) -> None:
        self._entries: list[LedgerEntry] = []
        self._writer_token: object | None = None

    def issue_writer(self) -> object:
        if self._writer_token is not None:
            raise LedgerWriteError("el registro ya tiene escritor (PEP)")
        self._writer_token = object()
        return self._writer_token

    def record(self, token: object, *, task_id: str, request_id: str,
               auth_id: str, args: PaymentArgs) -> LedgerEntry:
        if self._writer_token is None or token is not self._writer_token:
            raise LedgerWriteError("escritura fuera del PEP")
        entry = LedgerEntry(len(self._entries) + 1, task_id, request_id, auth_id,
                            args.payee_id, args.amount_minor, args.currency)
        self._entries.append(entry)
        return entry

    @property
    def entries(self) -> tuple[LedgerEntry, ...]:
        return tuple(self._entries)

    def dump(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps([asdict(e) for e in self._entries],
                                         indent=2, ensure_ascii=False), encoding="utf-8")
