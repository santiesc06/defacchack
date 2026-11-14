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


# ==========================================================================================
# Registro de auditoría append-only con cadena SHA-256 (núcleo universal; ISO 27001 8.15,
# ISO 42001 A.6). hash_actual = sha256(hash_anterior + json_canónico(evento)).
# ==========================================================================================
import hashlib  # noqa: E402
import threading  # noqa: E402
from datetime import datetime, timezone  # noqa: E402
from typing import Any, Callable  # noqa: E402

GENESIS = "0" * 64


def _canonico(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def _hash(anterior: str, evento: dict) -> str:
    return hashlib.sha256((anterior + _canonico(evento)).encode("utf-8")).hexdigest()


class AuditLogSHA256:
    def __init__(self, ruta: Path | None = None,
                 reloj: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        self._ruta = ruta
        self._reloj = reloj
        self._entradas: list[dict] = []
        self._lock = threading.Lock()
        if ruta is not None:
            ruta.parent.mkdir(parents=True, exist_ok=True)
            ruta.write_text("", encoding="utf-8")  # cada arranque de demo abre un registro nuevo

    def anexar(self, *, actor: str, evento: str, solicitud_id: str | None = None,
               estado: str | None = None, payload: dict | None = None) -> dict:
        with self._lock:
            anterior = self._entradas[-1]["hash_actual"] if self._entradas else GENESIS
            cuerpo = {
                "seq": len(self._entradas) + 1,
                "ts": self._reloj().isoformat(timespec="milliseconds"),
                "solicitud_id": solicitud_id,
                "actor": actor,
                "evento": evento,
                "estado": estado,
                "payload": json.loads(_canonico(payload or {})),
            }
            entrada = {**cuerpo, "hash_anterior": anterior, "hash_actual": _hash(anterior, cuerpo)}
            self._entradas.append(entrada)
            if self._ruta is not None:
                with self._ruta.open("a", encoding="utf-8") as f:
                    f.write(_canonico(entrada) + "\n")
            return dict(entrada)

    @property
    def entradas(self) -> list[dict]:
        return [dict(e) for e in self._entradas]

    def ultimo_hash(self) -> str:
        return self._entradas[-1]["hash_actual"] if self._entradas else GENESIS

    @staticmethod
    def verificar_cadena(entradas: list[dict]) -> dict:
        anterior = GENESIS
        for i, e in enumerate(entradas):
            cuerpo = {k: e.get(k) for k in ("seq", "ts", "solicitud_id", "actor", "evento", "estado", "payload")}
            esperado = _hash(anterior, cuerpo)
            if e.get("hash_anterior") != anterior or e.get("hash_actual") != esperado or e.get("seq") != i + 1:
                return {"integro": False, "entradas": len(entradas), "primera_alterada": e.get("seq", i + 1),
                        "detalle": f"La entrada #{e.get('seq', i + 1)} no coincide con su hash: el registro fue alterado"}
            anterior = e["hash_actual"]
        return {"integro": True, "entradas": len(entradas), "primera_alterada": None,
                "ultimo_hash": anterior, "detalle": "Cadena SHA-256 íntegra"}

    def verificar(self) -> dict:
        memoria = self.verificar_cadena(self._entradas)
        if self._ruta is None or not memoria["integro"]:
            return memoria
        disco = [json.loads(l) for l in self._ruta.read_text(encoding="utf-8").splitlines() if l.strip()]
        res = self.verificar_cadena(disco)
        if res["integro"] and len(disco) != len(self._entradas):
            return {"integro": False, "entradas": len(disco), "primera_alterada": len(disco) + 1,
                    "detalle": "El archivo tiene distinta cantidad de entradas que la memoria (truncado)"}
        return res

    # --- Solo para la demo ante el jurado: simula que un intruso edita el archivo ---------
    def _demo_manipular(self, seq: int | None = None) -> dict:
        if not self._entradas:
            return {"ok": False, "detalle": "No hay entradas para manipular"}
        objetivo = seq or max(1, len(self._entradas) // 2)
        e = self._entradas[objetivo - 1]
        e["payload"] = {**e.get("payload", {}), "manipulado": "monto cambiado por un intruso"}
        if self._ruta is not None:
            self._ruta.write_text("".join(_canonico(x) + "\n" for x in self._entradas), encoding="utf-8")
        return {"ok": True, "seq": objetivo}
