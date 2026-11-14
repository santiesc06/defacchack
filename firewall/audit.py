"""Registro de auditoría append-only con cadena de hashes SHA-256 (ISO 27001 8.15, 42001 A.6).

hash_actual = sha256(hash_anterior + json_canónico(evento))

No existe método para editar ni borrar entradas. `verificar()` recalcula la cadena completa
(en memoria y, si hay archivo, desde el disco) y señala la primera entrada alterada.
Límite declarado: un atacante con acceso de escritura al archivo puede TRUNCAR el final
sin ser detectado, salvo que el último hash se ancle fuera (opción P2-C del documento de decisiones).
"""
from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

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
