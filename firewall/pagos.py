"""Servicio de pagos simulado. No toca dinero, red ni bancos reales.

Matriz 1: «Ejecutar el pago — Servicio de pagos: solo ejecuta órdenes del PEP».
- Con el firewall ACTIVO, solo acepta órdenes con firma HMAC del PEP (`emitir_llave_pep` se
  puede llamar una sola vez: la toma el PEP al construirse).
- Con el firewall DESACTIVADO (línea base «confianza implícita», P4) acepta cualquier orden:
  es el contrafactual que se mide en la evaluación, no un modo de operación.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
from dataclasses import dataclass

from .config import SALDO_INICIAL_COP


class PagoRechazado(RuntimeError):
    pass


@dataclass(frozen=True)
class OrdenPago:
    solicitud_id: str
    proveedor_id: str | None
    beneficiario: str
    cuenta_destino: str
    monto_cop: int
    numero_factura: str | None
    hash_transaccion: str

    def canonico(self) -> bytes:
        return json.dumps(self.__dict__, sort_keys=True, ensure_ascii=False).encode()


class ServicioPagosMock:
    def __init__(self, repositorio, saldo_inicial: int = SALDO_INICIAL_COP) -> None:
        self._repo = repositorio
        self.saldo = saldo_inicial
        self.saldo_inicial = saldo_inicial
        self.ejecutados: list[dict] = []
        self._llave_pep: bytes | None = None
        self._lock = threading.Lock()
        self.exigir_firma_pep = True

    def emitir_llave_pep(self) -> bytes:
        if self._llave_pep is not None:
            raise PagoRechazado("la llave del PEP ya fue emitida")
        self._llave_pep = secrets.token_bytes(32)
        return self._llave_pep

    def ejecutar(self, orden: OrdenPago, firma_pep: str | None, *, actor: str) -> dict:
        with self._lock:
            if self.exigir_firma_pep:
                if self._llave_pep is None or firma_pep is None:
                    raise PagoRechazado("orden sin firma del PEP")
                esperado = hmac.new(self._llave_pep, orden.canonico(), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(esperado, firma_pep):
                    raise PagoRechazado("firma del PEP inválida")
            if orden.monto_cop > self.saldo:
                raise PagoRechazado("saldo insuficiente")
            self.saldo -= orden.monto_cop
            pago_id = f"PAG-{len(self.ejecutados) + 100:04d}"
            registro = {"pago_id": pago_id, **orden.__dict__, "ordenado_por": actor,
                        "con_firma_pep": firma_pep is not None, "saldo_resultante": self.saldo}
            self.ejecutados.append(registro)
            self._repo._registrar_pago(pago_id=pago_id, proveedor_id=orden.proveedor_id,
                                       factura=orden.numero_factura, monto_cop=orden.monto_cop,
                                       cuenta=orden.cuenta_destino)
            return registro
