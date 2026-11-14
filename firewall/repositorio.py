"""Maestro de proveedores, órdenes de compra, historial y directorio de personas.

Los agentes reciben `VistaSoloLectura` (Matriz 1: «Consultar maestro... Solo lectura»).
No existe en esa vista ningún método para modificar proveedores, cuentas, políticas o umbrales.
El único escritor del historial es el servicio de pagos (al ejecutar una orden del PEP).
"""
from __future__ import annotations

import copy
import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from typing import Callable

from .config import Rol
from . import fuente_datos
from .data import seed
from .schemas import ProveedorInfo, ResultadoDuplicado, ResultadoOC

Reloj = Callable[[], datetime]


def reloj_sistema() -> datetime:
    return datetime.now(timezone.utc)


def normalizar_cuenta(cuenta: str | None) -> str:
    return "".join(ch for ch in (cuenta or "") if ch.isdigit())


def _hash_pin(usuario_id: str, pin: str) -> str:
    return hashlib.sha256(f"cfzt-demo-salt|{usuario_id}|{pin}".encode()).hexdigest()


def _datos_demo() -> dict:
    return {"proveedores": seed.PROVEEDORES, "ordenes": seed.ORDENES_COMPRA, "historial": seed.HISTORIAL_PAGOS,
            "usuarios": seed.USUARIOS, "origen": fuente_datos.describir(None, None)}


class Repositorio:
    """Datos de solo lectura. Fuente: base SQL (CFZT_DB_URL / CFZT_DB_SQL) o datos de demostración."""

    def __init__(self, reloj: Reloj = reloj_sistema, datos: dict | None = None) -> None:
        self._reloj = reloj
        ahora = reloj()
        datos = datos or fuente_datos.cargar() or _datos_demo()
        self.origen_datos = datos.get("origen", "datos en memoria")

        def hace(dias) -> datetime | None:
            return ahora - timedelta(days=int(dias)) if dias is not None else None

        self._proveedores = {}
        for p in copy.deepcopy(datos["proveedores"]):
            fecha = p.get("fecha_cambio_cuenta") or hace(p.get("dias_desde_cambio_cuenta", p.get("cambio_cuenta_hace_dias")))
            self._proveedores[str(p["proveedor_id"])] = {
                "proveedor_id": str(p["proveedor_id"]), "razon_social": p["razon_social"], "nit": p.get("nit") or "",
                "dominio": str(p["dominio"]).lower(), "banco": p.get("banco"), "cuenta": str(p["cuenta"]),
                "telefono": p.get("telefono"), "fecha_cambio_cuenta": fecha,
                "cambio_aprobado_por": p.get("cambio_aprobado_por")}
        self._ocs = {str(o["numero_oc"]): {"numero_oc": str(o["numero_oc"]), "proveedor_id": str(o["proveedor_id"]),
                                           "monto_cop": int(o["monto_cop"]), "factura": o.get("factura")}
                     for o in datos["ordenes"]}
        self._historial = []
        for h in copy.deepcopy(datos["historial"]):
            self._historial.append({"pago_id": str(h["pago_id"]), "proveedor_id": str(h["proveedor_id"]),
                                    "factura": h.get("factura"), "monto_cop": int(h["monto_cop"]),
                                    "cuenta": h.get("cuenta"), "fecha": h.get("fecha") or hace(h.get("hace_dias"))})
        self._usuarios = {}
        for u in datos.get("usuarios") or seed.USUARIOS:  # personas de demo si la base no trae cfzt_usuarios
            uid, pin = str(u["usuario_id"]), str(u["pin"])
            self._usuarios[uid] = {
                "usuario_id": uid, "nombre": u["nombre"], "rol": Rol(str(u["rol"]).strip().upper()),
                "pin_hash": _hash_pin(uid, pin),
                # Llave de firma personal simulada (en producción: HSM / llave del usuario).
                "llave_firma": hashlib.sha256(f"llave|{uid}|{pin}".encode()).digest(),
                "pin_demo": pin,
            }

    # ---- proveedores ---------------------------------------------------------------
    def _a_info(self, p: dict | None) -> ProveedorInfo:
        if p is None:
            return ProveedorInfo(encontrado=False)
        dias = (self._reloj() - p["fecha_cambio_cuenta"]).days if p["fecha_cambio_cuenta"] else None
        return ProveedorInfo(encontrado=True, proveedor_id=p["proveedor_id"], razon_social=p["razon_social"],
                             nit=p["nit"], dominio=p["dominio"], banco=p["banco"], cuenta_registrada=p["cuenta"],
                             telefono_registrado=p["telefono"], dias_desde_cambio_cuenta=dias,
                             cambio_cuenta_aprobado_por=p["cambio_aprobado_por"])

    def buscar_proveedor(self, *, proveedor_id: str | None = None, nit: str | None = None,
                         nombre: str | None = None, dominio: str | None = None) -> ProveedorInfo:
        if proveedor_id and proveedor_id in self._proveedores:
            return self._a_info(self._proveedores[proveedor_id])
        def norm(s: str) -> str:
            return "".join(ch for ch in s.lower() if ch.isalnum())
        for p in self._proveedores.values():
            if nit and norm(nit) == norm(p["nit"]):
                return self._a_info(p)
        if nombre:
            exactos = [p for p in self._proveedores.values() if norm(nombre) == norm(p["razon_social"])]
            # Prefijo solo si es inequívoco: «Proveedor Corporativo 1» no debe elegir al 10, 11…
            prefijos = [p for p in self._proveedores.values()
                        if len(norm(nombre)) >= 8 and norm(p["razon_social"]).startswith(norm(nombre))]
            if len(exactos) == 1:
                return self._a_info(exactos[0])
            if not exactos and len(prefijos) == 1:
                return self._a_info(prefijos[0])
        for p in self._proveedores.values():
            if dominio and dominio.lower() == p["dominio"]:
                return self._a_info(p)
        return ProveedorInfo(encontrado=False)

    def cuentas_registradas(self) -> set[str]:
        return {normalizar_cuenta(p["cuenta"]) for p in self._proveedores.values()}

    def dominios_registrados(self) -> list[str]:
        return [p["dominio"] for p in self._proveedores.values()]

    # ---- órdenes de compra -------------------------------------------------------------
    def buscar_soporte(self, *, proveedor_id: str | None, numero_oc: str | None,
                       numero_factura: str | None, monto_cop: int | None) -> ResultadoOC:
        candidatos = []
        if numero_oc and numero_oc in self._ocs:
            candidatos.append(self._ocs[numero_oc])
        if numero_factura:
            candidatos += [o for o in self._ocs.values() if o["factura"] == numero_factura]
        if not candidatos:
            return ResultadoOC(existe=False, detalle="No hay factura ni orden de compra registrada que respalde el pago")
        o = candidatos[0]
        coincide = o["proveedor_id"] == proveedor_id and o["monto_cop"] == monto_cop
        detalle = "Soporte coincide en proveedor y monto" if coincide else (
            f"El soporte {o['numero_oc']} es de {o['proveedor_id']} por {o['monto_cop']:,} COP; no coincide")
        return ResultadoOC(existe=True, numero_oc=o["numero_oc"], proveedor_id=o["proveedor_id"],
                           monto_cop=o["monto_cop"], factura_asociada=o["factura"], coincide=coincide,
                           detalle=detalle)

    # ---- historial ------------------------------------------------------------------------
    def buscar_duplicado(self, *, proveedor_id: str | None, numero_factura: str | None,
                         monto_cop: int | None) -> ResultadoDuplicado:
        for h in self._historial:
            if numero_factura and h["factura"] == numero_factura and h["proveedor_id"] == proveedor_id:
                return ResultadoDuplicado(duplicado=True, pago_previo_id=h["pago_id"],
                                          detalle=f"La factura {numero_factura} ya se pagó ({h['pago_id']})")
        for h in self._historial:
            if (proveedor_id and h["proveedor_id"] == proveedor_id and monto_cop == h["monto_cop"]
                    and h["fecha"] is not None and (self._reloj() - h["fecha"]).days <= 3 and not numero_factura):
                return ResultadoDuplicado(duplicado=True, pago_previo_id=h["pago_id"],
                                          detalle="Mismo beneficiario y monto pagados hace menos de 3 días")
        return ResultadoDuplicado(duplicado=False, detalle="Sin pagos previos para esta factura")

    def _registrar_pago(self, *, pago_id: str, proveedor_id: str | None, factura: str | None,
                        monto_cop: int, cuenta: str) -> None:
        """Solo lo invoca ServicioPagosMock tras ejecutar."""
        self._historial.append({"pago_id": pago_id, "proveedor_id": proveedor_id, "factura": factura,
                                "monto_cop": monto_cop, "cuenta": cuenta, "fecha": self._reloj()})

    # ---- personas -----------------------------------------------------------------------
    def usuario(self, usuario_id: str) -> dict | None:
        return self._usuarios.get(usuario_id)

    def verificar_pin(self, usuario_id: str, pin: str) -> bool:
        u = self._usuarios.get(usuario_id)
        return bool(u) and hmac.compare_digest(u["pin_hash"], _hash_pin(usuario_id, pin))

    def usuarios_publicos(self) -> list[dict]:
        return [{"usuario_id": u["usuario_id"], "nombre": u["nombre"], "rol": u["rol"].value,
                 "pin_demo": u["pin_demo"]} for u in self._usuarios.values()]

    def vista_solo_lectura(self) -> "VistaSoloLectura":
        return VistaSoloLectura(self)


class VistaSoloLectura:
    """Lo único que ven el Orquestador y el PEP del maestro. Sin métodos de escritura."""
    __slots__ = ("_r",)

    def __init__(self, repo: Repositorio) -> None:
        object.__setattr__(self, "_r", repo)

    def __setattr__(self, *_):  # pragma: no cover - defensa contra cableado erróneo
        raise AttributeError("vista de solo lectura")

    def buscar_proveedor(self, **kw) -> ProveedorInfo:
        return self._r.buscar_proveedor(**kw)

    def buscar_soporte(self, **kw) -> ResultadoOC:
        return self._r.buscar_soporte(**kw)

    def buscar_duplicado(self, **kw) -> ResultadoDuplicado:
        return self._r.buscar_duplicado(**kw)
