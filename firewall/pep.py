"""Policy Enforcement Point — código determinista, sin LLM.

Capa 1: intercepta cada invocación de herramienta del Agente Financiero y aplica la Matriz 3.
Capa 2: gestiona las firmas humanas (Matriz 2: segregación de funciones, MFA, hash, vigencia) y
        es el ÚNICO componente que puede ordenar un pago al servicio de pagos.

Zero-trust interno: el PEP no confía en lo que dicen los agentes. Vuelve a consultar por sí mismo
(solo lectura) el maestro, las OC y el historial, verifica el sello de las etiquetas del Sanitizer,
y construye la orden de pago con los datos del MAESTRO, no con los del correo.
"""
from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable

from pydantic import ValidationError

from .audit import AuditLogSHA256
from .config import (DIAS_CUENTA_RECIENTE, DIAS_RESTRICCION_SOD_CAMBIO_CUENTA, ETIQUETA_ROL,
                     HORAS_VIGENCIA_FIRMA, ROLES_QUE_PUEDEN_RECHAZAR, UMBRAL_ALTO_COP, UMBRAL_BAJO_COP, Rol,
                     formato_cop)
from .pagos import OrdenPago, PagoRechazado, ServicioPagosMock
from .repositorio import Repositorio, normalizar_cuenta
from .sanitizer import sellar
from .schemas import (ESTADOS_PENDIENTES, Estado, Firma, MetadataSeguridadSchema, PropuestaPagoSchema,
                      ReglaActivada, VeredictoPEP)

# Matriz 1: herramientas que cada identidad no humana puede invocar a través del PEP.
PERMISOS_HERRAMIENTAS: dict[str, frozenset[str]] = {
    "agente:financiero": frozenset({"solicitar_ejecucion_pago"}),
    "agente:recepcionista": frozenset(),
    "agente:sanitizer": frozenset(),
    "agente:orquestador": frozenset(),
    "agente:explicador": frozenset(),
}

DESCRIPCION_REGLAS = {
    "R0": "Integridad de la invocación (herramienta permitida, argumentos válidos, etiquetas selladas)",
    "R1": "Proveedor no registrado, o cuenta distinta a la del maestro",
    "R2": "El Sanitizer marca riesgo ALTO",
    "R3": "Falla SPF/DKIM/DMARC o dominio parecido/distinto al legítimo",
    "R4": "Pago duplicado",
    "R5": "Sin factura u orden de compra que lo respalde",
    "R6": "Válido, riesgo bajo, hasta $2.000.000",
    "R7": "Válido, riesgo medio o entre $2.000.000 y $20.000.000",
    "R8": "Válido, más de $20.000.000",
    "R9": "Cuenta del proveedor modificada en los últimos 30 días",
}


def hash_transaccion(proveedor_id: str | None, cuenta: str, monto: int) -> str:
    return hashlib.sha256(f"{proveedor_id}|{normalizar_cuenta(cuenta)}|{monto}".encode()).hexdigest()


@dataclass(frozen=True)
class ContextoPEP:
    """Lo fija el entorno de ejecución (no un agente)."""
    solicitud_id: str
    metadata: MetadataSeguridadSchema
    sello_registrado: str
    iniciado_por: str | None = None


@dataclass
class RegistroPago:
    solicitud_id: str
    proveedor_id: str
    razon_social: str
    cuenta: str
    monto_cop: int
    numero_factura: str | None
    numero_oc: str | None
    concepto: str
    hash_transaccion: str
    firmas_requeridas: tuple[Rol, ...]
    verificacion_telefonica_requerida: bool
    telefono_registrado: str | None
    iniciado_por: str | None
    creado: datetime
    estado: Estado = Estado.PENDIENTE_FIRMA_1
    firmas: list[Firma] = field(default_factory=list)
    verificacion_telefonica_hecha: bool = False
    pago: dict | None = None


class ErrorFirma(Exception):
    pass


class PolicyEnforcementPoint:
    def __init__(self, repositorio: Repositorio, pagos: ServicioPagosMock, audit: AuditLogSHA256,
                 reloj: Callable[[], datetime]) -> None:
        self._repo = repositorio
        self._vista = repositorio.vista_solo_lectura()
        self._pagos = pagos
        self._llave = pagos.emitir_llave_pep()  # único emisor de órdenes de pago
        self._audit = audit
        self._reloj = reloj
        self.registros: dict[str, RegistroPago] = {}
        self.estados_finales: dict[str, Estado] = {}

    # ====================================================================================
    # Capa 1 — motor de reglas (Matriz 3)
    # ====================================================================================
    def evaluar(self, agente: str, herramienta: str, args: dict, ctx: ContextoPEP) -> VeredictoPEP:
        t0 = time.perf_counter()
        veredicto = self._evaluar(agente, herramienta, args, ctx)
        veredicto = veredicto.model_copy(update={"latencia_ms": round((time.perf_counter() - t0) * 1000, 3)})
        self.estados_finales[ctx.solicitud_id] = veredicto.estado
        self._audit.anexar(actor="pep", evento="DECISION_PEP", solicitud_id=ctx.solicitud_id,
                           estado=veredicto.estado.value,
                           payload={"decision": veredicto.decision, "regla_principal": veredicto.regla_principal,
                                    "reglas": [r.codigo for r in veredicto.reglas],
                                    "firmas_requeridas": [r.value for r in veredicto.firmas_requeridas],
                                    "hash_transaccion": veredicto.hash_transaccion,
                                    "alerta_seguridad": veredicto.alerta_seguridad})
        if veredicto.alerta_seguridad:
            self._audit.anexar(actor="pep", evento="ALERTA_OFICIAL_SEGURIDAD", solicitud_id=ctx.solicitud_id,
                               estado=veredicto.estado.value,
                               payload={"caso": f"CASO-{ctx.solicitud_id[4:]}", "motivo": veredicto.regla_principal})
        return veredicto

    def _evaluar(self, agente: str, herramienta: str, args: dict, ctx: ContextoPEP) -> VeredictoPEP:
        def r0(detalle: str) -> VeredictoPEP:
            regla = ReglaActivada(codigo="R0", descripcion=detalle, decision="BLOQUEADA")
            return VeredictoPEP(decision="BLOQUEADA", estado=Estado.BLOQUEADA, regla_principal=f"R0 · {detalle}",
                                reglas=(regla,), alerta_seguridad=True)

        if herramienta not in PERMISOS_HERRAMIENTAS.get(agente, frozenset()):
            return r0(f"{agente} no tiene permiso para {herramienta} (Matriz 1)")
        try:
            p = PropuestaPagoSchema.model_validate(args)
        except ValidationError as e:
            return r0(f"Argumentos fuera del esquema cerrado ({e.error_count()} errores)")
        if p.solicitud_id != ctx.solicitud_id:
            return r0("La propuesta no corresponde a la solicitud en curso")
        if sellar(ctx.metadata) != ctx.sello_registrado:
            return r0("Las etiquetas del Sanitizer fueron alteradas después de selladas")

        md = ctx.metadata
        interno = md.origen == "INTERNO_VERIFICADO"
        prov = (self._vista.buscar_proveedor(proveedor_id=p.proveedor_id) if p.proveedor_id
                else self._vista.buscar_proveedor(nombre=p.beneficiario))
        reglas: list[ReglaActivada] = []

        def add(codigo: str, detalle: str, decision: str) -> None:
            reglas.append(ReglaActivada(codigo=codigo, descripcion=detalle, decision=decision))

        if not prov.encontrado:
            add("R1", f"«{p.beneficiario}» no está registrado en el maestro de proveedores", "BLOQUEADA")
        elif normalizar_cuenta(p.cuenta_destino) != normalizar_cuenta(prov.cuenta_registrada):
            add("R1", f"Cuenta solicitada {p.cuenta_destino} ≠ cuenta registrada de {prov.razon_social} "
                      f"(…{prov.cuenta_registrada[-4:]})", "BLOQUEADA")
        if md.nivel_riesgo == "ALTO":
            add("R2", "Sanitizer: riesgo ALTO (" + ", ".join(md.banderas_anomalia[:4]) + ")", "BLOQUEADA")
        if not md.spf_dkim_valido:
            add("R3", "El remitente falla SPF/DKIM/DMARC", "BLOQUEADA")
        if md.dominio_parecido_a:
            add("R3", f"Dominio {md.dominio_remitente} parecido a {md.dominio_parecido_a}", "BLOQUEADA")
        elif prov.encontrado and not interno and md.dominio_remitente != prov.dominio:
            add("R3", f"Dominio {md.dominio_remitente} distinto al registrado ({prov.dominio})", "BLOQUEADA")

        dup = self._vista.buscar_duplicado(proveedor_id=prov.proveedor_id, numero_factura=p.numero_factura,
                                           monto_cop=p.monto_cop)
        if dup.duplicado:
            add("R4", dup.detalle, "RECHAZADA")
        sop = self._vista.buscar_soporte(proveedor_id=prov.proveedor_id, numero_oc=p.numero_oc,
                                         numero_factura=p.numero_factura, monto_cop=p.monto_cop)
        if not (sop.existe and sop.coincide):
            add("R5", sop.detalle, "RECHAZADA")

        bloqueos = [r for r in reglas if r.decision == "BLOQUEADA"]
        if bloqueos:
            return VeredictoPEP(decision="BLOQUEADA", estado=Estado.BLOQUEADA,
                                regla_principal=f"{bloqueos[0].codigo} · {DESCRIPCION_REGLAS[bloqueos[0].codigo]}",
                                reglas=tuple(reglas), alerta_seguridad=True)
        rechazos = [r for r in reglas if r.decision == "RECHAZADA"]
        if rechazos:
            return VeredictoPEP(decision="RECHAZADA", estado=Estado.RECHAZADA,
                                regla_principal=f"{rechazos[0].codigo} · {DESCRIPCION_REGLAS[rechazos[0].codigo]}",
                                reglas=tuple(reglas))

        # --- Ruta de firmas (Capa 2) ---------------------------------------------------
        requeridas = [Rol.ANALISTA_CXP, Rol.TESORERO]
        telefono = False
        if prov.dias_desde_cambio_cuenta is not None and prov.dias_desde_cambio_cuenta < DIAS_CUENTA_RECIENTE:
            add("R9", f"Cuenta modificada hace {prov.dias_desde_cambio_cuenta} días", "FIRMAS")
            telefono = True
            requeridas.append(Rol.DIRECTOR_FINANCIERO)
        if p.monto_cop > UMBRAL_ALTO_COP:
            add("R8", f"Monto {formato_cop(p.monto_cop)} supera {formato_cop(UMBRAL_ALTO_COP)}", "FIRMAS")
            if Rol.DIRECTOR_FINANCIERO not in requeridas:
                requeridas.append(Rol.DIRECTOR_FINANCIERO)
        if md.nivel_riesgo == "MEDIO" or UMBRAL_BAJO_COP < p.monto_cop <= UMBRAL_ALTO_COP:
            motivo = "riesgo MEDIO" if md.nivel_riesgo == "MEDIO" else f"monto entre {formato_cop(UMBRAL_BAJO_COP)} y {formato_cop(UMBRAL_ALTO_COP)}"
            add("R7", f"Requiere verificación telefónica: {motivo}", "FIRMAS")
            telefono = True
        if not reglas:
            add("R6", "Riesgo bajo y monto hasta $2.000.000", "FIRMAS")
        principal = sorted(reglas, key=lambda r: {"R9": 0, "R8": 1, "R7": 2, "R6": 3}[r.codigo])[0]

        h = hash_transaccion(prov.proveedor_id, prov.cuenta_registrada, p.monto_cop)
        self.registros[p.solicitud_id] = RegistroPago(
            solicitud_id=p.solicitud_id, proveedor_id=prov.proveedor_id, razon_social=prov.razon_social,
            cuenta=prov.cuenta_registrada, monto_cop=p.monto_cop, numero_factura=p.numero_factura,
            numero_oc=p.numero_oc or sop.numero_oc, concepto=p.concepto, hash_transaccion=h,
            firmas_requeridas=tuple(requeridas), verificacion_telefonica_requerida=telefono,
            telefono_registrado=prov.telefono_registrado, iniciado_por=ctx.iniciado_por, creado=self._reloj())
        return VeredictoPEP(decision="PENDING_APPROVAL", estado=Estado.PENDIENTE_FIRMA_1,
                            regla_principal=f"{principal.codigo} · {DESCRIPCION_REGLAS[principal.codigo]}",
                            reglas=tuple(reglas), firmas_requeridas=tuple(requeridas),
                            verificacion_telefonica=telefono, telefono_registrado=prov.telefono_registrado,
                            hash_transaccion=h)

    # ====================================================================================
    # Capa 2 — supervisión humana (Matriz 2)
    # ====================================================================================
    def _firma_hmac(self, usuario_id: str, reg: RegistroPago, ts: datetime, h: str) -> str:
        llave = self._repo.usuario(usuario_id)["llave_firma"]
        return hmac.new(llave, f"{reg.solicitud_id}|{h}|{ts.isoformat()}".encode(), hashlib.sha256).hexdigest()

    def _autenticar(self, solicitud_id: str, usuario_id: str, pin: str, accion: str) -> dict:
        if usuario_id.startswith("agente"):
            raise ErrorFirma("Ningún agente de IA puede aprobar, firmar ni rechazar (Matriz 2)")
        u = self._repo.usuario(usuario_id)
        if u is None or not self._repo.verificar_pin(usuario_id, pin):
            self._audit.anexar(actor=f"humano:{usuario_id}", evento=f"{accion}_DENEGADA", solicitud_id=solicitud_id,
                               payload={"motivo": "MFA fallida (PIN incorrecto)"})
            raise ErrorFirma("Autenticación MFA fallida: PIN incorrecto")
        return u

    def _denegar(self, reg: RegistroPago, u: dict, motivo: str) -> None:
        self._audit.anexar(actor=f"humano:{u['usuario_id']}", evento="FIRMA_DENEGADA", solicitud_id=reg.solicitud_id,
                           estado=reg.estado.value, payload={"motivo": motivo, "rol": u["rol"].value})
        raise ErrorFirma(motivo)

    def _expirar_si_vencida(self, reg: RegistroPago) -> bool:
        if reg.estado in ESTADOS_PENDIENTES and self._reloj() - reg.creado > timedelta(hours=HORAS_VIGENCIA_FIRMA):
            reg.estado = Estado.EXPIRADA
            self.estados_finales[reg.solicitud_id] = reg.estado
            self._audit.anexar(actor="pep", evento="EXPIRADA", solicitud_id=reg.solicitud_id, estado=reg.estado.value,
                               payload={"vigencia_horas": HORAS_VIGENCIA_FIRMA})
            return True
        return False

    def firmar(self, solicitud_id: str, usuario_id: str, pin: str, verificacion_telefonica: bool = False) -> dict:
        reg = self.registros.get(solicitud_id)
        if reg is None:
            estado = self.estados_finales.get(solicitud_id)
            if estado is Estado.BLOQUEADA:
                raise ErrorFirma("Solicitud BLOQUEADA: no se puede aprobar. Solo el Oficial de Seguridad puede revisar el incidente")
            raise ErrorFirma("No hay una solicitud pendiente de firma con ese identificador")
        u = self._autenticar(solicitud_id, usuario_id, pin, "FIRMA")
        if self._expirar_si_vencida(reg):
            raise ErrorFirma("La solicitud venció (48 h) y pasó a EXPIRADA; debe iniciarse de nuevo")
        if reg.estado not in ESTADOS_PENDIENTES:
            raise ErrorFirma(f"La solicitud está {reg.estado.value}; no admite firmas")

        rol: Rol = u["rol"]
        if rol is Rol.ADMIN_PLATAFORMA:
            self._denegar(reg, u, "Administradores de plataforma no pueden firmar pagos (ISO 27001 8.2)")
        esperado = reg.firmas_requeridas[len(reg.firmas)]
        if rol is not esperado:
            self._denegar(reg, u, f"Se espera la firma {len(reg.firmas) + 1} de {ETIQUETA_ROL[esperado]}; "
                                  f"{u['nombre']} es {ETIQUETA_ROL[rol]}")
        if usuario_id == reg.iniciado_por:
            self._denegar(reg, u, "Segregación de funciones: quien inició la solicitud no puede firmarla (ISO 27001 5.3)")
        if any(f.usuario_id == usuario_id for f in reg.firmas):
            self._denegar(reg, u, "Segregación de funciones: una persona no puede firmar dos veces la misma solicitud")
        prov = self._vista.buscar_proveedor(proveedor_id=reg.proveedor_id)
        if (prov.cambio_cuenta_aprobado_por == usuario_id and prov.dias_desde_cambio_cuenta is not None
                and prov.dias_desde_cambio_cuenta < DIAS_RESTRICCION_SOD_CAMBIO_CUENTA):
            self._denegar(reg, u, f"Segregación de funciones: {u['nombre']} aprobó el cambio de cuenta de este "
                                  f"proveedor hace {prov.dias_desde_cambio_cuenta} días (restricción de 30 días)")
        if verificacion_telefonica and rol in (Rol.ANALISTA_CXP, Rol.TESORERO):
            reg.verificacion_telefonica_hecha = True
        es_ultima = len(reg.firmas) + 1 == len(reg.firmas_requeridas)
        if es_ultima and reg.verificacion_telefonica_requerida and not reg.verificacion_telefonica_hecha:
            self._denegar(reg, u, f"Falta la constancia de verificación telefónica al número registrado "
                                  f"{reg.telefono_registrado} (la registra el Analista o el Tesorero)")

        ts = self._reloj()
        firma = Firma(usuario_id=usuario_id, nombre=u["nombre"], rol=rol, hash_transaccion=reg.hash_transaccion,
                      timestamp=ts, firma_hmac=self._firma_hmac(usuario_id, reg, ts, reg.hash_transaccion),
                      verificacion_telefonica=verificacion_telefonica)
        reg.firmas.append(firma)
        n = len(reg.firmas)
        self._audit.anexar(actor=f"humano:{usuario_id}", evento=f"FIRMA_{n}", solicitud_id=solicitud_id,
                           estado=reg.estado.value,
                           payload={"rol": rol.value, "hash_transaccion": reg.hash_transaccion,
                                    "firma_hmac": firma.firma_hmac[:16] + "…",
                                    "verificacion_telefonica": verificacion_telefonica})
        if n < len(reg.firmas_requeridas):
            reg.estado = [Estado.PENDIENTE_FIRMA_1, Estado.PENDIENTE_FIRMA_2, Estado.PENDIENTE_FIRMA_3][n]
            self.estados_finales[solicitud_id] = reg.estado
            return {"ok": True, "estado": reg.estado.value, "mensaje": f"Firma {n} de {len(reg.firmas_requeridas)} registrada"}
        return self._ordenar_pago(reg)

    def _ordenar_pago(self, reg: RegistroPago) -> dict:
        """Procedimiento paso 8: re-verificar firmas y SoD; ordenar el pago."""
        h_actual = hash_transaccion(reg.proveedor_id, reg.cuenta, reg.monto_cop)
        prov = self._vista.buscar_proveedor(proveedor_id=reg.proveedor_id)
        problemas = []
        if normalizar_cuenta(prov.cuenta_registrada) != normalizar_cuenta(reg.cuenta):
            problemas.append("La cuenta del maestro cambió después de iniciar las firmas")
        if len({f.usuario_id for f in reg.firmas}) != len(reg.firmas):
            problemas.append("Firmantes repetidos")
        for f in reg.firmas:
            if f.hash_transaccion != h_actual or not hmac.compare_digest(
                    f.firma_hmac, self._firma_hmac(f.usuario_id, reg, f.timestamp, h_actual)):
                problemas.append(f"La firma de {f.nombre} no cubre los datos actuales (beneficiario/cuenta/monto cambiaron)")
            if self._reloj() - f.timestamp > timedelta(hours=HORAS_VIGENCIA_FIRMA):
                problemas.append(f"La firma de {f.nombre} venció")
        if problemas:
            reg.estado = Estado.BLOQUEADA
            self.estados_finales[reg.solicitud_id] = reg.estado
            self._audit.anexar(actor="pep", evento="VERIFICACION_FIRMAS_FALLIDA", solicitud_id=reg.solicitud_id,
                               estado=reg.estado.value, payload={"problemas": problemas})
            return {"ok": False, "estado": reg.estado.value, "mensaje": "; ".join(problemas)}

        orden = OrdenPago(solicitud_id=reg.solicitud_id, proveedor_id=reg.proveedor_id, beneficiario=reg.razon_social,
                          cuenta_destino=reg.cuenta, monto_cop=reg.monto_cop, numero_factura=reg.numero_factura,
                          hash_transaccion=h_actual)
        firma_pep = hmac.new(self._llave, orden.canonico(), hashlib.sha256).hexdigest()
        self._audit.anexar(actor="pep", evento="ORDEN_PAGO", solicitud_id=reg.solicitud_id, estado=reg.estado.value,
                           payload={"hash_transaccion": h_actual, "firmantes": [f.usuario_id for f in reg.firmas]})
        try:
            pago = self._pagos.ejecutar(orden, firma_pep, actor="pep")
        except PagoRechazado as e:
            reg.estado = Estado.RECHAZADA
            self.estados_finales[reg.solicitud_id] = reg.estado
            self._audit.anexar(actor="servicio_pagos", evento="PAGO_RECHAZADO", solicitud_id=reg.solicitud_id,
                               estado=reg.estado.value, payload={"motivo": str(e)})
            return {"ok": False, "estado": reg.estado.value, "mensaje": str(e)}
        reg.estado = Estado.EJECUTADA
        reg.pago = pago
        self.estados_finales[reg.solicitud_id] = reg.estado
        self._audit.anexar(actor="servicio_pagos", evento="EJECUTADA", solicitud_id=reg.solicitud_id,
                           estado=reg.estado.value,
                           payload={"pago_id": pago["pago_id"], "monto_cop": reg.monto_cop, "cuenta": reg.cuenta,
                                    "saldo_resultante": pago["saldo_resultante"]})
        return {"ok": True, "estado": reg.estado.value, "mensaje": f"Pago {pago['pago_id']} ejecutado", "pago": pago}

    def rechazar(self, solicitud_id: str, usuario_id: str, pin: str, motivo: str = "") -> dict:
        u = self._autenticar(solicitud_id, usuario_id, pin, "RECHAZO")
        if u["rol"] not in ROLES_QUE_PUEDEN_RECHAZAR:
            raise ErrorFirma(f"{ETIQUETA_ROL[u['rol']]} no puede rechazar solicitudes")
        reg = self.registros.get(solicitud_id)
        if reg is None or reg.estado not in ESTADOS_PENDIENTES:
            raise ErrorFirma("Solo se pueden rechazar solicitudes pendientes de firma")
        reg.estado = Estado.RECHAZADA
        self.estados_finales[solicitud_id] = reg.estado
        self._audit.anexar(actor=f"humano:{usuario_id}", evento="RECHAZADA_POR_HUMANO", solicitud_id=solicitud_id,
                           estado=reg.estado.value, payload={"rol": u["rol"].value, "motivo": motivo[:300]})
        return {"ok": True, "estado": reg.estado.value, "mensaje": f"Rechazada por {u['nombre']}"}

    def revisar_incidente(self, solicitud_id: str, usuario_id: str, pin: str, nota: str = "") -> dict:
        u = self._autenticar(solicitud_id, usuario_id, pin, "REVISION")
        if u["rol"] is not Rol.OFICIAL_SEGURIDAD:
            raise ErrorFirma("Solo el Oficial de Seguridad y Cumplimiento puede revisar incidentes bloqueados")
        if self.estados_finales.get(solicitud_id) is not Estado.BLOQUEADA:
            raise ErrorFirma("La solicitud no está bloqueada")
        self._audit.anexar(actor=f"humano:{usuario_id}", evento="INCIDENTE_REVISADO", solicitud_id=solicitud_id,
                           estado=Estado.BLOQUEADA.value,
                           payload={"caso": f"CASO-{solicitud_id[4:]}", "nota": nota[:300],
                                    "accion": "Caso abierto; la solicitud sigue BLOQUEADA (procedimiento 2.2)"})
        return {"ok": True, "estado": Estado.BLOQUEADA.value,
                "mensaje": "Incidente registrado. La solicitud permanece bloqueada; reabrirla exige un caso nuevo."}
