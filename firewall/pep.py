"""Policy Enforcement Point — código determinista, sin LLM, agnóstico al dominio.

Capa 1: intercepta cada invocación de herramienta del Agente Ejecutor y aplica, en este orden,
        1) las reglas universales del núcleo `cfzt.pep.UniversalPEP` (U0–U3) y
        2) las reglas del Policy Pack activo (pagos R1–R9, DevOps D1–D5).
Capa 2: gestiona las firmas humanas (U4 segregación de funciones, MFA, hash de la acción, vigencia)
        y es el ÚNICO componente que puede ordenar la ejecución al servicio del pack.

Zero-trust interno: el PEP no confía en lo que dicen los agentes. El pack vuelve a consultar por sí
mismo sus datos de referencia (maestro, catálogo), el núcleo verifica el sello de las etiquetas del
Sanitizer, y la orden se construye con los datos verificados, no con los del correo o del issue.
"""
from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable

from cfzt.pep import REGLAS_UNIVERSALES, UniversalPEP

from .audit import AuditLogSHA256
from .config import HORAS_VIGENCIA_FIRMA, ROLES_QUE_PUEDEN_RECHAZAR, Rol, etiqueta_rol
from .packs.base import EjecucionRechazada, PolicyPack
from .sanitizer import sellar
from .schemas import ESTADOS_PENDIENTES, Estado, Firma, MetadataSeguridadSchema, ReglaActivada, VeredictoPEP

# Compatibilidad: el pack de pagos conserva sus nombres históricos.
from .packs.pagos_iso42001 import DESCRIPCION_REGLAS, RegistroPago, hash_transaccion  # noqa: E402,F401

PERMISOS_HERRAMIENTAS = {  # Matriz 1 del pack de pagos (cada pack declara la suya en `permisos`)
    "agente:financiero": frozenset({"solicitar_ejecucion_pago"}),
    "agente:recepcionista": frozenset(), "agente:sanitizer": frozenset(),
    "agente:orquestador": frozenset(), "agente:explicador": frozenset(),
}


@dataclass(frozen=True)
class ContextoPEP:
    """Lo fija el entorno de ejecución (no un agente)."""
    solicitud_id: str
    metadata: MetadataSeguridadSchema
    sello_registrado: str
    iniciado_por: str | None = None
    correo: object | None = None  # solo lo usa el verificador del modo SOLO_LLM; el PEP lo ignora


class ErrorFirma(Exception):
    pass


class PolicyEnforcementPoint:
    def __init__(self, pack: PolicyPack, audit: AuditLogSHA256, reloj: Callable[[], datetime]) -> None:
        self.pack = pack
        self.core = UniversalPEP(pack.id, pack.permisos, pack.manifiestos)
        self._directorio = pack.directorio
        self._servicio = pack.servicio_ejecucion
        self._llave = self._servicio.emitir_llave_pep()  # único emisor de órdenes de ejecución
        self._audit = audit
        self._reloj = reloj
        self.registros: dict = {}
        self.estados_finales: dict[str, Estado] = {}

    def _codigo(self, codigo: str) -> str:
        return self.pack.etiqueta(codigo)

    def _descripcion(self, codigo: str) -> str:
        return self.pack.descripcion_reglas.get(codigo) or REGLAS_UNIVERSALES.get(codigo, codigo)

    # ====================================================================================
    # Capa 1 — núcleo universal + reglas del pack
    # ====================================================================================
    def evaluar(self, agente: str, herramienta: str, args: dict, ctx: ContextoPEP) -> VeredictoPEP:
        t0 = time.perf_counter()
        veredicto = self._evaluar(agente, herramienta, args, ctx)
        veredicto = veredicto.model_copy(update={"latencia_ms": round((time.perf_counter() - t0) * 1000, 3)})
        self.estados_finales[ctx.solicitud_id] = veredicto.estado
        self._audit.anexar(actor="pep", evento="DECISION_PEP", solicitud_id=ctx.solicitud_id,
                           estado=veredicto.estado.value,
                           payload={"dominio": self.pack.id, "decision": veredicto.decision,
                                    "regla_principal": veredicto.regla_principal,
                                    "reglas": [r.codigo for r in veredicto.reglas],
                                    "firmas_requeridas": [str(r) for r in veredicto.firmas_requeridas],
                                    "hash_transaccion": veredicto.hash_transaccion,
                                    "alerta_seguridad": veredicto.alerta_seguridad})
        if veredicto.alerta_seguridad:
            self._audit.anexar(actor="pep", evento="ALERTA_OFICIAL_SEGURIDAD", solicitud_id=ctx.solicitud_id,
                               estado=veredicto.estado.value,
                               payload={"caso": f"CASO-{ctx.solicitud_id[4:]}", "motivo": veredicto.regla_principal})
        return veredicto

    def _evaluar(self, agente: str, herramienta: str, args: dict, ctx: ContextoPEP) -> VeredictoPEP:
        md = ctx.metadata
        core = self.core.evaluar_core(
            agente, herramienta, args, solicitud_id=ctx.solicitud_id, tainted=md.tainted,
            nivel_riesgo=md.nivel_riesgo, autenticacion_origen_valida=md.spf_dkim_valido,
            suplantacion=(f"dominio {md.dominio_remitente} parecido a {md.dominio_parecido_a}"
                          if md.dominio_parecido_a else None),
            sello_valido=sellar(md) == ctx.sello_registrado)
        reglas = [ReglaActivada(codigo=self._codigo(r.codigo), descripcion=r.descripcion, decision=r.decision)
                  for r in core.reglas]
        if core.integridad_fallida:
            r = reglas[0]
            return VeredictoPEP(decision="BLOQUEADA", estado=Estado.BLOQUEADA, regla_principal=f"{r.codigo} · {r.descripcion}",
                                reglas=(r,), alerta_seguridad=True)

        dec = self.pack.evaluar_politicas_pep(core.args, ctx, bloqueado_por_core=core.bloqueada, reloj=self._reloj)
        reglas += dec.reglas
        bloqueos = [r for r in reglas if r.decision == "BLOQUEADA"]
        if bloqueos:
            c = bloqueos[0].codigo
            return VeredictoPEP(decision="BLOQUEADA", estado=Estado.BLOQUEADA, regla_principal=f"{c} · {self._descripcion(c)}",
                                reglas=tuple(reglas), alerta_seguridad=True)
        rechazos = [r for r in reglas if r.decision == "RECHAZADA"]
        if rechazos:
            c = rechazos[0].codigo
            return VeredictoPEP(decision="RECHAZADA", estado=Estado.RECHAZADA, regla_principal=f"{c} · {self._descripcion(c)}",
                                reglas=tuple(reglas))

        # U3: una acción crítica desde contexto contaminado nunca se ejecuta sola.
        if core.requiere_humano:
            reglas.append(ReglaActivada(codigo=self._codigo("U3"), descripcion=REGLAS_UNIVERSALES["U3"], decision="FIRMAS"))
        if dec.registro is None:  # defensa en profundidad: sin ruta de firmas no hay ejecución
            return VeredictoPEP(decision="BLOQUEADA", estado=Estado.BLOQUEADA, alerta_seguridad=True,
                                regla_principal="U3 · El pack no definió una ruta de aprobación humana", reglas=tuple(reglas))
        self.registros[ctx.solicitud_id] = dec.registro
        principal = dec.regla_principal or "U3"
        return VeredictoPEP(decision="PENDING_APPROVAL", estado=Estado.PENDIENTE_FIRMA_1,
                            regla_principal=f"{principal} · {self._descripcion(principal)}",
                            reglas=tuple(reglas), firmas_requeridas=tuple(dec.firmas_requeridas),
                            verificacion_telefonica=dec.verificacion_telefonica,
                            telefono_registrado=dec.telefono_registrado, hash_transaccion=dec.hash_accion)

    # ====================================================================================
    # Capa 2 — supervisión humana (U4 + restricciones del pack)
    # ====================================================================================
    def _firma_hmac(self, usuario_id: str, reg, ts: datetime, h: str) -> str:
        llave = self._directorio.usuario(usuario_id)["llave_firma"]
        return hmac.new(llave, f"{reg.solicitud_id}|{h}|{ts.isoformat()}".encode(), hashlib.sha256).hexdigest()

    def _autenticar(self, solicitud_id: str, usuario_id: str, pin: str, accion: str) -> dict:
        if UniversalPEP.es_identidad_de_agente(usuario_id):
            raise ErrorFirma("Ningún agente de IA puede aprobar, firmar ni rechazar (Matriz 2)")
        u = self._directorio.usuario(usuario_id)
        if u is None or not self._directorio.verificar_pin(usuario_id, pin):
            self._audit.anexar(actor=f"humano:{usuario_id}", evento=f"{accion}_DENEGADA", solicitud_id=solicitud_id,
                               payload={"motivo": "MFA fallida (PIN incorrecto)"})
            raise ErrorFirma("Autenticación MFA fallida: PIN incorrecto")
        return u

    def _denegar(self, reg, u: dict, motivo: str) -> None:
        self._audit.anexar(actor=f"humano:{u['usuario_id']}", evento="FIRMA_DENEGADA", solicitud_id=reg.solicitud_id,
                           estado=reg.estado.value, payload={"motivo": motivo, "rol": str(u["rol"])})
        raise ErrorFirma(motivo)

    def _expirar_si_vencida(self, reg) -> bool:
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
            if self.estados_finales.get(solicitud_id) is Estado.BLOQUEADA:
                raise ErrorFirma("Solicitud BLOQUEADA: no se puede aprobar. Solo el Oficial de Seguridad puede revisar el incidente")
            raise ErrorFirma("No hay una solicitud pendiente de firma con ese identificador")
        u = self._autenticar(solicitud_id, usuario_id, pin, "FIRMA")
        if self._expirar_si_vencida(reg):
            raise ErrorFirma("La solicitud venció (48 h) y pasó a EXPIRADA; debe iniciarse de nuevo")
        if reg.estado not in ESTADOS_PENDIENTES:
            raise ErrorFirma(f"La solicitud está {reg.estado.value}; no admite firmas")

        rol = str(u["rol"])
        previos = [f.usuario_id for f in reg.firmas]
        if rol == Rol.ADMIN_PLATAFORMA:  # U4
            self._denegar(reg, u, UniversalPEP.verificar_sod(usuario_id, iniciado_por=None, firmantes_previos=[],
                                                             es_admin_plataforma=True))
        esperado = str(reg.firmas_requeridas[len(reg.firmas)])
        if rol != esperado:
            self._denegar(reg, u, f"Se espera la firma {len(reg.firmas) + 1} de {etiqueta_rol(esperado)}; "
                                  f"{u['nombre']} es {etiqueta_rol(rol)}")
        motivo = UniversalPEP.verificar_sod(usuario_id, iniciado_por=reg.iniciado_por, firmantes_previos=previos,
                                            es_admin_plataforma=False)  # U4
        if motivo:
            self._denegar(reg, u, motivo)
        es_ultima = len(reg.firmas) + 1 == len(reg.firmas_requeridas)
        motivo = self.pack.verificar_firmante(reg, u, verificacion_telefonica, es_ultima)
        if motivo:
            self._denegar(reg, u, motivo)

        ts = self._reloj()
        firma = Firma(usuario_id=usuario_id, nombre=u["nombre"], rol=rol, hash_transaccion=reg.hash_transaccion,
                      timestamp=ts, firma_hmac=self._firma_hmac(usuario_id, reg, ts, reg.hash_transaccion),
                      verificacion_telefonica=verificacion_telefonica)
        reg.firmas.append(firma)
        n = len(reg.firmas)
        self._audit.anexar(actor=f"humano:{usuario_id}", evento=f"FIRMA_{n}", solicitud_id=solicitud_id,
                           estado=reg.estado.value,
                           payload={"rol": rol, "hash_transaccion": reg.hash_transaccion,
                                    "firma_hmac": firma.firma_hmac[:16] + "…",
                                    "verificacion_telefonica": verificacion_telefonica})
        if n < len(reg.firmas_requeridas):
            reg.estado = [Estado.PENDIENTE_FIRMA_1, Estado.PENDIENTE_FIRMA_2, Estado.PENDIENTE_FIRMA_3][n]
            self.estados_finales[solicitud_id] = reg.estado
            return {"ok": True, "estado": reg.estado.value, "mensaje": f"Firma {n} de {len(reg.firmas_requeridas)} registrada"}
        return self._ordenar_ejecucion(reg)

    def _ordenar_ejecucion(self, reg) -> dict:
        """Re-verificar firmas y SoD sobre los datos ACTUALES; luego ordenar la ejecución al servicio del pack."""
        h_actual = self.pack.hash_registro(reg)
        problemas = list(self.pack.revalidar_registro(reg))
        if len({f.usuario_id for f in reg.firmas}) != len(reg.firmas):
            problemas.append("Firmantes repetidos")
        for f in reg.firmas:
            if f.hash_transaccion != h_actual or not hmac.compare_digest(
                    f.firma_hmac, self._firma_hmac(f.usuario_id, reg, f.timestamp, h_actual)):
                problemas.append(f"La firma de {f.nombre} no cubre los datos actuales ({self.pack.descripcion_hash})")
            if self._reloj() - f.timestamp > timedelta(hours=HORAS_VIGENCIA_FIRMA):
                problemas.append(f"La firma de {f.nombre} venció")
        if problemas:
            reg.estado = Estado.BLOQUEADA
            self.estados_finales[reg.solicitud_id] = reg.estado
            self._audit.anexar(actor="pep", evento="VERIFICACION_FIRMAS_FALLIDA", solicitud_id=reg.solicitud_id,
                               estado=reg.estado.value, payload={"problemas": problemas})
            return {"ok": False, "estado": reg.estado.value, "mensaje": "; ".join(problemas)}

        orden = self.pack.orden_desde_registro(reg, h_actual)
        firma_pep = hmac.new(self._llave, orden.canonico(), hashlib.sha256).hexdigest()
        self._audit.anexar(actor="pep", evento=self.pack.evento_orden, solicitud_id=reg.solicitud_id,
                           estado=reg.estado.value,
                           payload={"hash_transaccion": h_actual, "firmantes": [f.usuario_id for f in reg.firmas]})
        try:
            resultado = self.pack.ejecutar_accion_aprobada(orden, firma_pep)
        except EjecucionRechazada as e:
            reg.estado = Estado.RECHAZADA
            self.estados_finales[reg.solicitud_id] = reg.estado
            self._audit.anexar(actor=self.pack.actor_servicio, evento=self.pack.evento_rechazo,
                               solicitud_id=reg.solicitud_id, estado=reg.estado.value, payload={"motivo": str(e)})
            return {"ok": False, "estado": reg.estado.value, "mensaje": str(e)}
        reg.estado = Estado.EJECUTADA
        reg.resultado = resultado
        self.estados_finales[reg.solicitud_id] = reg.estado
        self._audit.anexar(actor=self.pack.actor_servicio, evento="EJECUTADA", solicitud_id=reg.solicitud_id,
                           estado=reg.estado.value, payload=self.pack.payload_ejecucion(reg, resultado))
        return {"ok": True, "estado": reg.estado.value, "mensaje": self.pack.mensaje_ejecucion(resultado),
                "pago": resultado}

    def rechazar(self, solicitud_id: str, usuario_id: str, pin: str, motivo: str = "") -> dict:
        u = self._autenticar(solicitud_id, usuario_id, pin, "RECHAZO")
        if u["rol"] not in ROLES_QUE_PUEDEN_RECHAZAR:
            raise ErrorFirma(f"{etiqueta_rol(u['rol'])} no puede rechazar solicitudes")
        reg = self.registros.get(solicitud_id)
        if reg is None or reg.estado not in ESTADOS_PENDIENTES:
            raise ErrorFirma("Solo se pueden rechazar solicitudes pendientes de firma")
        reg.estado = Estado.RECHAZADA
        self.estados_finales[solicitud_id] = reg.estado
        self._audit.anexar(actor=f"humano:{usuario_id}", evento="RECHAZADA_POR_HUMANO", solicitud_id=solicitud_id,
                           estado=reg.estado.value, payload={"rol": str(u["rol"]), "motivo": motivo[:300]})
        return {"ok": True, "estado": reg.estado.value, "mensaje": f"Rechazada por {u['nombre']}"}

    def revisar_incidente(self, solicitud_id: str, usuario_id: str, pin: str, nota: str = "") -> dict:
        u = self._autenticar(solicitud_id, usuario_id, pin, "REVISION")
        if str(u["rol"]) != Rol.OFICIAL_SEGURIDAD:
            raise ErrorFirma("Solo el Oficial de Seguridad y Cumplimiento puede revisar incidentes bloqueados")
        if self.estados_finales.get(solicitud_id) is not Estado.BLOQUEADA:
            raise ErrorFirma("La solicitud no está bloqueada")
        self._audit.anexar(actor=f"humano:{usuario_id}", evento="INCIDENTE_REVISADO", solicitud_id=solicitud_id,
                           estado=Estado.BLOQUEADA.value,
                           payload={"caso": f"CASO-{solicitud_id[4:]}", "nota": nota[:300],
                                    "accion": "Caso abierto; la solicitud sigue BLOQUEADA (procedimiento 2.2)"})
        return {"ok": True, "estado": Estado.BLOQUEADA.value,
                "mensaje": "Incidente registrado. La solicitud permanece bloqueada; reabrirla exige un caso nuevo."}
