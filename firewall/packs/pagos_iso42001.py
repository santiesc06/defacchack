"""Policy Pack `pagos_iso42001`: tesorería y pagos autónomos desde correo (el caso original).

Encapsula el maestro de proveedores, órdenes de compra e historial (Repositorio), las reglas R1–R9 de
la Matriz 3 con umbrales en COP, la verificación telefónica, UNA firma humana (Tesorero; Director
financiero si el monto es alto o la cuenta cambió hace < 30 días), la restricción de 30 días a quien
aprobó un cambio de cuenta y el
ServicioPagosMock. Las reglas universales del núcleo se reportan con sus códigos históricos:
U0→R0, U1→R2, U2→R3.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from cfzt.contracts import NivelImpacto, ToolManifest

from .. import llm_local
from ..config import (DIAS_CUENTA_RECIENTE, DIAS_RESTRICCION_SOD_CAMBIO_CUENTA, UMBRAL_ALTO_COP, UMBRAL_BAJO_COP,
                      Rol, formato_cop)
from ..llm import delimitar_no_confiable
from ..pagos import OrdenPago, ServicioPagosMock
from ..repositorio import Repositorio, normalizar_cuenta
from ..schemas import (DecisionRelevancia, ExplicacionSchema, PropuestaPagoSchema, ReglaActivada,
                       SolicitudExtraccionSchema, ValidacionNegocioSchema)
from .base import DecisionPack, PolicyPack, RegistroAccion

import hashlib


def hash_transaccion(proveedor_id: str | None, cuenta: str, monto: int) -> str:
    """Hash que firma cada persona: beneficiario (proveedor), cuenta y monto."""
    return hashlib.sha256(f"{proveedor_id}|{normalizar_cuenta(cuenta)}|{monto}".encode()).hexdigest()


DESCRIPCION_REGLAS = {
    "R0": "Integridad de la invocación (herramienta permitida, argumentos válidos, etiquetas selladas)",
    "R1": "Proveedor no registrado, o cuenta distinta a la del maestro",
    "R2": "El Sanitizer marca riesgo ALTO",
    "R3": "Falla SPF/DKIM/DMARC o dominio parecido/distinto al legítimo",
    "R4": "Pago duplicado",
    "R5": "Sin factura u orden de compra que lo respalde",
    "R6": "Válido, riesgo bajo, hasta $2.000.000: firma el Tesorero",
    "R7": "Válido, riesgo medio o entre $2.000.000 y $20.000.000: firma el Tesorero con verificación telefónica",
    "R8": "Válido, más de $20.000.000: firma el Director financiero",
    "R9": "Cuenta del proveedor modificada en los últimos 30 días: firma el Director financiero",
    "U3": "Acción crítica desde contexto no confiable: requiere aprobación humana atada al hash de la acción",
}


@dataclass(kw_only=True)
class RegistroPago(RegistroAccion):
    proveedor_id: str
    razon_social: str
    cuenta: str
    monto_cop: int
    numero_factura: str | None = None
    numero_oc: str | None = None
    concepto: str = ""


class PackPagosISO42001(PolicyPack):
    id = "pagos_iso42001"
    nombre = "Tesorería y Pagos (ISO 42001)"
    descripcion = "Pagos autónomos desde correo: maestro de proveedores, R1–R9 en COP, una firma humana"
    agente_ejecutor = "agente:financiero"
    herramienta_ejecutora = "solicitar_ejecucion_pago"
    alias_reglas = {"U0": "R0", "U1": "R2", "U2": "R3"}
    descripcion_reglas = DESCRIPCION_REGLAS
    descripcion_hash = "beneficiario/cuenta/monto cambiaron"
    evento_orden = "ORDEN_PAGO"
    evento_rechazo = "PAGO_RECHAZADO"
    actor_servicio = "servicio_pagos"
    prompts = {"recepcionista": "recepcionista", "orquestador": "orquestador", "ejecutor": "financiero",
               "explicador": "explicador", "verificador": "verificador"}
    candidatos_firma = {  # se prueba primero a quien podría violar la segregación de funciones
        Rol.TESORERO: ["u-tomas", "u-teresa"],
        Rol.DIRECTOR_FINANCIERO: ["u-diana"],
    }
    etiquetas_ui = {
        "entrada": "Bandeja de entrada externa", "canal_por_defecto": "EMAIL_EXTERNO",
        "campos": {"remitente": "Remitente", "asunto": "Asunto", "cuerpo": "Cuerpo",
                   "adjunto": "Adjunto simulado", "autenticacion": "SPF / DKIM / DMARC"},
        "canales": [["EMAIL_EXTERNO", "Correo externo"], ["CANAL_INTERNO", "Canal interno (ERP)"]],
        "agentes": {"recepcionista": "Agente Recepcionista", "ejecutor": "Agente Financiero"},
        "kpi_activo": "Saldo empresarial", "accion": "Aprobar transacción", "panel": "Banco simulado",
        "herramienta": "solicitar_ejecucion_pago",
    }

    def __init__(self, reloj) -> None:
        from ..herramientas import herramientas_orquestador
        self.repo = Repositorio(reloj)
        self.vista = self.repo.vista_solo_lectura()
        self.pagos = ServicioPagosMock(self.repo)
        self.servicio_ejecucion = self.pagos
        self.directorio = self.repo
        self.origen_datos = self.repo.origen_datos
        self._tools = herramientas_orquestador(self.vista)
        self.manifiestos = {
            "solicitar_ejecucion_pago": ToolManifest(
                nombre="solicitar_ejecucion_pago", dominio=self.id, nivel_impacto=NivelImpacto.CRITICA_IRREVERSIBLE,
                esquema_args=PropuestaPagoSchema, requiere_aprobacion_humana_si_tainted=True,
                descripcion=("Entrega una propuesta de pago al PEP. NO ejecuta el pago: el PEP decide la ruta y una "
                             "persona debe confirmar y firmar.")),
            **{n: ToolManifest(nombre=n, dominio=self.id, nivel_impacto=NivelImpacto.LECTURA,
                               esquema_args=t.args_schema, requiere_aprobacion_humana_si_tainted=False,
                               descripcion=t.description) for n, t in self._tools.items()},
        }
        self.permisos = {
            "agente:financiero": frozenset({"solicitar_ejecucion_pago"}),
            "agente:orquestador": frozenset(self._tools),
            "agente:recepcionista": frozenset(), "agente:sanitizer": frozenset(), "agente:explicador": frozenset(),
        }

    # ==================================================================================
    # Agentes
    # ==================================================================================
    def extraer_solicitud(self, correo, llm):
        contenido = delimitar_no_confiable(
            f"De: {correo.nombre_remitente} <{correo.remitente}>\nAsunto: {correo.asunto}\n\n{correo.cuerpo}\n\n"
            f"[Adjunto {correo.adjunto_nombre or '-'}]\n{correo.adjunto_texto or ''}")
        return llm.estructurar("recepcionista", contenido, SolicitudExtraccionSchema,
                               lambda: llm_local.extraer_solicitud(correo))

    def relevancia(self, ext, asunto, llm):
        contenido = json.dumps({"solicitud": ext.model_dump(), "asunto_truncado": asunto[:120]}, ensure_ascii=False)
        dec, origen = llm.estructurar("orquestador", contenido, DecisionRelevancia,
                                      lambda: llm_local.decidir_relevancia(ext, asunto))
        if not ext.es_solicitud_pago and dec.requiere_accion_financiera and not ext.monto_cop:
            dec = DecisionRelevancia(requiere_accion_financiera=False, categoria="INFORMATIVA",
                                     justificacion="Sin monto ni datos de pago: no requiere al Agente Financiero.")
        return dec, origen

    def validar_reglas_negocio(self, ext, md):
        llamadas = []

        def usar(_herramienta: str, **args):
            args = {k: v for k, v in args.items() if v is not None}
            res = self._tools[_herramienta].invoke(args)
            llamadas.append({"herramienta": _herramienta, "argumentos": args, "resultado": res})
            return res

        prov = usar("consultar_maestro_proveedor", nombre=ext.beneficiario, nit=ext.nit_beneficiario,
                    dominio=md.dominio_remitente)
        pid = prov.get("proveedor_id")
        oc = usar("verificar_orden_compra", proveedor_id=pid, numero_oc=ext.numero_oc,
                  numero_factura=ext.numero_factura, monto_cop=ext.monto_cop)
        dup = usar("verificar_pago_duplicado", proveedor_id=pid, numero_factura=ext.numero_factura,
                   monto_cop=ext.monto_cop)
        obs = []
        registrado = bool(prov.get("encontrado"))
        cuenta_ok = registrado and normalizar_cuenta(ext.cuenta_destino) == normalizar_cuenta(prov.get("cuenta_registrada"))
        interno = md.origen == "INTERNO_VERIFICADO"
        dominio_ok = interno or (registrado and md.dominio_remitente == prov.get("dominio"))
        soporte = bool(oc.get("existe") and oc.get("coincide"))
        if not registrado:
            obs.append("Proveedor no encontrado en el maestro")
        elif not cuenta_ok:
            obs.append(f"La cuenta solicitada no coincide con la registrada de {prov.get('razon_social')}")
        if registrado and not dominio_ok:
            obs.append("El dominio del remitente no es el registrado del proveedor")
        if not soporte:
            obs.append(oc.get("detalle", "Sin soporte"))
        if dup.get("duplicado"):
            obs.append(dup.get("detalle", "Duplicado"))
        dias = prov.get("dias_desde_cambio_cuenta")
        if dias is not None and dias < 30:
            obs.append(f"Cuenta del proveedor modificada hace {dias} días")
        if not registrado or not cuenta_ok or not dominio_ok or md.nivel_riesgo == "ALTO":
            reco = "ESCALAR_SEGURIDAD"
        elif not soporte or dup.get("duplicado"):
            reco = "RECHAZAR"
        else:
            reco = "PROPONER_PAGO"
        val = ValidacionNegocioSchema(
            proveedor_registrado=registrado, proveedor_id=pid, razon_social=prov.get("razon_social"),
            cuenta_coincide_maestro=cuenta_ok, dominio_coincide=dominio_ok, dias_desde_cambio_cuenta=dias,
            soporte_valido=soporte, duplicado=bool(dup.get("duplicado")), recomendacion=reco,
            observaciones=tuple(obs) or ("Proveedor, cuenta, soporte e historial verificados",))
        return val, llamadas

    def preparar_propuesta(self, solicitud_id, ext, val, herramienta, llm):
        def local() -> dict:
            return {k: v for k, v in {
                "solicitud_id": solicitud_id, "proveedor_id": val.proveedor_id,
                "beneficiario": ext.beneficiario or val.razon_social or "Desconocido",
                "cuenta_destino": ext.cuenta_destino or "00000", "monto_cop": ext.monto_cop or 1,
                "concepto": (ext.concepto or "Pago")[:160], "numero_factura": ext.numero_factura,
                "numero_oc": ext.numero_oc}.items() if v is not None}

        contexto = {"solicitud_id": solicitud_id, "solicitud": ext.model_dump(), "validacion": val.model_dump()}
        return llm.llamar_herramienta("financiero", contexto, herramienta, local)

    # ==================================================================================
    # PEP: reglas del dominio (después de U0–U2 del núcleo)
    # ==================================================================================
    def evaluar_politicas_pep(self, p: PropuestaPagoSchema, ctx, *, bloqueado_por_core: bool, reloj) -> DecisionPack:
        md = ctx.metadata
        interno = md.origen == "INTERNO_VERIFICADO"
        prov = (self.vista.buscar_proveedor(proveedor_id=p.proveedor_id) if p.proveedor_id
                else self.vista.buscar_proveedor(nombre=p.beneficiario))
        dec = DecisionPack()

        def add(codigo: str, detalle: str, decision: str) -> None:
            dec.reglas.append(ReglaActivada(codigo=codigo, descripcion=detalle, decision=decision))

        if not prov.encontrado:
            add("R1", f"«{p.beneficiario}» no está registrado en el maestro de proveedores", "BLOQUEADA")
        elif normalizar_cuenta(p.cuenta_destino) != normalizar_cuenta(prov.cuenta_registrada):
            add("R1", f"Cuenta solicitada {p.cuenta_destino} ≠ cuenta registrada de {prov.razon_social} "
                      f"(…{prov.cuenta_registrada[-4:]})", "BLOQUEADA")
        # La suplantación por dominio parecido es U2 (núcleo); aquí, el dominio distinto al registrado.
        if prov.encontrado and not interno and not md.dominio_parecido_a and md.dominio_remitente != prov.dominio:
            add("R3", f"Dominio {md.dominio_remitente} distinto al registrado ({prov.dominio})", "BLOQUEADA")
        dup = self.vista.buscar_duplicado(proveedor_id=prov.proveedor_id, numero_factura=p.numero_factura,
                                          monto_cop=p.monto_cop)
        if dup.duplicado:
            add("R4", dup.detalle, "RECHAZADA")
        sop = self.vista.buscar_soporte(proveedor_id=prov.proveedor_id, numero_oc=p.numero_oc,
                                        numero_factura=p.numero_factura, monto_cop=p.monto_cop)
        if not (sop.existe and sop.coincide):
            add("R5", sop.detalle, "RECHAZADA")
        if bloqueado_por_core or dec.reglas:
            return dec

        # --- Ruta de aprobación: UNA sola firma humana ----------------------------------
        # Firma la Tesorería; el Director financiero firma en su lugar si el monto es alto (R8) o la
        # cuenta del proveedor cambió hace menos de 30 días (R9). Cuentas por pagar prepara y revisa.
        requeridas = [Rol.TESORERO]
        telefono = False
        if prov.dias_desde_cambio_cuenta is not None and prov.dias_desde_cambio_cuenta < DIAS_CUENTA_RECIENTE:
            add("R9", f"Cuenta modificada hace {prov.dias_desde_cambio_cuenta} días: firma el Director financiero", "FIRMAS")
            telefono = True
            requeridas = [Rol.DIRECTOR_FINANCIERO]
        if p.monto_cop > UMBRAL_ALTO_COP:
            add("R8", f"Monto {formato_cop(p.monto_cop)} supera {formato_cop(UMBRAL_ALTO_COP)}: firma el Director financiero",
                "FIRMAS")
            requeridas = [Rol.DIRECTOR_FINANCIERO]
        if md.nivel_riesgo == "MEDIO" or UMBRAL_BAJO_COP < p.monto_cop <= UMBRAL_ALTO_COP:
            motivo = ("riesgo MEDIO" if md.nivel_riesgo == "MEDIO"
                      else f"monto entre {formato_cop(UMBRAL_BAJO_COP)} y {formato_cop(UMBRAL_ALTO_COP)}")
            add("R7", f"Requiere verificación telefónica: {motivo}", "FIRMAS")
            telefono = True
        if not dec.reglas:
            add("R6", "Riesgo bajo y monto hasta $2.000.000", "FIRMAS")
        principal = sorted(dec.reglas, key=lambda r: {"R9": 0, "R8": 1, "R7": 2, "R6": 3}[r.codigo])[0]

        h = hash_transaccion(prov.proveedor_id, prov.cuenta_registrada, p.monto_cop)
        dec.firmas_requeridas = tuple(requeridas)
        dec.verificacion_telefonica = telefono
        dec.telefono_registrado = prov.telefono_registrado
        dec.regla_principal = principal.codigo
        dec.hash_accion = h
        dec.registro = RegistroPago(
            solicitud_id=p.solicitud_id, proveedor_id=prov.proveedor_id, razon_social=prov.razon_social,
            cuenta=prov.cuenta_registrada, monto_cop=p.monto_cop, numero_factura=p.numero_factura,
            numero_oc=p.numero_oc or sop.numero_oc, concepto=p.concepto, hash_transaccion=h,
            firmas_requeridas=tuple(requeridas), verificacion_telefonica_requerida=telefono,
            telefono_registrado=prov.telefono_registrado, iniciado_por=ctx.iniciado_por, creado=reloj())
        return dec

    def verificar_firmante(self, reg: RegistroPago, u: dict, verificacion_telefonica: bool, es_ultima: bool):
        prov = self.vista.buscar_proveedor(proveedor_id=reg.proveedor_id)
        if (prov.cambio_cuenta_aprobado_por == u["usuario_id"] and prov.dias_desde_cambio_cuenta is not None
                and prov.dias_desde_cambio_cuenta < DIAS_RESTRICCION_SOD_CAMBIO_CUENTA):
            return (f"Segregación de funciones: {u['nombre']} aprobó el cambio de cuenta de este proveedor hace "
                    f"{prov.dias_desde_cambio_cuenta} días (restricción de 30 días)")
        if verificacion_telefonica and str(u["rol"]) in (Rol.TESORERO, Rol.DIRECTOR_FINANCIERO):
            reg.verificacion_telefonica_hecha = True
        if es_ultima and reg.verificacion_telefonica_requerida and not reg.verificacion_telefonica_hecha:
            return (f"Falta la constancia de verificación telefónica al número registrado {reg.telefono_registrado} "
                    "(la registra quien firma)")
        return None

    def hash_registro(self, reg: RegistroPago) -> str:
        return hash_transaccion(reg.proveedor_id, reg.cuenta, reg.monto_cop)

    def revalidar_registro(self, reg: RegistroPago) -> list[str]:
        prov = self.vista.buscar_proveedor(proveedor_id=reg.proveedor_id)
        if normalizar_cuenta(prov.cuenta_registrada) != normalizar_cuenta(reg.cuenta):
            return ["La cuenta del maestro cambió después de iniciar las firmas"]
        return []

    def orden_desde_registro(self, reg: RegistroPago, hash_actual: str) -> OrdenPago:
        return OrdenPago(solicitud_id=reg.solicitud_id, proveedor_id=reg.proveedor_id, beneficiario=reg.razon_social,
                         cuenta_destino=reg.cuenta, monto_cop=reg.monto_cop, numero_factura=reg.numero_factura,
                         hash_transaccion=hash_actual)

    def payload_ejecucion(self, reg: RegistroPago, pago: dict) -> dict:
        return {"pago_id": pago["pago_id"], "monto_cop": pago["monto_cop"], "cuenta": pago["cuenta_destino"],
                "saldo_resultante": pago["saldo_resultante"]}

    def mensaje_ejecucion(self, pago: dict) -> str:
        return f"Pago {pago['pago_id']} ejecutado"

    # ==================================================================================
    # Comparación, UI y benchmark
    # ==================================================================================
    def ejecutar_directo(self, args: dict, actor: str) -> tuple[dict, str]:
        p = PropuestaPagoSchema.model_validate(args)
        h = hash_transaccion(p.proveedor_id, p.cuenta_destino, p.monto_cop)
        orden = OrdenPago(solicitud_id=p.solicitud_id, proveedor_id=p.proveedor_id, beneficiario=p.beneficiario,
                          cuenta_destino=p.cuenta_destino, monto_cop=p.monto_cop, numero_factura=p.numero_factura,
                          hash_transaccion=h)
        return self.pagos.ejecutar(orden, None, actor=actor), h

    def datos_verificados(self, reg: RegistroPago | None, args: dict) -> dict:
        monto_args = args.get("monto_cop") if isinstance(args.get("monto_cop"), int) else None
        return {
            "beneficiario": reg.razon_social if reg else args.get("beneficiario"),
            "cuenta": reg.cuenta if reg else args.get("cuenta_destino"),
            "monto_cop": reg.monto_cop if reg else monto_args,
            "monto_formateado": formato_cop(reg.monto_cop if reg else monto_args),
            "hash_transaccion": reg.hash_transaccion if reg else None,
            "fuente": "Maestro de proveedores (verificado por el PEP)" if reg else "Datos propuestos por el agente (sin verificar)",
        }

    def propuesta_para_explicador(self, args: dict, dv: dict) -> dict:
        return {**args, "beneficiario": dv["beneficiario"], "cuenta_destino": dv["cuenta"]}

    def datos_internos(self, args: dict) -> dict:
        pid = args.get("proveedor_id") if isinstance(args.get("proveedor_id"), str) else None
        prov = (self.vista.buscar_proveedor(proveedor_id=pid) if pid
                else self.vista.buscar_proveedor(nombre=str(args.get("beneficiario") or "")))
        monto = args.get("monto_cop") if isinstance(args.get("monto_cop"), int) else None
        return {
            "maestro_proveedor": prov.model_dump(exclude={"cambio_cuenta_aprobado_por"}),
            "orden_de_compra": self.vista.buscar_soporte(
                proveedor_id=prov.proveedor_id, numero_oc=args.get("numero_oc"),
                numero_factura=args.get("numero_factura"), monto_cop=monto).model_dump(),
            "historial": self.vista.buscar_duplicado(
                proveedor_id=prov.proveedor_id, numero_factura=args.get("numero_factura"), monto_cop=monto).model_dump(),
        }

    def explicar_local(self, datos: dict) -> ExplicacionSchema:
        return llm_local.explicar(datos)

    def explicacion_coherente(self, exp, dv: dict) -> bool:
        from ..herramientas import explicacion_coherente
        monto = dv["monto_cop"] if isinstance(dv["monto_cop"], int) else 0
        return explicacion_coherente(exp, monto, str(dv["cuenta"] or ""))

    def dominios_protegidos(self) -> list[str]:
        return self.repo.dominios_registrados()

    def escenarios(self) -> list[dict]:
        from ..escenarios import ESCENARIOS
        return ESCENARIOS

    def kpis(self) -> dict:
        cuentas = self.repo.cuentas_registradas()
        desviado = sum(p["monto_cop"] for p in self.pagos.ejecutados
                       if normalizar_cuenta(p["cuenta_destino"]) not in cuentas)
        return {
            "activo": self.pagos.saldo, "activo_inicial": self.pagos.saldo_inicial, "activo_formato": "cop",
            "ejecutadas_con_firma": sum(1 for p in self.pagos.ejecutados if p["con_firma_pep"]),
            "ejecutadas_sin_control": sum(1 for p in self.pagos.ejecutados if not p["con_firma_pep"]),
            "danio": desviado, "danio_etiqueta": "Desviado a cuentas no registradas", "danio_formato": "cop",
            "movimientos": [{"id": p["pago_id"], "titulo": p["beneficiario"], "detalle": p["cuenta_destino"],
                             "valor": -p["monto_cop"], "valor_formato": "cop", "con_control": p["con_firma_pep"]}
                            for p in reversed(self.pagos.ejecutados)][:20],
        }
