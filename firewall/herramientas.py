"""Herramientas LangChain con contratos Pydantic + ToolGateway.

- Herramientas del Orquestador: SOLO LECTURA sobre el maestro, OC e historial.
- Herramienta del Agente Financiero: `solicitar_ejecucion_pago`. Su implementación NO paga: entrega
  la invocación al `ToolGateway`, que (1) la somete al PEP y (2) pide al Agente Explicador que se la
  explique a la persona y le pida confirmación. No existe ninguna herramienta de aprobación o firma
  expuesta a los agentes (Matriz 2).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .config import ETIQUETA_ROL, formato_cop
from .pagos import OrdenPago, PagoRechazado, ServicioPagosMock
from .pep import ContextoPEP, PolicyEnforcementPoint, hash_transaccion
from .repositorio import VistaSoloLectura
from .schemas import (PATRON_FACTURA, PATRON_OC, Estado, ExplicacionSchema, PropuestaPagoSchema, ProveedorInfo,
                      ResultadoDuplicado, ResultadoOC, VeredictoPEP)


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ConsultaProveedorArgs(_Args):
    nombre: str | None = Field(default=None, max_length=120)
    nit: str | None = Field(default=None, max_length=20)
    dominio: str | None = Field(default=None, max_length=120)


class ConsultaOCArgs(_Args):
    proveedor_id: str | None = Field(default=None, pattern=r"^PROV-[0-9]{3}$")
    numero_oc: str | None = Field(default=None, pattern=PATRON_OC)
    numero_factura: str | None = Field(default=None, pattern=PATRON_FACTURA)
    monto_cop: int | None = Field(default=None, gt=0)


class ConsultaDuplicadoArgs(_Args):
    proveedor_id: str | None = Field(default=None, pattern=r"^PROV-[0-9]{3}$")
    numero_factura: str | None = Field(default=None, pattern=PATRON_FACTURA)
    monto_cop: int | None = Field(default=None, gt=0)


def herramientas_orquestador(vista: VistaSoloLectura) -> dict[str, StructuredTool]:
    def consultar_maestro_proveedor(nombre=None, nit=None, dominio=None) -> dict:
        info: ProveedorInfo = vista.buscar_proveedor(nombre=nombre, nit=nit, dominio=dominio)
        if not info.encontrado and dominio:
            info = vista.buscar_proveedor(dominio=dominio)
        return info.model_dump()

    def verificar_orden_compra(proveedor_id=None, numero_oc=None, numero_factura=None, monto_cop=None) -> dict:
        r: ResultadoOC = vista.buscar_soporte(proveedor_id=proveedor_id, numero_oc=numero_oc,
                                              numero_factura=numero_factura, monto_cop=monto_cop)
        return r.model_dump()

    def verificar_pago_duplicado(proveedor_id=None, numero_factura=None, monto_cop=None) -> dict:
        r: ResultadoDuplicado = vista.buscar_duplicado(proveedor_id=proveedor_id, numero_factura=numero_factura,
                                                       monto_cop=monto_cop)
        return r.model_dump()

    return {
        "consultar_maestro_proveedor": StructuredTool.from_function(
            consultar_maestro_proveedor, name="consultar_maestro_proveedor", args_schema=ConsultaProveedorArgs,
            description="SOLO LECTURA. Busca un proveedor en el maestro por nombre, NIT o dominio."),
        "verificar_orden_compra": StructuredTool.from_function(
            verificar_orden_compra, name="verificar_orden_compra", args_schema=ConsultaOCArgs,
            description="SOLO LECTURA. Verifica que exista factura u OC que respalde el pago y que coincida."),
        "verificar_pago_duplicado": StructuredTool.from_function(
            verificar_pago_duplicado, name="verificar_pago_duplicado", args_schema=ConsultaDuplicadoArgs,
            description="SOLO LECTURA. Revisa el historial de pagos para detectar duplicados."),
    }


# =========================================================================================
@dataclass
class ResultadoGateway:
    veredicto: VeredictoPEP
    explicacion: ExplicacionSchema
    explicacion_coherente: bool
    origen_explicador: str
    datos_verificados: dict


def _solo_digitos(s: str) -> str:
    return re.sub(r"\D", "", s)


def explicacion_coherente(exp: ExplicacionSchema, monto: int, cuenta: str) -> bool:
    """Control determinista: la explicación del LLM debe citar el monto y la cuenta exactos."""
    texto = _solo_digitos(f"{exp.resumen} {exp.pregunta_confirmacion}")
    return str(monto) in texto and _solo_digitos(cuenta) in texto


class ToolGateway:
    """Interceptor de TODAS las herramientas del Agente Financiero."""

    def __init__(self, pep: PolicyEnforcementPoint, pagos: ServicioPagosMock, audit,
                 explicar: Callable[[dict], tuple[ExplicacionSchema, str]]) -> None:
        self._pep = pep
        self._pagos = pagos
        self._audit = audit
        self._explicar = explicar

    def invocar(self, agente: str, herramienta: str, args: dict, ctx: ContextoPEP, *, pep_activo: bool) -> ResultadoGateway:
        self._audit.anexar(actor=agente, evento="INVOCACION_HERRAMIENTA", solicitud_id=ctx.solicitud_id,
                           payload={"herramienta": herramienta, "argumentos": args})
        if pep_activo:
            v = self._pep.evaluar(agente, herramienta, args, ctx)
        else:
            v = self._ejecutar_sin_control(args, ctx)

        reg = self._pep.registros.get(ctx.solicitud_id) if pep_activo else None
        datos_verificados = {
            "beneficiario": reg.razon_social if reg else args.get("beneficiario"),
            "cuenta": reg.cuenta if reg else args.get("cuenta_destino"),
            "monto_cop": reg.monto_cop if reg else args.get("monto_cop"),
            "monto_formateado": formato_cop(reg.monto_cop if reg else (args.get("monto_cop") if isinstance(args.get("monto_cop"), int) else None)),
            "hash_transaccion": v.hash_transaccion,
            "fuente": "Maestro de proveedores (verificado por el PEP)" if reg else "Datos propuestos por el agente (sin verificar)",
        }
        datos = {
            "propuesta": {**args, "beneficiario": datos_verificados["beneficiario"],
                          "cuenta_destino": datos_verificados["cuenta"]},
            "veredicto": v.model_dump(mode="json"),
            # Sin `evidencias`: citan texto del atacante y el Explicador no debe ver texto del correo.
            "metadata": ctx.metadata.model_dump(mode="json", exclude={"evidencias"}),
            "etiquetas_firmantes": [ETIQUETA_ROL[r] for r in v.firmas_requeridas],
        }
        exp, origen = self._explicar(datos)
        monto = datos_verificados["monto_cop"] if isinstance(datos_verificados["monto_cop"], int) else 0
        coherente = explicacion_coherente(exp, monto, str(datos_verificados["cuenta"] or ""))
        self._audit.anexar(actor="agente:explicador", evento="EXPLICACION_A_HUMANO", solicitud_id=ctx.solicitud_id,
                           estado=v.estado.value,
                           payload={"titulo": exp.titulo, "recomendacion": exp.recomendacion, "coherente": coherente,
                                    "origen": origen})
        return ResultadoGateway(v, exp, coherente, origen, datos_verificados)

    def _ejecutar_sin_control(self, args: dict, ctx: ContextoPEP) -> VeredictoPEP:
        """Línea base «confianza implícita» (P4): sin reglas, sin firmas, sin confirmación."""
        try:
            p = PropuestaPagoSchema.model_validate(args)
        except ValidationError:
            return VeredictoPEP(decision="RECHAZADA", estado=Estado.RECHAZADA, pep_activo=False,
                                regla_principal="Servicio de pagos: argumentos ilegibles")
        h = hash_transaccion(p.proveedor_id, p.cuenta_destino, p.monto_cop)
        orden = OrdenPago(solicitud_id=p.solicitud_id, proveedor_id=p.proveedor_id, beneficiario=p.beneficiario,
                          cuenta_destino=p.cuenta_destino, monto_cop=p.monto_cop, numero_factura=p.numero_factura,
                          hash_transaccion=h)
        try:
            pago = self._pagos.ejecutar(orden, None, actor="agente:financiero")
        except PagoRechazado as e:
            return VeredictoPEP(decision="RECHAZADA", estado=Estado.RECHAZADA, regla_principal=f"Servicio de pagos: {e}",
                                pep_activo=False, hash_transaccion=h)
        self._pep.estados_finales[ctx.solicitud_id] = Estado.EJECUTADA
        self._audit.anexar(actor="servicio_pagos", evento="EJECUTADA_SIN_PEP", solicitud_id=ctx.solicitud_id,
                           estado=Estado.EJECUTADA.value,
                           payload={"pago_id": pago["pago_id"], "monto_cop": p.monto_cop, "cuenta": p.cuenta_destino,
                                    "saldo_resultante": pago["saldo_resultante"]})
        return VeredictoPEP(decision="EJECUTADA", estado=Estado.EJECUTADA,
                            regla_principal="PEP DESACTIVADO · confianza implícita: el agente ejecutó directamente",
                            pep_activo=False, hash_transaccion=h)


def herramienta_financiera(gateway: ToolGateway, ctx: ContextoPEP, pep_activo: bool,
                           destino: list) -> StructuredTool:
    """Herramienta del Agente Financiero, ligada al contexto de la solicitud en curso."""
    def solicitar_ejecucion_pago(**kwargs) -> dict:
        res = gateway.invocar("agente:financiero", "solicitar_ejecucion_pago", kwargs, ctx, pep_activo=pep_activo)
        destino.append(res)
        # Al agente solo vuelve el resultado; no puede reintentar ni ver detalles de firma.
        return {"decision": res.veredicto.decision, "estado": res.veredicto.estado.value}

    return StructuredTool.from_function(
        solicitar_ejecucion_pago, name="solicitar_ejecucion_pago", args_schema=PropuestaPagoSchema,
        description=("Entrega una propuesta de pago al PEP. NO ejecuta el pago: el PEP decide la ruta y una persona "
                     "debe confirmar y firmar."))
