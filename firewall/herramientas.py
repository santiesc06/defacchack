"""Herramientas LangChain con contratos Pydantic + ToolGateway.

- Herramientas de solo lectura del Orquestador (pack de pagos: maestro, OC e historial).
- Herramienta crítica del Agente Ejecutor del pack activo (pagos: `solicitar_ejecucion_pago`; DevOps:
  `solicitar_cambio_infraestructura`), declarada en su ToolManifest. Su implementación NO paga: entrega
  la invocación al `ToolGateway`, que (1) la somete al control del modo activo (PEP en COMPLETO y
  SOLO_PEP) y (2) pide al Agente Explicador que se la explique a la persona y le pida confirmación.
  No existe ninguna herramienta de aprobación o firma expuesta a los agentes (Matriz 2).
- Los modos SOLO_SANITIZER, SOLO_LLM y SIN_DEFENSA existen para COMPARAR (evaluacion_empirica.py):
  en ellos, si el control no bloquea, el pago se ejecuta sin firmas humanas.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Callable

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .config import MODOS_CON_PEP, Modo, etiqueta_rol
from .llm import ErrorModelo
from .packs.base import EjecucionRechazada
from .pep import ContextoPEP, PolicyEnforcementPoint
from .repositorio import VistaSoloLectura
from .schemas import (PATRON_FACTURA, PATRON_OC, Estado, ExplicacionSchema, ProveedorInfo, ResultadoDuplicado,
                      ResultadoOC, VeredictoPEP)


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
    """Control determinista (pack de pagos): la explicación del LLM debe citar el monto y la cuenta exactos."""
    texto = _solo_digitos(f"{exp.resumen} {exp.pregunta_confirmacion}")
    return str(monto) in texto and _solo_digitos(cuenta) in texto


class ToolGateway:
    """Interceptor de TODAS las herramientas del Agente Ejecutor, para cualquier Policy Pack."""

    def __init__(self, pep: PolicyEnforcementPoint, audit, explicar: Callable[[dict], tuple[ExplicacionSchema, str]],
                 verificador=None) -> None:
        self._pep = pep
        self.pack = pep.pack
        self._audit = audit
        self._explicar = explicar
        self._verificador = verificador

    def invocar(self, agente: str, herramienta: str, args: dict, ctx: ContextoPEP, *, modo: Modo) -> ResultadoGateway:
        self._audit.anexar(actor=agente, evento="INVOCACION_HERRAMIENTA", solicitud_id=ctx.solicitud_id,
                           payload={"herramienta": herramienta, "argumentos": args, "modo": modo.value,
                                    "dominio": self.pack.id})
        if modo in MODOS_CON_PEP:
            v = self._pep.evaluar(agente, herramienta, args, ctx)
        elif modo is Modo.SOLO_SANITIZER:
            v = self._solo_sanitizer(args, ctx, agente)
        elif modo is Modo.SOLO_LLM:
            v = self._solo_llm(args, ctx, agente)
        else:
            v = self._ejecutar_sin_control(args, ctx, "SIN DEFENSA · confianza implícita: el agente ejecutó directamente",
                                           "NINGUNO", agente)

        reg = self._pep.registros.get(ctx.solicitud_id) if modo in MODOS_CON_PEP else None
        dv = self.pack.datos_verificados(reg, args)
        if dv.get("hash_transaccion") is None:
            dv["hash_transaccion"] = v.hash_transaccion
        datos = {
            "dominio": self.pack.id,
            "propuesta": self.pack.propuesta_para_explicador(args, dv),
            "veredicto": v.model_dump(mode="json"),
            # Sin `evidencias`: citan texto del atacante y el Explicador no debe ver texto del correo/issue.
            "metadata": ctx.metadata.model_dump(mode="json", exclude={"evidencias"}),
            "etiquetas_firmantes": [etiqueta_rol(r) for r in v.firmas_requeridas],
        }
        if modo in MODOS_CON_PEP:
            try:
                exp, origen = self._explicar(datos)
            except ErrorModelo as e:  # la decisión del PEP no depende del Explicador: se avisa y se sigue
                exp = ExplicacionSchema(
                    titulo="Explicación no disponible (fallo del modelo)",
                    resumen=f"El modelo no generó la explicación ({str(e)[:200]}). Revise los datos verificados por el PEP.",
                    recomendacion="REVISAR_CON_CUIDADO",
                    pregunta_confirmacion="Decida solo con los datos verificados de abajo.")
                origen = "fallo del modelo"
        else:  # sin supervisión humana no hay a quién pedir confirmación: resumen informativo por plantilla
            exp, origen = self.pack.explicar_local(datos), "plantilla (modo sin supervisión humana)"
        coherente = self.pack.explicacion_coherente(exp, dv)
        self._audit.anexar(actor="agente:explicador", evento="EXPLICACION_A_HUMANO", solicitud_id=ctx.solicitud_id,
                           estado=v.estado.value,
                           payload={"titulo": exp.titulo, "recomendacion": exp.recomendacion, "coherente": coherente,
                                    "origen": origen})
        return ResultadoGateway(v, exp, coherente, origen, dv)

    # ---- modos de comparación ---------------------------------------------------------------
    def _registrar_decision(self, ctx: ContextoPEP, v: VeredictoPEP, evento: str, extra: dict | None = None) -> None:
        self._pep.estados_finales[ctx.solicitud_id] = v.estado
        self._audit.anexar(actor=f"control:{v.control.lower()}", evento=evento, solicitud_id=ctx.solicitud_id,
                           estado=v.estado.value,
                           payload={"decision": v.decision, "regla_principal": v.regla_principal, **(extra or {})})

    def _solo_sanitizer(self, args: dict, ctx: ContextoPEP, agente: str) -> VeredictoPEP:
        t0 = time.perf_counter()
        md = ctx.metadata
        if md.nivel_riesgo == "ALTO":
            v = VeredictoPEP(decision="BLOQUEADA", estado=Estado.BLOQUEADA, pep_activo=False, control="SANITIZER",
                             regla_principal="Sanitizer: riesgo ALTO (" + ", ".join(md.banderas_anomalia[:4]) + ")",
                             alerta_seguridad=True, latencia_ms=round((time.perf_counter() - t0) * 1000, 3))
            self._registrar_decision(ctx, v, "DECISION_SANITIZER")
            return v
        return self._ejecutar_sin_control(
            args, ctx, f"SOLO SANITIZER · riesgo {md.nivel_riesgo}: no bloqueó y la acción se ejecutó sin más controles",
            "SANITIZER", agente, t0)

    def _solo_llm(self, args: dict, ctx: ContextoPEP, agente: str) -> VeredictoPEP:
        t0 = time.perf_counter()
        try:
            res, origen = self._verificador(ctx.correo, args, self.pack.datos_internos(args))
        except Exception as e:  # falla cerrada: si el único control no responde, no se ejecuta
            v = VeredictoPEP(decision="BLOQUEADA", estado=Estado.BLOQUEADA, pep_activo=False, control="LLM",
                             regla_principal=f"Verificador LLM no disponible ({type(e).__name__}): falla cerrada",
                             latencia_ms=round((time.perf_counter() - t0) * 1000, 3))
            self._registrar_decision(ctx, v, "DECISION_VERIFICADOR_LLM", {"error": str(e)[:200]})
            return v
        if res.decision == "BLOQUEAR":
            v = VeredictoPEP(decision="BLOQUEADA", estado=Estado.BLOQUEADA, pep_activo=False, control="LLM",
                             regla_principal=f"Verificador LLM ({res.nivel_riesgo}): {res.motivo}"[:400],
                             alerta_seguridad=True, latencia_ms=round((time.perf_counter() - t0) * 1000, 3))
            self._registrar_decision(ctx, v, "DECISION_VERIFICADOR_LLM", {"origen": origen})
            return v
        return self._ejecutar_sin_control(
            args, ctx, f"SOLO LLM · el verificador aprobó ({res.nivel_riesgo}): {res.motivo}"[:400], "LLM", agente, t0)

    def _ejecutar_sin_control(self, args: dict, ctx: ContextoPEP, regla: str, control: str, agente: str,
                              t0: float | None = None) -> VeredictoPEP:
        """Ejecución directa, sin PEP ni firmas (solo en modos de comparación)."""
        t0 = t0 if t0 is not None else time.perf_counter()

        def lat() -> float:
            return round((time.perf_counter() - t0) * 1000, 3)

        try:
            resultado, h = self.pack.ejecutar_directo(args, actor=agente)
        except ValidationError:
            v = VeredictoPEP(decision="RECHAZADA", estado=Estado.RECHAZADA, pep_activo=False, control=control,
                             regla_principal="Servicio de ejecución: argumentos ilegibles", latencia_ms=lat())
            self._registrar_decision(ctx, v, "EJECUCION_RECHAZADA")
            return v
        except EjecucionRechazada as e:
            v = VeredictoPEP(decision="RECHAZADA", estado=Estado.RECHAZADA, regla_principal=f"Servicio de ejecución: {e}",
                             pep_activo=False, control=control, latencia_ms=lat())
            self._registrar_decision(ctx, v, "EJECUCION_RECHAZADA")
            return v
        v = VeredictoPEP(decision="EJECUTADA", estado=Estado.EJECUTADA, regla_principal=regla, pep_activo=False,
                         control=control, hash_transaccion=h, latencia_ms=lat())
        self._registrar_decision(ctx, v, "EJECUTADA_SIN_PEP", self.pack.payload_ejecucion(None, resultado))
        return v


def herramienta_financiera(gateway: ToolGateway, ctx: ContextoPEP, modo: Modo, destino: list) -> StructuredTool:
    """Herramienta crítica del pack activo, ligada al contexto de la solicitud en curso.
    (Nombre histórico: en el pack de pagos es `solicitar_ejecucion_pago`.)"""
    pack = gateway.pack
    manifiesto = pack.manifiestos[pack.herramienta_ejecutora]

    def herramienta_critica(**kwargs) -> dict:
        res = gateway.invocar(pack.agente_ejecutor, manifiesto.nombre, kwargs, ctx, modo=modo)
        destino.append(res)
        # Al agente solo vuelve el resultado; no puede reintentar ni ver detalles de firma.
        return {"decision": res.veredicto.decision, "estado": res.veredicto.estado.value}

    return StructuredTool.from_function(herramienta_critica, name=manifiesto.nombre, args_schema=manifiesto.esquema_args,
                                        description=manifiesto.descripcion)


herramienta_ejecutora = herramienta_financiera
