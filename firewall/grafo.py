"""Grafo LangGraph del flujo (Procedimiento de aprobación, pasos 1–4).

    START → recepcionista → sanitizer → orquestador ─┬─(no financiera)→ END   [Agente Financiero AISLADO]
                                                    └─(pago)→ financiero → herramientas_pep → END

`herramientas_pep` cumple el papel del ToolNode de LangGraph, pero cada llamada pasa por el
ToolGateway: PEP determinista (Capa 1) + Explicador LLM que pide confirmación humana (Capa 2).
Las firmas (pasos 5–9) ocurren fuera del grafo, por el canal humano autenticado (API/UI).
"""
from __future__ import annotations

import operator
import time
from dataclasses import dataclass
from typing import Annotated, Any, TypedDict

from langgraph.graph import END, START, StateGraph
from pydantic import ValidationError

from .agentes import AgenteFinanciero, OrquestadorAgent, RecepcionistaAgent
from .audit import AuditLogSHA256
from .herramientas import ResultadoGateway, ToolGateway, herramienta_financiera
from .pep import ContextoPEP
from .sanitizer import ContextSanitizer, sellar
from .schemas import (CorreoEntrada, DecisionRelevancia, Estado, MetadataSeguridadSchema, SolicitudExtraccionSchema,
                      ValidacionNegocioSchema)


class EstadoGrafo(TypedDict, total=False):
    solicitud_id: str
    pep_activo: bool
    sanitizer_activo: bool
    correo: CorreoEntrada
    extraccion: SolicitudExtraccionSchema
    metadata: MetadataSeguridadSchema
    sello_metadata: str
    relevancia: DecisionRelevancia
    validacion: ValidacionNegocioSchema
    llamada_herramienta: dict
    resultado: ResultadoGateway
    financiero_invocado: bool
    estado: str
    traza: Annotated[list[dict], operator.add]


@dataclass
class Dependencias:
    recepcionista: RecepcionistaAgent
    sanitizer: ContextSanitizer
    orquestador: OrquestadorAgent
    financiero: AgenteFinanciero
    gateway: ToolGateway
    audit: AuditLogSHA256


def _paso(paso: str, agente: str, estado: str, titulo: str, datos: dict[str, Any], t0: float,
          origen: str | None = None) -> dict:
    return {"paso": paso, "agente": agente, "estado": estado, "titulo": titulo, "datos": datos,
            "origen_llm": origen, "ms": round((time.perf_counter() - t0) * 1000, 2)}


def construir_grafo(d: Dependencias):
    def recepcionista(s: EstadoGrafo) -> dict:
        t0 = time.perf_counter()
        c = s["correo"]
        d.audit.anexar(actor="canal:correo", evento="RECIBIDA", solicitud_id=s["solicitud_id"],
                       estado=Estado.RECIBIDA.value,
                       payload={"remitente": c.remitente, "asunto": c.asunto[:120], "canal": c.canal})
        ext, origen = d.recepcionista.extraer_solicitud_cerrada(c)
        d.audit.anexar(actor=d.recepcionista.identidad, evento="EXTRACCION_ESQUEMA_CERRADO",
                       solicitud_id=s["solicitud_id"], estado=Estado.RECIBIDA.value, payload=ext.model_dump())
        return {"extraccion": ext, "estado": Estado.RECIBIDA.value,
                "traza": [_paso("recepcionista", d.recepcionista.identidad, Estado.RECIBIDA.value,
                                "Extracción a esquema cerrado", ext.model_dump(), t0, origen)]}

    def sanitizer(s: EstadoGrafo) -> dict:
        t0 = time.perf_counter()
        md, origen = d.sanitizer.etiquetar(s["correo"], activo=s.get("sanitizer_activo", True))
        sello = sellar(md)
        d.audit.anexar(actor="agente:sanitizer", evento="ETIQUETADA", solicitud_id=s["solicitud_id"],
                       estado=Estado.ETIQUETADA.value, payload={**md.model_dump(mode="json"), "sello_sha256": sello})
        return {"metadata": md, "sello_metadata": sello, "estado": Estado.ETIQUETADA.value,
                "traza": [_paso("sanitizer", "agente:sanitizer", Estado.ETIQUETADA.value,
                                "Etiquetas inmutables de procedencia y riesgo",
                                {**md.model_dump(mode="json"), "sello_sha256": sello}, t0, origen)]}

    def orquestador(s: EstadoGrafo) -> dict:
        t0 = time.perf_counter()
        ext, md = s["extraccion"], s["metadata"]
        rel, origen = d.orquestador.filtrar_relevancia(ext, s["correo"].asunto)
        if not rel.requiere_accion_financiera:
            d.audit.anexar(actor=d.orquestador.identidad, evento="CERRADA_NO_FINANCIERA",
                           solicitud_id=s["solicitud_id"], estado=Estado.CERRADA_NO_FINANCIERA.value,
                           payload={**rel.model_dump(), "agente_financiero": "AISLADO"})
            return {"relevancia": rel, "financiero_invocado": False, "estado": Estado.CERRADA_NO_FINANCIERA.value,
                    "traza": [_paso("orquestador", d.orquestador.identidad, Estado.CERRADA_NO_FINANCIERA.value,
                                    "Filtro de relevancia: tarea no financiera",
                                    {"relevancia": rel.model_dump(), "herramientas_usadas": [],
                                     "agente_financiero": "AISLADO / EN REPOSO"}, t0, origen)]}
        val, llamadas = d.orquestador.validar_negocio(ext, md)
        estado = Estado.VALIDADA if val.recomendacion == "PROPONER_PAGO" else Estado.RECHAZADA
        d.audit.anexar(actor=d.orquestador.identidad, evento=estado.value, solicitud_id=s["solicitud_id"],
                       estado=estado.value, payload=val.model_dump())
        return {"relevancia": rel, "validacion": val, "estado": estado.value,
                "traza": [_paso("orquestador", d.orquestador.identidad, estado.value,
                                "Relevancia + validación de negocio (solo lectura)",
                                {"relevancia": rel.model_dump(), "validacion": val.model_dump(),
                                 "herramientas_usadas": llamadas}, t0, origen)]}

    def _ctx(s: EstadoGrafo) -> ContextoPEP:
        return ContextoPEP(solicitud_id=s["solicitud_id"], metadata=s["metadata"], sello_registrado=s["sello_metadata"],
                           iniciado_por=s["correo"].iniciado_por if s["metadata"].origen == "INTERNO_VERIFICADO" else None)

    def financiero(s: EstadoGrafo) -> dict:
        t0 = time.perf_counter()
        herramienta = herramienta_financiera(d.gateway, _ctx(s), s.get("pep_activo", True), [])
        args, origen = d.financiero.proponer(s["solicitud_id"], s["extraccion"], s["validacion"], herramienta)
        llamada = {"herramienta": herramienta.name, "argumentos": args}
        return {"llamada_herramienta": llamada, "financiero_invocado": True,
                "traza": [_paso("financiero", d.financiero.identidad, s["estado"],
                                "Intención de herramienta: solicitar_ejecucion_pago", llamada, t0, origen)]}

    def herramientas_pep(s: EstadoGrafo) -> dict:
        t0 = time.perf_counter()
        resultados: list[ResultadoGateway] = []
        ctx = _ctx(s)
        herramienta = herramienta_financiera(d.gateway, ctx, s.get("pep_activo", True), resultados)
        args = s["llamada_herramienta"]["argumentos"]
        try:
            herramienta.invoke(args)
        except ValidationError:
            # Fuera del esquema cerrado: igual se entrega al gateway para bloqueo R0 y registro.
            resultados.append(d.gateway.invocar("agente:financiero", herramienta.name, args, ctx,
                                                pep_activo=s.get("pep_activo", True)))
        r = resultados[-1]
        v = r.veredicto
        return {"resultado": r, "estado": v.estado.value,
                "traza": [
                    _paso("pep", "pep (código determinista)", v.estado.value, "Veredicto de la aduana PEP",
                          v.model_dump(mode="json"), t0, None),
                    _paso("explicador", "agente:explicador", v.estado.value, "Explicación y solicitud de confirmación",
                          {**r.explicacion.model_dump(), "coherente": r.explicacion_coherente,
                           "datos_verificados": r.datos_verificados}, t0, r.origen_explicador),
                ]}

    def ruta(s: EstadoGrafo) -> str:
        return "financiero" if s["relevancia"].requiere_accion_financiera else END

    g = StateGraph(EstadoGrafo)
    g.add_node("recepcionista", recepcionista)
    g.add_node("sanitizer", sanitizer)
    g.add_node("orquestador", orquestador)
    g.add_node("financiero", financiero)
    g.add_node("herramientas_pep", herramientas_pep)
    g.add_edge(START, "recepcionista")
    g.add_edge("recepcionista", "sanitizer")
    g.add_edge("sanitizer", "orquestador")
    g.add_conditional_edges("orquestador", ruta, {"financiero": "financiero", END: END})
    g.add_edge("financiero", "herramientas_pep")
    g.add_edge("herramientas_pep", END)
    return g.compile()
