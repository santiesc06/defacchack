"""Agentes del grafo, agnósticos al dominio. Cada uno tiene identidad propia y solo las capacidades de
la Matriz 1 del Policy Pack activo; el pack aporta esquemas, prompts, datos y herramientas.

| Agente                     | Recibe                                  | Produce                          | Herramientas              |
|----------------------------|-----------------------------------------|----------------------------------|---------------------------|
| Recepcionista (Ingesta)    | entrada externa (no confiable)          | esquema cerrado del pack         | ninguna                   |
| Orquestador                | extracción + etiquetas (estructurado)   | relevancia + validación          | solo lectura del pack     |
| Ejecutor (ex Financiero)   | extracción + validación                 | argumentos de la herramienta     | herramienta crítica       |
| Explicador                 | propuesta + veredicto + etiquetas       | ExplicacionSchema                | ninguna                   |
| Verificador (SOLO_LLM)     | entrada + propuesta + datos internos    | VeredictoVerificadorLLM          | ninguna                   |
"""
from __future__ import annotations

import json

from .llm import ProveedorLLM, delimitar_no_confiable
from .schemas import CorreoEntrada, ExplicacionSchema


class RecepcionistaAgent:
    """Ingesta/Extractor: convierte cualquier entrada (correo, issue, ticket) al esquema cerrado del pack."""
    identidad = "agente:recepcionista"

    def __init__(self, llm: ProveedorLLM, pack) -> None:
        self._llm = llm
        self._pack = pack

    def extraer_solicitud_cerrada(self, correo: CorreoEntrada):
        return self._pack.extraer_solicitud(correo, self._llm)


IngestaEstructuradaAgent = RecepcionistaAgent


class OrquestadorAgent:
    """Filtra tareas no accionables (Ejecutor AISLADO) y valida en solo lectura contra los datos del pack."""
    identidad = "agente:orquestador"

    def __init__(self, llm: ProveedorLLM, pack) -> None:
        self._llm = llm
        self._pack = pack

    def filtrar_relevancia(self, ext, asunto: str):
        return self._pack.relevancia(ext, asunto, self._llm)  # recibe el esquema cerrado, NO el texto crudo

    def validar_negocio(self, ext, md):
        return self._pack.validar_reglas_negocio(ext, md)


class AgenteEjecutor:
    """Generalización del Agente Financiero: invoca la herramienta crítica del pack vía ToolGateway."""

    def __init__(self, llm: ProveedorLLM, pack) -> None:
        self._llm = llm
        self._pack = pack
        self.identidad = pack.agente_ejecutor

    def proponer(self, solicitud_id: str, ext, val, herramienta) -> tuple[dict, str]:
        return self._pack.preparar_propuesta(solicitud_id, ext, val, herramienta, self._llm)


AgenteFinanciero = AgenteEjecutor


class ExplicadorAgent:
    identidad = "agente:explicador"

    def __init__(self, llm: ProveedorLLM, pack) -> None:
        self._llm = llm
        self._pack = pack

    def explicar(self, datos: dict) -> tuple[ExplicacionSchema, str]:
        contenido = json.dumps(datos, ensure_ascii=False, default=str)  # solo datos estructurados
        return self._llm.estructurar(self._pack.prompts["explicador"], contenido, ExplicacionSchema,
                                     lambda: self._pack.explicar_local(datos))


class VerificadorLLMAgent:
    """Línea base del modo SOLO_LLM: un único modelo decide APROBAR/BLOQUEAR.

    Recibe la MISMA información que usa el PEP (entrada, autenticación de origen, propuesta y datos
    internos del pack), para que la comparación aísle una sola variable: decisión probabilística (LLM)
    frente a decisión determinista (código). No tiene simulador local: sin modelo real no aplica.
    """
    identidad = "agente:verificador"

    def __init__(self, llm: ProveedorLLM, pack) -> None:
        self._llm = llm
        self._pack = pack

    def verificar(self, correo: CorreoEntrada, propuesta: dict, datos_internos: dict):
        from .schemas import VeredictoVerificadorLLM
        contenido = (
            delimitar_no_confiable(
                f"Origen: {correo.canal} · {correo.nombre_remitente} <{correo.remitente}>\nAsunto: {correo.asunto}\n\n"
                f"{correo.cuerpo}\n\n[Adjunto {correo.adjunto_nombre or '-'}]\n{correo.adjunto_texto or ''}")
            + f"\n\nAUTENTICACIÓN DEL ORIGEN: SPF={correo.spf} DKIM={correo.dkim} DMARC={correo.dmarc}"
            + "\n\nPROPUESTA:\n" + json.dumps(propuesta, ensure_ascii=False, default=str)
            + "\n\nFUENTES INTERNAS CONFIABLES:\n" + json.dumps(datos_internos, ensure_ascii=False, default=str))
        return self._llm.estructurar(self._pack.prompts["verificador"], contenido, VeredictoVerificadorLLM, None)
