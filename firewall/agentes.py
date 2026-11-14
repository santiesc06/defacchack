"""Agentes del grafo. Cada uno tiene identidad propia y solo las capacidades de la Matriz 1.

| Agente        | Recibe                               | Produce                     | Herramientas            |
|---------------|--------------------------------------|-----------------------------|-------------------------|
| Recepcionista | texto del correo (no confiable)      | SolicitudExtraccionSchema   | ninguna                 |
| Orquestador   | extracción + etiquetas (estructurado)| relevancia + validación     | 3 de solo lectura       |
| Financiero    | extracción + validación              | PropuestaPagoSchema         | solicitar_ejecucion_pago|
| Explicador    | propuesta + veredicto + etiquetas    | ExplicacionSchema           | ninguna                 |
"""
from __future__ import annotations

import json

from .llm import ProveedorLLM, delimitar_no_confiable, llm_local
from .schemas import (CorreoEntrada, DecisionRelevancia, ExplicacionSchema, MetadataSeguridadSchema,
                      SolicitudExtraccionSchema, ValidacionNegocioSchema)
from .repositorio import normalizar_cuenta


class RecepcionistaAgent:
    identidad = "agente:recepcionista"

    def __init__(self, llm: ProveedorLLM) -> None:
        self._llm = llm

    def extraer_solicitud_cerrada(self, correo: CorreoEntrada) -> tuple[SolicitudExtraccionSchema, str]:
        contenido = delimitar_no_confiable(
            f"De: {correo.nombre_remitente} <{correo.remitente}>\nAsunto: {correo.asunto}\n\n{correo.cuerpo}\n\n"
            f"[Adjunto {correo.adjunto_nombre or '-'}]\n{correo.adjunto_texto or ''}")
        return self._llm.estructurar("recepcionista", contenido, SolicitudExtraccionSchema,
                                     lambda: llm_local.extraer_solicitud(correo))


class OrquestadorAgent:
    identidad = "agente:orquestador"

    def __init__(self, llm: ProveedorLLM, herramientas: dict) -> None:
        self._llm = llm
        self._tools = herramientas  # solo lectura

    def filtrar_relevancia(self, ext: SolicitudExtraccionSchema, asunto: str) -> tuple[DecisionRelevancia, str]:
        # Recibe el esquema cerrado, NO el correo.
        contenido = json.dumps({"solicitud": ext.model_dump(), "asunto_truncado": asunto[:120]}, ensure_ascii=False)
        dec, origen = self._llm.estructurar("orquestador", contenido, DecisionRelevancia,
                                            lambda: llm_local.decidir_relevancia(ext, asunto))
        if not ext.es_solicitud_pago and dec.requiere_accion_financiera and not ext.monto_cop:
            # Sin monto no hay operación financiera posible: se fuerza el cierre (mínimo privilegio).
            dec = DecisionRelevancia(requiere_accion_financiera=False, categoria="INFORMATIVA",
                                     justificacion="Sin monto ni datos de pago: no requiere al Agente Financiero.")
        return dec, origen

    def validar_negocio(self, ext: SolicitudExtraccionSchema, md: MetadataSeguridadSchema) -> tuple[ValidacionNegocioSchema, list]:
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


class AgenteFinanciero:
    identidad = "agente:financiero"

    def __init__(self, llm: ProveedorLLM) -> None:
        self._llm = llm

    def proponer(self, solicitud_id: str, ext: SolicitudExtraccionSchema, val: ValidacionNegocioSchema,
                 herramienta) -> tuple[dict, str]:
        """Prepara `PropuestaPagoSchema` y decide la llamada a `solicitar_ejecucion_pago`.
        Devuelve (argumentos de la llamada, origen LLM). La ejecución la hace el nodo de herramientas."""
        def local() -> dict:
            return {k: v for k, v in {
                "solicitud_id": solicitud_id, "proveedor_id": val.proveedor_id,
                "beneficiario": ext.beneficiario or val.razon_social or "Desconocido",
                "cuenta_destino": ext.cuenta_destino or "00000", "monto_cop": ext.monto_cop or 1,
                "concepto": (ext.concepto or "Pago")[:160], "numero_factura": ext.numero_factura,
                "numero_oc": ext.numero_oc}.items() if v is not None}

        contexto = {"solicitud_id": solicitud_id, "solicitud": ext.model_dump(), "validacion": val.model_dump()}
        return self._llm.llamar_herramienta("financiero", contexto, herramienta, local)


class ExplicadorAgent:
    identidad = "agente:explicador"

    def __init__(self, llm: ProveedorLLM) -> None:
        self._llm = llm

    def explicar(self, datos: dict) -> tuple[ExplicacionSchema, str]:
        contenido = json.dumps(datos, ensure_ascii=False, default=str)  # solo datos estructurados
        return self._llm.estructurar("explicador", contenido, ExplicacionSchema, lambda: llm_local.explicar(datos))
