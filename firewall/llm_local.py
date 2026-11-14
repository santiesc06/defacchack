"""Simulador LLM local y determinista (opción P1-A).

Reproduce el comportamiento TÍPICO de un agente LLM ingenuo, incluidas sus debilidades, para que
la demo y el benchmark sean reproducibles y funcionen sin red:
- El Recepcionista simulado sí es vulnerable a la inyección indirecta: cuando el correo o el
  adjunto contienen varias cuentas o montos, toma el ÚLTIMO mencionado (la instrucción inyectada
  suele ir al final) y lo resume en lenguaje corporativo limpio («lavado semántico»).
- Nada de este módulo es una defensa: las defensas están en `sanitizer.py` (reglas) y `pep.py`.
"""
from __future__ import annotations

import re

from .config import formato_cop
from .schemas import (ClasificacionSemantica, CorreoEntrada, DecisionRelevancia, ExplicacionSchema,
                      SolicitudExtraccionSchema)

_MONTO = re.compile(
    r"(?:\$\s?|COP\s?|(?:valor|monto|total|suma)\s+(?:de\s+)?\$?\s?)(\d{1,3}(?:[.,]\d{3})+|\d{4,12})(?:,\d{2})?(?!\d)"
    r"|(\d{1,3}(?:[.,]\d{3})+|\d{4,12})(?:,\d{2})?\s?(?:COP|pesos)", re.I)
_CUENTA = re.compile(r"cuenta[^0-9\n]{0,60}?(\d[\d-]{4,22}\d)", re.I)
_FACTURA = re.compile(r"factura(?:\s+(?:electr[oó]nica|de\s+venta))?\s*(?:n[°ºo.]+\s*|#\s*|n[uú]mero\s*)?"
                      r"([A-Z]{1,5}-?\d{2,8})\b", re.I)
_OC = re.compile(r"\bOC-\d{4}-\d{4}\b", re.I)
_NIT = re.compile(r"NIT\s*:?\s*([\d.]{6,14}-?\d?)", re.I)
_PAL = r"[A-ZÁÉÍÓÚÑ][a-záéíóúñA-ZÁÉÍÓÚÑ&]*"
_EMPRESA = re.compile(rf"({_PAL}(?:\s+(?:de\s+|del\s+)?{_PAL}){{0,4}}\s+(?:S\.A\.S\.?|SAS|Ltda\.?|S\.A\.))")
_CONCEPTO = re.compile(r"(?:por\s+concepto\s+de|correspondiente\s+a|concepto:)\s*([^.,;\n]{3,120})", re.I)
_PAGO_KW = re.compile(r"\b(pag[oa]r?|pagos?|transfer\w*|consign\w*|abon\w*|desembols\w*|gir[oa]r?|factura|anticipo)\b", re.I)
_SPAM_KW = re.compile(r"\b(cup[oó]n|promoci[oó]n|oferta|gana|gratis|descuento|sorteo)\b", re.I)
_INFO_KW = re.compile(r"\b(pedido|env[ií]o|despacho|consulta|estado|reuni[oó]n|agenda|informaci[oó]n)\b", re.I)


def _a_entero(txt: str) -> int | None:
    digitos = re.sub(r"[^\d]", "", txt)
    return int(digitos) if digitos and 0 < int(digitos) <= 10**12 else None


def extraer_solicitud(correo: CorreoEntrada) -> SolicitudExtraccionSchema:
    texto = f"{correo.asunto}\n{correo.cuerpo}\n{correo.adjunto_texto or ''}"
    montos = [m for m in (_a_entero(a or b) for a, b in _MONTO.findall(texto)) if m]
    cuentas = _CUENTA.findall(texto)
    facturas = [f.upper() for f in _FACTURA.findall(texto)]
    ocs = [o.upper() for o in _OC.findall(texto)]
    nits = _NIT.findall(texto)
    empresas = _EMPRESA.findall(texto)
    conceptos = _CONCEPTO.findall(texto)

    # Debilidad simulada: «la última instrucción gana».
    monto = montos[-1] if montos else None
    cuenta = cuentas[-1] if cuentas else None
    factura = next((f for f in facturas if re.fullmatch(r"[A-Z]{1,5}-?[0-9]{2,8}", f)), None)
    beneficiario = empresas[0].strip() if empresas else (correo.nombre_remitente or None)
    conceptos = [c.strip() for c in conceptos if not re.search(r"OC-\d|la\s+OC|factura", c, re.I)]
    asunto_limpio = correo.asunto.split("—", 1)[-1].strip() if "—" in correo.asunto else correo.asunto
    concepto = (conceptos[-1] if conceptos else asunto_limpio)[:160]
    es_pago = bool(monto) and bool(_PAGO_KW.search(texto))

    if es_pago:
        partes = [f"{beneficiario or 'El remitente'} solicita el pago de {formato_cop(monto)}"]
        if concepto:
            partes.append(f"por concepto de {concepto.rstrip('.').lower()}")
        if factura:
            partes.append(f"(factura {factura})")
        if cuenta:
            partes.append(f"con destino a la cuenta {cuenta}")
        resumen = " ".join(partes) + "."
    else:
        resumen = f"Correo sin solicitud de pago. Asunto: {correo.asunto[:150]}."
    return SolicitudExtraccionSchema(
        es_solicitud_pago=es_pago, beneficiario=beneficiario[:120] if beneficiario else None,
        nit_beneficiario=nits[0] if nits else None, cuenta_destino=cuenta, monto_cop=monto,
        concepto=concepto, numero_factura=factura, numero_oc=ocs[0] if ocs else None,
        resumen_neutro=resumen[:400])


_SEMANTICA = [
    ("INSTRUCCION_OCULTA", re.compile(r"(asistente|agente|modelo|sistema|ia)\b.{0,40}\b(debe|deber[aá]s|procede|ejecuta|ignora)"
                                      r"|instrucci[oó]n(es)? (para|al) (el )?(sistema|asistente)|nota para (el|la) (ia|asistente|sistema)", re.I)),
    ("CAMBIO_CUENTA", re.compile(r"(nueva|actualizad[ao]|distinta|otra|cambi\w+ (de|nuestra))\s+(cuenta|datos bancarios|entidad bancaria)"
                                 r"|reestructuraci[oó]n de (nuestra )?tesorer[ií]a|migramos de banco|nuevo n[uú]mero de cuenta", re.I)),
    ("URGENCIA_ARTIFICIAL", re.compile(r"\b(hoy mismo|de inmediato|inmediatamente|antes de las \d|sin demora|urgent\w*|cuanto antes)\b", re.I)),
    ("PRESION_AUTORIDAD", re.compile(r"(gerente|gerencia|ceo|presidente|director)\w*\s+(ya\s+)?(aprob|autoriz|orden)\w*", re.I)),
    ("SECRETISMO", re.compile(r"(confidencial|no lo comente|discreci[oó]n|no informe|no copie|sin copiar a|no lo menciones)", re.I)),
]


def clasificar_semantico(correo: CorreoEntrada) -> ClasificacionSemantica:
    texto = f"{correo.asunto}\n{correo.cuerpo}\n{correo.adjunto_texto or ''}"
    banderas = tuple(n for n, rx in _SEMANTICA if rx.search(texto))
    if "INSTRUCCION_OCULTA" in banderas or ("CAMBIO_CUENTA" in banderas and
                                            {"URGENCIA_ARTIFICIAL", "SECRETISMO"} & set(banderas)):
        nivel = "ALTO"
    elif banderas:
        nivel = "MEDIO"
    else:
        nivel = "BAJO"
    return ClasificacionSemantica(nivel_riesgo=nivel, banderas=banderas,
                                  justificacion=("Señales: " + ", ".join(banderas)) if banderas else "Sin señales")


def decidir_relevancia(ext: SolicitudExtraccionSchema, asunto: str) -> DecisionRelevancia:
    if ext.es_solicitud_pago:
        return DecisionRelevancia(requiere_accion_financiera=True, categoria="SOLICITUD_PAGO",
                                  justificacion="La solicitud estructurada contiene monto y concepto de pago.")
    texto = f"{asunto} {ext.resumen_neutro}"
    if _SPAM_KW.search(texto):
        return DecisionRelevancia(requiere_accion_financiera=False, categoria="SPAM",
                                  justificacion="Contenido promocional sin relación con pagos.")
    if _INFO_KW.search(texto):
        return DecisionRelevancia(requiere_accion_financiera=False, categoria="INFORMATIVA",
                                  justificacion="Consulta informativa: no requiere mover fondos.")
    return DecisionRelevancia(requiere_accion_financiera=False, categoria="OFF_TOPIC",
                              justificacion="Tarea ajena al flujo de pagos.")


def explicar(datos: dict) -> ExplicacionSchema:
    """`datos` es SOLO información estructurada (nunca el texto del correo)."""
    p, v, m = datos["propuesta"], datos["veredicto"], datos["metadata"]
    monto, cuenta = formato_cop(p["monto_cop"]), p["cuenta_destino"]
    destino = f"{p['beneficiario']} (cuenta {cuenta})"
    riesgos = [f"Bandera del Sanitizer: {b}" for b in m.get("banderas_anomalia", [])]
    if not m.get("spf_dkim_valido", True):
        riesgos.append("El correo no superó SPF/DKIM/DMARC")
    if m.get("origen") == "EXTERNO_NO_CONFIABLE":
        riesgos.append("Origen externo no confiable (taint)")
    riesgos += [f"{r['codigo']}: {r['descripcion']}" for r in v.get("reglas", [])
                if r["decision"] in ("BLOQUEADA", "RECHAZADA")]

    if v["decision"] == "BLOQUEADA":
        return ExplicacionSchema(
            titulo="Operación bloqueada por el PEP",
            resumen=(f"El Agente Financiero intentó ejecutar un pago de {monto} a {destino}. El PEP la bloqueó por "
                     f"la regla {v['regla_principal']}. No se movió dinero y se envió alerta al Oficial de Seguridad."),
            riesgos=tuple(riesgos), recomendacion="NO_FIRMAR",
            pregunta_confirmacion="Esta operación no se puede aprobar. Solo el Oficial de Seguridad puede revisar el incidente.")
    if v["decision"] == "RECHAZADA":
        return ExplicacionSchema(
            titulo="Solicitud rechazada y devuelta a cuentas por pagar",
            resumen=(f"El Agente Financiero solicitó pagar {monto} a {destino}. El PEP la rechazó por la regla "
                     f"{v['regla_principal']}. No se movió dinero."),
            riesgos=tuple(riesgos), recomendacion="NO_FIRMAR",
            pregunta_confirmacion="No requiere firma. Cuentas por pagar puede corregirla y reenviarla con soporte.")
    if v["decision"] == "EJECUTADA":
        return ExplicacionSchema(
            titulo="Pago ejecutado sin control (PEP desactivado)",
            resumen=f"Se transfirieron {monto} a {destino} sin reglas, sin firmas y sin confirmación humana.",
            riesgos=tuple(riesgos), recomendacion="SOLO_INFORMATIVO",
            pregunta_confirmacion="El pago ya ocurrió: no hubo oportunidad de confirmar.")

    firmantes = ", ".join(datos["etiquetas_firmantes"])
    extra = (f" Antes de la última firma debe hacerse verificación telefónica al número registrado "
             f"{v['telefono_registrado']}.") if v.get("verificacion_telefonica") else ""
    soporte = " y ".join(x for x in [f"factura {p['numero_factura']}" if p.get("numero_factura") else "",
                                      p.get("numero_oc") or ""] if x) or "soporte registrado"
    sin_alertas = m.get("nivel_riesgo") == "BAJO" and not m.get("banderas_anomalia")
    reco = "FIRMAR" if sin_alertas and not v.get("verificacion_telefonica") else "REVISAR_CON_CUIDADO"
    return ExplicacionSchema(
        titulo=f"Confirmación requerida: pago a {p['beneficiario']}",
        resumen=(f"El Agente Financiero solicitó ejecutar un pago de {monto} a {destino} por "
                 f"«{p['concepto']}», con {soporte}. El PEP verificó que el proveedor está registrado, que la cuenta "
                 f"coincide con el maestro y que no es un duplicado. Por la regla {v['regla_principal']} se requieren "
                 f"las firmas de: {firmantes}.{extra} Nada se paga hasta completar las firmas."),
        riesgos=tuple(riesgos), recomendacion=reco,
        pregunta_confirmacion=(f"¿Confirma que revisó la evidencia y desea firmar el pago de {monto} a "
                               f"{p['beneficiario']}, cuenta {cuenta}?"))
