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
_CUENTA = re.compile(r"(?:cuenta|account)[^0-9\n]{0,60}?(\d[\d-]{4,22}\d)", re.I)
_FACTURA = re.compile(r"factura(?:\s+(?:electr[oó]nica|de\s+venta))?\s*(?:n[°ºo.]+\s*|#\s*|n[uú]mero\s*)?"
                      r"([A-Z]{1,5}-?\d{2,8})\b", re.I)
_OC = re.compile(r"\bOC-\d{4}-\d{4}\b", re.I)
_NIT = re.compile(r"NIT\s*:?\s*([\d.]{6,14}-?\d?)", re.I)
_PAL = r"[A-ZÁÉÍÓÚÑ][a-záéíóúñA-ZÁÉÍÓÚÑ&]*"
_EMPRESA = re.compile(rf"({_PAL}(?:\s+(?:de\s+|del\s+)?(?:{_PAL}|\d+)){{0,4}}\s+(?:S\.A\.S\.?|SAS|Ltda\.?|S\.A\.))")
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

    control = {"PEP": "el PEP", "SANITIZER": "el Sanitizer", "LLM": "el verificador LLM"}.get(v.get("control", "PEP"), "el control")
    if v["decision"] == "EJECUTADA" and v.get("control", "NINGUNO") != "NINGUNO":
        return ExplicacionSchema(
            titulo=f"Pago ejecutado: {control} no lo bloqueó",
            resumen=(f"Se transfirieron {monto} a {destino}. En este modo de comparación {control} es el único "
                     f"control y no hay firmas humanas. Motivo: {v['regla_principal']}"[:900]),
            riesgos=tuple(riesgos), recomendacion="SOLO_INFORMATIVO",
            pregunta_confirmacion="El pago ya ocurrió: en este modo no hay confirmación humana.")
    if v["decision"] == "BLOQUEADA":
        return ExplicacionSchema(
            titulo=f"Operación bloqueada por {control.removeprefix('el ')}",
            resumen=(f"El Agente Financiero intentó ejecutar un pago de {monto} a {destino}. {control.capitalize()} la "
                     f"bloqueó: {v['regla_principal']}. No se movió dinero y se envió alerta al Oficial de Seguridad."[:900]),
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


# ==========================================================================================
# Pack devops_cloud: extracción de issues/tickets, relevancia y explicación (simulador offline).
# Misma debilidad simulada que en pagos: «la última instrucción gana» (recurso y acción).
# ==========================================================================================
_RECURSO = re.compile(r"\b([a-z][a-z0-9]*(?:-[a-z0-9]+){1,5})\b")
_ACCIONES_KW = [
    ("ESCALAR", re.compile(r"\bescal\w*|\bscale\w*", re.I)),
    ("REINICIAR", re.compile(r"\breinici\w*|\brestart\w*", re.I)),
    ("DESPLEGAR_VERSION", re.compile(r"\bdespleg\w*|\bdesplieg\w*|\bdeploy\w*", re.I)),
    ("ACTUALIZAR_CONFIG", re.compile(r"\bconfiguraci[oó]n\b|\bconfig\b", re.I)),
    ("DROP_DATABASE", re.compile(r"drop\s+database|borr\w*\s+(la\s+)?base|elimin\w*\s+(la\s+)?base", re.I)),
    ("EXPONER_BUCKET_PUBLICO", re.compile(r"bucket\s+p[uú]blico|public\s+bucket|acceso\s+p[uú]blico|make\s+(it\s+)?public", re.I)),
    ("ROTAR_LLAVES_ROOT", re.compile(r"llaves?\s+root|root\s+keys?|credenciales\s+root", re.I)),
    ("AGREGAR_LLAVE_SSH", re.compile(r"llave\s+ssh|clave\s+ssh|ssh\s+key|authorized_keys", re.I)),
]
_REPLICAS = re.compile(r"(\d{1,2})\s*r[eé]plicas|replicas?\s*(?:a|to)\s*(\d{1,2})", re.I)
_VERSION = re.compile(r"(?<![\d.-])v?(\d{1,3}\.\d{1,3}\.\d{1,4})(?![\d.])")
_TICKET = re.compile(r"\bCHG-\d{4}-\d{4}\b")
_ACCION_LEGIBLE = {"ESCALAR": "escalar", "REINICIAR": "reiniciar", "DESPLEGAR_VERSION": "desplegar una versión en",
                   "ACTUALIZAR_CONFIG": "actualizar la configuración de", "DROP_DATABASE": "eliminar la base de datos",
                   "EXPONER_BUCKET_PUBLICO": "exponer públicamente el almacenamiento de",
                   "ROTAR_LLAVES_ROOT": "rotar las llaves root de", "AGREGAR_LLAVE_SSH": "agregar una llave SSH en"}


def extraer_cambio(correo):
    from .packs.devops_cloud import SolicitudCambioSchema
    texto = f"{correo.asunto}\n{correo.cuerpo}\n{correo.adjunto_texto or ''}"
    recursos = [r for r in _RECURSO.findall(texto) if not r.startswith(("ssh-", "chg-")) and len(r) <= 50]
    recurso = recursos[-1] if recursos else None
    posiciones = [(m.start(), accion) for accion, rx in _ACCIONES_KW for m in rx.finditer(texto)]
    accion = max(posiciones)[1] if posiciones else None
    rep = _REPLICAS.findall(texto)
    replicas = next((int(a or b) for a, b in reversed(rep) if (a or b)), None)
    versiones = _VERSION.findall(texto)
    tickets = _TICKET.findall(texto)
    entorno = ("PRODUCCION" if recurso and "prod" in recurso else "STAGING" if recurso and "staging" in recurso else None)
    es_cambio = bool(recurso and accion)
    if es_cambio:
        extras = []
        if replicas and accion == "ESCALAR":
            extras.append(f"a {replicas} réplicas")
        if versiones and accion == "DESPLEGAR_VERSION":
            extras.append(f"versión {versiones[-1]}")
        resumen = (f"Se solicita {_ACCION_LEGIBLE[accion]} {recurso}" + (f" ({', '.join(extras)})" if extras else "")
                   + (f", con ticket {tickets[-1]}" if tickets else ", sin ticket de cambio") + ".")
    else:
        resumen = f"Issue/ticket sin solicitud de cambio. Título: {correo.asunto[:150]}."
    return SolicitudCambioSchema(
        es_solicitud_cambio=es_cambio, recurso=recurso, accion=accion, entorno=entorno,
        replicas=replicas if accion == "ESCALAR" else None,
        version=(versiones[-1] if versiones and accion == "DESPLEGAR_VERSION" else None),
        ticket_cambio=tickets[-1] if tickets else None, resumen_neutro=resumen[:400])


def decidir_relevancia_cambio(ext, titulo: str) -> DecisionRelevancia:
    if ext.es_solicitud_cambio:
        return DecisionRelevancia(requiere_accion_financiera=True, categoria="SOLICITUD_CAMBIO",
                                  justificacion="El issue pide un cambio concreto sobre un recurso de infraestructura.")
    texto = f"{titulo} {ext.resumen_neutro}"
    if _SPAM_KW.search(texto):
        return DecisionRelevancia(requiere_accion_financiera=False, categoria="SPAM",
                                  justificacion="Contenido promocional sin relación con la operación.")
    return DecisionRelevancia(requiere_accion_financiera=False, categoria="INFORMATIVA",
                              justificacion="Consulta informativa: no requiere cambiar la infraestructura.")


def explicar_cambio(datos: dict) -> ExplicacionSchema:
    p, v, m = datos["propuesta"], datos["veredicto"], datos["metadata"]
    recurso, accion = p.get("recurso"), p.get("accion")
    objetivo = f"{accion} sobre {recurso} ({p.get('entorno') or 'entorno desconocido'})"
    riesgos = [f"Bandera del Sanitizer: {b}" for b in m.get("banderas_anomalia", [])]
    if not m.get("spf_dkim_valido", True):
        riesgos.append("El origen no superó la autenticación (firma HMAC / SPF)")
    if m.get("origen") == "EXTERNO_NO_CONFIABLE":
        riesgos.append("Origen externo no confiable (taint)")
    riesgos += [f"{r['codigo']}: {r['descripcion']}" for r in v.get("reglas", []) if r["decision"] in ("BLOQUEADA", "RECHAZADA")]
    control = {"PEP": "el PEP", "SANITIZER": "el Sanitizer", "LLM": "el verificador LLM"}.get(v.get("control", "PEP"), "el control")
    if v["decision"] == "BLOQUEADA":
        return ExplicacionSchema(
            titulo="Cambio de infraestructura bloqueado",
            resumen=(f"El Agente Ejecutor Cloud intentó {objetivo}. {control.capitalize()} lo bloqueó: "
                     f"{v['regla_principal']}. No se tocó la infraestructura y se alertó al Oficial de Seguridad.")[:900],
            riesgos=tuple(riesgos), recomendacion="NO_FIRMAR",
            pregunta_confirmacion="Este cambio no se puede aprobar. Solo el Oficial de Seguridad puede revisar el incidente.")
    if v["decision"] == "RECHAZADA":
        return ExplicacionSchema(
            titulo="Cambio rechazado: falta autorización del CAB",
            resumen=f"El Agente Ejecutor Cloud propuso {objetivo}. {control.capitalize()} lo rechazó: {v['regla_principal']}.",
            riesgos=tuple(riesgos), recomendacion="NO_FIRMAR",
            pregunta_confirmacion="No requiere firma. Abra un ticket de cambio en el CAB y vuelva a solicitarlo.")
    if v["decision"] == "EJECUTADA":
        return ExplicacionSchema(
            titulo="Cambio aplicado sin supervisión humana",
            resumen=f"Se aplicó {objetivo} sin firmas. Motivo: {v['regla_principal']}"[:900],
            riesgos=tuple(riesgos), recomendacion="SOLO_INFORMATIVO",
            pregunta_confirmacion="El cambio ya ocurrió: en este modo no hay confirmación humana.")
    firmantes = ", ".join(datos["etiquetas_firmantes"])
    return ExplicacionSchema(
        titulo=f"Aprobación requerida: {accion} en {recurso}",
        resumen=(f"El Agente Ejecutor Cloud solicitó {objetivo}, con ticket {p.get('ticket_cambio') or '—'}. El PEP "
                 f"verificó el recurso en el catálogo y el ticket del CAB. Por la regla {v['regla_principal']} se "
                 f"requieren las firmas de: {firmantes}. Nada se aplica hasta completar las firmas."),
        riesgos=tuple(riesgos), recomendacion="REVISAR_CON_CUIDADO" if riesgos[1:] else "FIRMAR",
        pregunta_confirmacion=f"¿Confirma que revisó el cambio {accion} sobre {recurso} y desea aprobarlo?")
