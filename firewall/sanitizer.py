"""Context Sanitizer: etiquetas inmutables de procedencia y riesgo (taint tracking).

Combina:
1. Reglas deterministas sobre el CORREO ORIGINAL (no sobre el resumen del Recepcionista, que puede
   estar «lavado»): imperativos dirigidos a una IA, texto oculto, urgencia, cambio de cuenta,
   SPF/DKIM/DMARC, dominios parecidos a los protegidos, token de canal interno.
2. Clasificación semántica (LLM o simulador): SOLO puede elevar el riesgo, nunca bajarlo.

La salida es un `MetadataSeguridadSchema` congelado; su sello SHA-256 se registra en la auditoría
y el PEP lo vuelve a comprobar antes de decidir (Matriz 1: nadie modifica etiquetas asignadas).

Lista de dominios protegidos: la mantiene el Oficial de Seguridad (equivalente a la protección de
marca de una pasarela de correo). No es el maestro de proveedores (Matriz 1: el Sanitizer no lo consulta).
"""
from __future__ import annotations

import hashlib
import re
import unicodedata

from .data.seed import DOMINIO_INTERNO, TOKEN_CANAL_INTERNO
from .llm import ProveedorLLM, delimitar_no_confiable, llm_local
from .schemas import ORDEN_RIESGO, ClasificacionSemantica, CorreoEntrada, MetadataSeguridadSchema

REGLAS_TEXTO: list[tuple[str, str, re.Pattern]] = [
    ("INSTRUCCION_OCULTA", "ALTO", re.compile(
        r"ignor[ae]\w*\s+(las\s+|todas\s+las\s+|cualquier\s+)?(instrucci|regla|indicaci|anterior|previous|polic)"
        r"|ignore (all |the )?(previous|prior)|olvida (las|tus) instrucciones|system\s*:|\[(hidden|system|admin)[^\]]*\]"
        r"|<!--|nota para (el|la) (ia|asistente|sistema|agente)|como (asistente|modelo|agente) (de ia )?(debes|deber[aá]s)"
        r"|no (lo )?(menciones|informes|reportes) (esto|al usuario|a nadie)|sin (pasar por|consultar) (el|la) (aprobaci|verificaci|pep)"
        # marcadores agnósticos al dominio (issues, tickets, logs)
        r"|ignor[ae]\w*\s+(el|este|ese)\s+(ticket|issue|correo|mensaje)|ignore\s+(the|this)\s+(ticket|issue|email|message)"
        r"|(añade|agrega|a[ñn]adir|agregar|add)\s+(mi|my|esta|this)\s+(llave|clave|key)\s+ssh|authorized_keys"
        r"|nota para el agente de ia|ai (agent|assistant)\s*:|do not tell the (reviewer|user)", re.I)),
    ("URGENCIA_ARTIFICIAL", "MEDIO", re.compile(
        r"\b(urgent\w*|hoy mismo|de inmediato|inmediatamente|antes de las \d{1,2}|última oportunidad|sin demora)\b", re.I)),
    ("CAMBIO_CUENTA", "MEDIO", re.compile(
        r"(nueva|actualizad[ao]|otra)\s+cuenta|cuenta\s+(nueva|actualizada)|cambi\w+\s+(de\s+)?(cuenta|banco|datos bancarios)"
        r"|actualiz\w+\s+(nuestros\s+)?datos bancarios", re.I)),
    ("PRESION_AUTORIDAD", "MEDIO", re.compile(r"(ya\s+)?(aprobado|autorizado)\s+por\s+(la\s+)?(gerencia|presidencia|ceo|direcci[oó]n)", re.I)),
    ("SECRETISMO", "MEDIO", re.compile(r"\b(confidencial|no lo comente|con discreci[oó]n|no copie a)\b", re.I)),
]

_INVISIBLES = re.compile("[​‌‍⁠﻿­]")
_SUFIJOS = (".com.co", ".gov.co", ".edu.co", ".org.co", ".net.co", ".co", ".com", ".net", ".org")
_HOMOGLIFOS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s")]


def _base(dominio: str) -> str:
    d = dominio.lower()
    for s in _SUFIJOS:
        if d.endswith(s):
            return d[: -len(s)]
    return d


def _levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def detectar_dominio_parecido(dominio: str, protegidos: list[str]) -> str | None:
    dominio = dominio.lower()
    if dominio in protegidos:
        return None
    b = _base(unicodedata.normalize("NFKC", dominio))
    for h, r in _HOMOGLIFOS:
        b = b.replace(h, r)
    for p in protegidos:
        bp = _base(p)
        if b == bp or _levenshtein(b, bp) <= 2 or (len(bp) >= 6 and bp in b):
            return p
    return None


def sellar(metadata: MetadataSeguridadSchema) -> str:
    return hashlib.sha256(metadata.model_dump_json().encode()).hexdigest()


def _max(*niveles: str) -> str:
    return max(niveles, key=lambda n: ORDEN_RIESGO[n])


class ContextSanitizer:
    def __init__(self, llm: ProveedorLLM, dominios_protegidos: list[str]) -> None:
        self._llm = llm
        self._protegidos = sorted(set(d.lower() for d in dominios_protegidos) | {DOMINIO_INTERNO})

    def etiquetar(self, correo: CorreoEntrada, *, activo: bool = True) -> tuple[MetadataSeguridadSchema, str]:
        """Devuelve (etiquetas inmutables, origen del clasificador semántico)."""
        dominio = correo.remitente.rsplit("@", 1)[-1].lower()
        auth_ok = correo.spf == "pass" and correo.dkim == "pass" and correo.dmarc == "pass"
        interno = (correo.canal == "CANAL_INTERNO" and correo.token_interno == TOKEN_CANAL_INTERNO
                   and dominio == DOMINIO_INTERNO and auth_ok and bool(correo.iniciado_por))
        origen = "INTERNO_VERIFICADO" if interno else "EXTERNO_NO_CONFIABLE"

        if not activo:  # ablación «PEP sin Sanitizer»: solo procedencia y cabeceras de la pasarela
            md = MetadataSeguridadSchema(origen=origen, tainted=not interno, spf_dkim_valido=auth_ok,
                                         dominio_remitente=dominio, nivel_riesgo="BAJO", nivel_riesgo_reglas="BAJO",
                                         nivel_riesgo_semantico="BAJO", sanitizer_activo=False)
            return md, "desactivado"

        texto = f"{correo.asunto}\n{correo.cuerpo}\n{correo.adjunto_texto or ''}"
        banderas: list[str] = []
        evidencias: list[str] = []
        nivel = "BAJO"
        for nombre, sev, rx in REGLAS_TEXTO:
            m = rx.search(texto)
            if m:
                banderas.append(nombre)
                evidencias.append(f"{nombre}: «{m.group(0)[:60]}»")
                nivel = _max(nivel, sev)
        if _INVISIBLES.search(texto):
            banderas.append("CARACTERES_INVISIBLES")
            nivel = "ALTO"
        if correo.adjunto_texto and REGLAS_TEXTO[0][2].search(correo.adjunto_texto):
            banderas.append("INSTRUCCION_EN_ADJUNTO")
        if "CAMBIO_CUENTA" in banderas and {"URGENCIA_ARTIFICIAL", "SECRETISMO"} & set(banderas):
            nivel = "ALTO"
        if not auth_ok:
            banderas.append("FALLO_SPF_DKIM_DMARC")
            evidencias.append(f"SPF={correo.spf} DKIM={correo.dkim} DMARC={correo.dmarc}")
            nivel = "ALTO"
        parecido = detectar_dominio_parecido(dominio, self._protegidos)
        if parecido:
            banderas.append("DOMINIO_PARECIDO")
            evidencias.append(f"{dominio} imita a {parecido}")
            nivel = "ALTO"
        if correo.canal == "CANAL_INTERNO" and not interno:
            banderas.append("CANAL_INTERNO_NO_VERIFICADO")
            nivel = "ALTO"
        nivel_reglas = nivel

        sem, origen_llm = self._llm.estructurar(
            "sanitizer", delimitar_no_confiable(f"Remitente: {correo.remitente}\n{texto}"),
            ClasificacionSemantica, lambda: llm_local.clasificar_semantico(correo))
        for b in sem.banderas:
            if b not in banderas:
                banderas.append(b)
        nivel_final = _max(nivel_reglas, sem.nivel_riesgo)  # el LLM solo puede subir el riesgo

        md = MetadataSeguridadSchema(
            origen=origen, tainted=not interno, spf_dkim_valido=auth_ok, dominio_remitente=dominio,
            dominio_parecido_a=parecido, nivel_riesgo=nivel_final, nivel_riesgo_reglas=nivel_reglas,
            nivel_riesgo_semantico=sem.nivel_riesgo, banderas_anomalia=tuple(banderas),
            evidencias=tuple(evidencias[:6]), sanitizer_activo=True)
        return md, origen_llm
