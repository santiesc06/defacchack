"""Contratos de datos entre nodos del grafo (Pydantic v2).

Todos los modelos son cerrados (`extra="forbid"`) y congelados (`frozen=True`):
- un campo inesperado (p. ej. una instrucción colada como "nota") invalida el mensaje;
- ningún nodo posterior puede mutar lo que produjo un nodo anterior (las etiquetas del
  Sanitizer son inmutables, Matriz 1: «Modificar etiquetas ya asignadas: No»).
Los campos de texto tienen longitud máxima y, cuando el dato es un identificador, un patrón
estricto: una instrucción en lenguaje natural no cabe en `cuenta_destino` ni en `numero_oc`.
"""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .config import Rol

PATRON_CUENTA = r"^[0-9][0-9-]{4,22}[0-9]$"
PATRON_FACTURA = r"^[A-Z]{1,5}-?[0-9]{2,8}$"
PATRON_OC = r"^OC-[0-9]{4}-[0-9]{4}$"
PATRON_SOLICITUD = r"^SOL-[0-9A-F]{8}$"
MAX_MONTO = 10**12


class _Cerrado(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


ResultadoAuth = Literal["pass", "fail", "none"]
NivelRiesgo = Literal["BAJO", "MEDIO", "ALTO"]
ORDEN_RIESGO: dict[str, int] = {"BAJO": 0, "MEDIO": 1, "ALTO": 2}


class Estado(StrEnum):
    RECIBIDA = "RECIBIDA"
    ETIQUETADA = "ETIQUETADA"
    VALIDADA = "VALIDADA"
    CERRADA_NO_FINANCIERA = "CERRADA_NO_FINANCIERA"
    RECHAZADA = "RECHAZADA"
    BLOQUEADA = "BLOQUEADA"
    PENDIENTE_FIRMA_1 = "PENDIENTE_FIRMA_1"
    PENDIENTE_FIRMA_2 = "PENDIENTE_FIRMA_2"
    PENDIENTE_FIRMA_3 = "PENDIENTE_FIRMA_3"
    EJECUTADA = "EJECUTADA"
    EXPIRADA = "EXPIRADA"
    FALLO_MODELO = "FALLO_MODELO"  # modo estricto: el modelo real falló; no se paga ni se usa simulador


ESTADOS_PENDIENTES = frozenset({Estado.PENDIENTE_FIRMA_1, Estado.PENDIENTE_FIRMA_2, Estado.PENDIENTE_FIRMA_3})


# --- Entrada (mundo exterior) ----------------------------------------------------------

class CorreoEntrada(_Cerrado):
    remitente: str = Field(min_length=3, max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    nombre_remitente: str = Field(default="", max_length=120)
    asunto: str = Field(max_length=300)
    cuerpo: str = Field(max_length=8000)
    adjunto_nombre: str | None = Field(default=None, max_length=160)
    adjunto_texto: str | None = Field(default=None, max_length=8000)
    spf: ResultadoAuth = "pass"
    dkim: ResultadoAuth = "pass"
    dmarc: ResultadoAuth = "pass"
    canal: Literal["EMAIL_EXTERNO", "CANAL_INTERNO", "WEBHOOK_GITHUB", "TICKET_SOPORTE", "API_A2A"] = "EMAIL_EXTERNO"
    iniciado_por: str | None = Field(default=None, max_length=40)   # solo canal interno
    token_interno: str | None = Field(default=None, max_length=80)  # solo canal interno

    def a_envelope(self):
        """Adaptador hacia el sobre universal del núcleo (cfzt.contracts.ContextEnvelope)."""
        from cfzt.contracts import ContextEnvelope
        canal = {"EMAIL_EXTERNO": "email", "CANAL_INTERNO": "interno", "WEBHOOK_GITHUB": "webhook_github",
                 "TICKET_SOPORTE": "ticket_soporte", "API_A2A": "api_a2a"}[self.canal]
        return ContextEnvelope(
            canal=canal, remitente_o_actor=self.remitente, asunto_o_titulo=self.asunto, contenido_crudo=self.cuerpo,
            adjunto_o_payload=self.adjunto_texto,
            autenticacion_origen_valida=self.spf == "pass" and self.dkim == "pass" and self.dmarc == "pass",
            iniciado_por=self.iniciado_por)


# --- Agente A: Recepcionista --------------------------------------------------------

class SolicitudExtraccionSchema(_Cerrado):
    """Esquema cerrado: único producto del Recepcionista (Matriz 1)."""
    es_solicitud_pago: bool
    beneficiario: str | None = Field(default=None, max_length=120)
    nit_beneficiario: str | None = Field(default=None, pattern=r"^[0-9.]{6,14}-?[0-9]?$")
    cuenta_destino: str | None = Field(default=None, pattern=PATRON_CUENTA)
    monto_cop: int | None = Field(default=None, gt=0, le=MAX_MONTO)
    concepto: str | None = Field(default=None, max_length=160)
    numero_factura: str | None = Field(default=None, pattern=PATRON_FACTURA)
    numero_oc: str | None = Field(default=None, pattern=PATRON_OC)
    resumen_neutro: str = Field(max_length=400)


# --- Context Sanitizer --------------------------------------------------------------

class MetadataSeguridadSchema(_Cerrado):
    """Etiquetas inmutables de procedencia y riesgo (taint tracking)."""
    origen: Literal["EXTERNO_NO_CONFIABLE", "INTERNO_VERIFICADO"]
    tainted: bool
    spf_dkim_valido: bool
    dominio_remitente: str
    dominio_parecido_a: str | None = None
    nivel_riesgo: NivelRiesgo
    nivel_riesgo_reglas: NivelRiesgo
    nivel_riesgo_semantico: NivelRiesgo
    banderas_anomalia: tuple[str, ...] = ()
    evidencias: tuple[str, ...] = ()
    sanitizer_activo: bool = True


class ClasificacionSemantica(_Cerrado):
    """Salida del clasificador semántico (LLM). Solo puede SUBIR el riesgo, nunca bajarlo."""
    nivel_riesgo: NivelRiesgo
    banderas: tuple[Literal["INSTRUCCION_OCULTA", "URGENCIA_ARTIFICIAL", "SUPLANTACION",
                            "CAMBIO_CUENTA", "PRESION_AUTORIDAD", "SECRETISMO"], ...] = ()
    justificacion: str = Field(default="", max_length=300)


# --- Orquestador --------------------------------------------------------------------

class DecisionRelevancia(_Cerrado):
    requiere_accion_financiera: bool
    categoria: Literal["SOLICITUD_PAGO", "SOLICITUD_CAMBIO", "INFORMATIVA", "OFF_TOPIC", "SPAM"]
    justificacion: str = Field(max_length=300)


class ProveedorInfo(_Cerrado):
    encontrado: bool
    proveedor_id: str | None = None
    razon_social: str | None = None
    nit: str | None = None
    dominio: str | None = None
    banco: str | None = None
    cuenta_registrada: str | None = None
    telefono_registrado: str | None = None
    dias_desde_cambio_cuenta: int | None = None
    cambio_cuenta_aprobado_por: str | None = None


class ResultadoOC(_Cerrado):
    existe: bool
    numero_oc: str | None = None
    proveedor_id: str | None = None
    monto_cop: int | None = None
    factura_asociada: str | None = None
    coincide: bool = False
    detalle: str = ""


class ResultadoDuplicado(_Cerrado):
    duplicado: bool
    detalle: str = ""
    pago_previo_id: str | None = None


class ValidacionNegocioSchema(_Cerrado):
    proveedor_registrado: bool
    proveedor_id: str | None = None
    razon_social: str | None = None
    cuenta_coincide_maestro: bool
    dominio_coincide: bool
    dias_desde_cambio_cuenta: int | None = None
    soporte_valido: bool
    duplicado: bool
    recomendacion: Literal["PROPONER_PAGO", "RECHAZAR", "ESCALAR_SEGURIDAD"]
    observaciones: tuple[str, ...] = ()


# --- Agente B: Financiero (argumentos de su herramienta) ---------------------------

class PropuestaPagoSchema(_Cerrado):
    solicitud_id: str = Field(pattern=PATRON_SOLICITUD)
    proveedor_id: str | None = Field(default=None, pattern=r"^PROV-[0-9]{3}$")
    beneficiario: str = Field(min_length=2, max_length=120)
    cuenta_destino: str = Field(pattern=PATRON_CUENTA)
    monto_cop: int = Field(gt=0, le=MAX_MONTO)
    concepto: str = Field(max_length=160)
    numero_factura: str | None = Field(default=None, pattern=PATRON_FACTURA)
    numero_oc: str | None = Field(default=None, pattern=PATRON_OC)


class InvocacionHerramienta(_Cerrado):
    agente: str
    herramienta: str
    argumentos: dict


# --- PEP ------------------------------------------------------------------------------

class ReglaActivada(_Cerrado):
    codigo: str
    descripcion: str
    decision: str


class VeredictoPEP(_Cerrado):
    decision: Literal["BLOQUEADA", "RECHAZADA", "PENDING_APPROVAL", "EJECUTADA"]
    estado: Estado
    regla_principal: str
    reglas: tuple[ReglaActivada, ...] = ()
    firmas_requeridas: tuple[str, ...] = ()  # roles (Rol o RolDevOps)
    verificacion_telefonica: bool = False
    telefono_registrado: str | None = None
    alerta_seguridad: bool = False
    hash_transaccion: str | None = None
    latencia_ms: float = 0.0
    pep_activo: bool = True
    control: Literal["PEP", "SANITIZER", "LLM", "NINGUNO"] = "PEP"  # qué componente tomó la decisión


class VeredictoVerificadorLLM(_Cerrado):
    """Salida del verificador único del modo SOLO_LLM (línea base «LLM-como-juez»)."""
    decision: Literal["APROBAR", "BLOQUEAR"]
    nivel_riesgo: NivelRiesgo
    motivo: str = Field(max_length=400)


class Firma(_Cerrado):
    usuario_id: str
    nombre: str
    rol: str
    hash_transaccion: str
    timestamp: datetime
    firma_hmac: str
    verificacion_telefonica: bool = False


# --- Explicador (LLM) -----------------------------------------------------------------

class ExplicacionSchema(_Cerrado):
    titulo: str = Field(max_length=120)
    resumen: str = Field(max_length=900)
    riesgos: tuple[str, ...] = ()
    recomendacion: Literal["FIRMAR", "REVISAR_CON_CUIDADO", "NO_FIRMAR", "SOLO_INFORMATIVO"]
    pregunta_confirmacion: str = Field(max_length=300)


# --- Peticiones humanas (API) ---------------------------------------------------------

class PeticionFirma(_Cerrado):
    usuario_id: str = Field(max_length=40)
    pin: str = Field(min_length=4, max_length=12)
    verificacion_telefonica: bool = False


class PeticionRechazo(_Cerrado):
    usuario_id: str = Field(max_length=40)
    pin: str = Field(min_length=4, max_length=12)
    motivo: str = Field(default="", max_length=300)


class PeticionPack(_Cerrado):
    pack: Literal["pagos_iso42001", "devops_cloud"]


class PeticionModo(_Cerrado):
    pep_activo: bool | None = None  # interruptor de la demo (COMPLETO / SIN_DEFENSA)
    modo: Literal["COMPLETO", "SOLO_PEP", "SOLO_SANITIZER", "SOLO_LLM", "SIN_DEFENSA"] | None = None
