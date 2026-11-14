"""Interfaz de los Policy Packs (plugins de dominio).

El núcleo Zero-Trust (cfzt/: UniversalPEP U0–U4, ToolManifest, ContextEnvelope, ledger SHA-256) es el
mismo para cualquier ecosistema de agentes que ejecutan herramientas. Cada industria aporta un
Policy Pack con:

  - el esquema cerrado de extracción y de la herramienta crítica (con su ToolManifest);
  - sus datos de referencia de solo lectura (maestro de proveedores, catálogo de recursos…);
  - sus reglas deterministas (pagos R1–R9, DevOps D1–D5) y la ruta de firmas humanas;
  - el servicio que ejecuta SOLO órdenes firmadas por el PEP.

Métodos del contrato (nombres del documento de diseño):
  extraer_solicitud() · validar_reglas_negocio() · evaluar_politicas_pep() · ejecutar_accion_aprobada()
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from cfzt.contracts import ToolManifest

from ..schemas import Estado, Firma, ReglaActivada


class EjecucionRechazada(RuntimeError):
    """El servicio de ejecución del pack rechazó la orden (sin firma del PEP, saldo, recurso…)."""


@dataclass(kw_only=True)
class RegistroAccion:
    """Acción pendiente de firmas humanas, atada al hash de lo que se va a ejecutar."""
    solicitud_id: str
    hash_transaccion: str
    firmas_requeridas: tuple[str, ...]
    iniciado_por: str | None
    creado: datetime
    estado: Estado = Estado.PENDIENTE_FIRMA_1
    firmas: list[Firma] = field(default_factory=list)
    verificacion_telefonica_requerida: bool = False
    verificacion_telefonica_hecha: bool = False
    telefono_registrado: str | None = None
    resultado: dict | None = None

    @property
    def pago(self) -> dict | None:  # alias histórico del pack de pagos
        return self.resultado


@dataclass
class DecisionPack:
    """Lo que el pack aporta a la decisión del PEP, después de las reglas universales."""
    reglas: list[ReglaActivada] = field(default_factory=list)
    firmas_requeridas: tuple[str, ...] = ()
    verificacion_telefonica: bool = False
    telefono_registrado: str | None = None
    registro: RegistroAccion | None = None
    regla_principal: str | None = None   # código de la regla que define la ruta de firmas
    hash_accion: str | None = None


class PolicyPack(ABC):
    id: str
    nombre: str
    descripcion: str
    agente_ejecutor: str                 # identidad del agente que invoca la herramienta crítica
    herramienta_ejecutora: str           # nombre de la herramienta crítica
    manifiestos: dict[str, ToolManifest]
    permisos: dict[str, frozenset[str]]  # Matriz 1: agente -> herramientas
    alias_reglas: dict[str, str] = {}    # U0..U4 -> códigos históricos del dominio (compatibilidad)
    descripcion_reglas: dict[str, str] = {}
    descripcion_hash: str = "los datos firmados cambiaron"
    evento_orden: str = "ORDEN_EJECUCION"
    evento_rechazo: str = "EJECUCION_RECHAZADA"
    actor_servicio: str = "servicio_ejecucion"
    prompts: dict[str, str] = {}         # rol del agente -> clave en PROMPTS
    etiquetas_ui: dict[str, Any] = {}
    candidatos_firma: dict[str, list[str]] = {}
    origen_datos: str = "datos en memoria"
    servicio_ejecucion: Any = None       # expone exigir_firma_pep, emitir_llave_pep(), ejecutar(orden, firma, actor)
    directorio: Any = None               # expone usuario(), verificar_pin(), usuarios_publicos()

    # ---- agentes ------------------------------------------------------------------------
    @abstractmethod
    def extraer_solicitud(self, correo, llm) -> tuple[Any, str]: ...

    @abstractmethod
    def relevancia(self, extraccion, asunto: str, llm) -> tuple[Any, str]: ...

    @abstractmethod
    def validar_reglas_negocio(self, extraccion, metadata) -> tuple[Any, list]: ...

    @abstractmethod
    def preparar_propuesta(self, solicitud_id: str, extraccion, validacion, herramienta, llm) -> tuple[dict, str]: ...

    # ---- PEP ----------------------------------------------------------------------------
    @abstractmethod
    def evaluar_politicas_pep(self, args, ctx, *, bloqueado_por_core: bool, reloj) -> DecisionPack: ...

    def verificar_firmante(self, reg: RegistroAccion, usuario: dict, verificacion_telefonica: bool,
                           es_ultima: bool) -> str | None:
        """Restricciones de firma propias del dominio (además de U4). None si puede firmar."""
        return None

    @abstractmethod
    def hash_registro(self, reg: RegistroAccion) -> str: ...

    def revalidar_registro(self, reg: RegistroAccion) -> list[str]:
        return []

    @abstractmethod
    def orden_desde_registro(self, reg: RegistroAccion, hash_actual: str) -> Any: ...

    def ejecutar_accion_aprobada(self, orden, firma_pep: str) -> dict:
        return self.servicio_ejecucion.ejecutar(orden, firma_pep, actor="pep")

    @abstractmethod
    def payload_ejecucion(self, reg: RegistroAccion, resultado: dict) -> dict: ...

    @abstractmethod
    def mensaje_ejecucion(self, resultado: dict) -> str: ...

    # ---- modos de comparación, UI y benchmark ------------------------------------------
    @abstractmethod
    def ejecutar_directo(self, args: dict, actor: str) -> tuple[dict, str]: ...

    @abstractmethod
    def datos_verificados(self, reg: RegistroAccion | None, args: dict) -> dict: ...

    @abstractmethod
    def datos_internos(self, args: dict) -> dict: ...

    @abstractmethod
    def explicar_local(self, datos: dict): ...

    @abstractmethod
    def explicacion_coherente(self, exp, datos_verificados: dict) -> bool: ...

    @abstractmethod
    def dominios_protegidos(self) -> list[str]: ...

    @abstractmethod
    def escenarios(self) -> list[dict]: ...

    @abstractmethod
    def kpis(self) -> dict: ...

    def etiqueta(self, codigo: str) -> str:
        return self.alias_reglas.get(codigo, codigo)
