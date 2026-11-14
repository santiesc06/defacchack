"""Fachada del sistema: arma el núcleo + el Policy Pack activo, ejecuta el grafo y expone el canal humano."""
from __future__ import annotations

import threading
import time
import uuid

from .agentes import AgenteEjecutor, ExplicadorAgent, OrquestadorAgent, RecepcionistaAgent, VerificadorLLMAgent
from .audit import AuditLogSHA256
from .config import DESCRIPCION_MODO, MODOS_CON_PEP, RUNTIME_DIR, Modo, etiqueta_rol
from .grafo import Dependencias, construir_grafo
from .herramientas import ToolGateway
from .llm import ErrorModelo, ProveedorLLM
from .packs import PACK_POR_DEFECTO, crear_pack, listar_packs
from .pep import ErrorFirma, PolicyEnforcementPoint
from .repositorio import reloj_sistema
from .sanitizer import ContextSanitizer
from .schemas import ESTADOS_PENDIENTES, CorreoEntrada, Estado


class FirewallService:
    def __init__(self, *, persistir_auditoria: bool = True, reloj=reloj_sistema, llm: ProveedorLLM | None = None,
                 modo: Modo | str | None = None, pep_activo: bool = True, sanitizer_activo: bool = True,
                 pack: str = PACK_POR_DEFECTO) -> None:
        self._persistir = persistir_auditoria
        self._reloj = reloj
        self._llm_fijo = llm
        self._lock = threading.RLock()
        if modo is None:  # compatibilidad con la API anterior (interruptor del PEP)
            modo = Modo.SIN_DEFENSA if not pep_activo else (Modo.COMPLETO if sanitizer_activo else Modo.SOLO_PEP)
        self.reiniciar(modo=Modo(modo), pack=pack)

    # ------------------------------------------------------------------------------------
    def reiniciar(self, *, modo: Modo = Modo.COMPLETO, pack: str | None = None) -> None:
        with self._lock:
            self.pack = crear_pack(pack or getattr(self, "pack", None) and self.pack.id or PACK_POR_DEFECTO, self._reloj)
            # Atajos históricos del pack de pagos (las pruebas y el benchmark los usan).
            self.repo = getattr(self.pack, "repo", None)
            self.pagos = getattr(self.pack, "pagos", None)
            ruta = RUNTIME_DIR / "audit_log.jsonl" if self._persistir else None
            self.audit = AuditLogSHA256(ruta, self._reloj)
            self.pep = PolicyEnforcementPoint(self.pack, self.audit, self._reloj)
            self.llm = self._llm_fijo or ProveedorLLM()
            self.explicador = ExplicadorAgent(self.llm, self.pack)
            self.verificador = VerificadorLLMAgent(self.llm, self.pack)
            self.gateway = ToolGateway(self.pep, self.audit, self.explicador.explicar,
                                       verificador=self.verificador.verificar)
            self.grafo = construir_grafo(Dependencias(
                recepcionista=RecepcionistaAgent(self.llm, self.pack),
                sanitizer=ContextSanitizer(self.llm, self.pack.dominios_protegidos()),
                orquestador=OrquestadorAgent(self.llm, self.pack),
                financiero=AgenteEjecutor(self.llm, self.pack),
                gateway=self.gateway, audit=self.audit))
            self.solicitudes: dict[str, dict] = {}
            self.modo = Modo.COMPLETO
            self.set_modo(modo, registrar=False)
            self.audit.anexar(actor="sistema", evento="INICIO_SESION",
                              payload={"modo": self.modo.value, "dominio": self.pack.id, "llm": self.llm.descripcion,
                                       "kpi_inicial": self.pack.kpis()["activo"]})

    @property
    def pep_activo(self) -> bool:
        return self.modo in MODOS_CON_PEP

    def set_modo(self, modo: Modo | str, registrar: bool = True) -> None:
        modo = Modo(modo)
        if modo is Modo.SOLO_LLM and not self.llm.es_real:
            raise ValueError("El modo SOLO_LLM necesita un modelo real (CFZT_LLM=ollama, groq o gemini): "
                             "con el simulador no hay un LLM que verificar")
        with self._lock:
            self.modo = modo
            # Solo los modos con PEP exigen orden firmada; los demás son líneas base de comparación.
            self.pack.servicio_ejecucion.exigir_firma_pep = modo in MODOS_CON_PEP
            if registrar:
                self.audit.anexar(actor="humano:operador-demo", evento="CAMBIO_MODO",
                                  payload={"modo": modo.value, "descripcion": DESCRIPCION_MODO[modo]})

    def set_pep(self, activo: bool, registrar: bool = True) -> None:
        """Interruptor de la demo: ACTIVADO = COMPLETO, DESACTIVADO = SIN_DEFENSA."""
        self.set_modo(Modo.COMPLETO if activo else Modo.SIN_DEFENSA, registrar)

    def set_pack(self, pack_id: str) -> None:
        """Cambia de dominio: nuevo pack, nuevo registro de auditoría y nuevo estado (mismo núcleo)."""
        self.reiniciar(modo=self.modo, pack=pack_id)

    # ------------------------------------------------------------------------------------
    def procesar_correo(self, correo: CorreoEntrada, solicitud_id: str | None = None) -> dict:
        """Procesa cualquier entrada (correo, issue, ticket). `solicitud_id` fijo solo lo usa el benchmark."""
        with self._lock:
            sid = solicitud_id or f"SOL-{uuid.uuid4().hex[:8].upper()}"
            if sid in self.solicitudes:
                raise ValueError(f"La solicitud {sid} ya existe")
            t0 = time.perf_counter()
            base = {"id": sid, "creada": self._reloj().isoformat(timespec="seconds"), "correo": correo.model_dump(),
                    "pep_activo": self.pep_activo, "modo": self.modo.value, "dominio": self.pack.id}
            try:
                out = self.grafo.invoke({"solicitud_id": sid, "modo": self.modo, "correo": correo, "traza": []})
            except ErrorModelo as e:  # modo estricto: no se rellena con simulador y no se ejecuta nada
                self.audit.anexar(actor=f"agente:{e.agente}", evento="FALLO_MODELO", solicitud_id=sid,
                                  estado=Estado.FALLO_MODELO.value, payload={"error": str(e)})
                self.solicitudes[sid] = {
                    **base, "traza": [], "financiero_invocado": False, "estado_grafo": Estado.FALLO_MODELO.value,
                    "error_modelo": str(e), "latencia_total_ms": round((time.perf_counter() - t0) * 1000, 2),
                    "veredicto": None, "explicacion": None, "datos_verificados": None, "metadata": None}
                return self.vista(sid)
            r = out.get("resultado")
            self.solicitudes[sid] = {
                **base, "traza": out["traza"], "financiero_invocado": bool(out.get("financiero_invocado")),
                "estado_grafo": out.get("estado"), "latencia_total_ms": round((time.perf_counter() - t0) * 1000, 2),
                "veredicto": r.veredicto.model_dump(mode="json") if r else None,
                "explicacion": ({**r.explicacion.model_dump(), "coherente": r.explicacion_coherente,
                                 "origen": r.origen_explicador} if r else None),
                "datos_verificados": r.datos_verificados if r else None,
                "metadata": out["metadata"].model_dump(mode="json") if out.get("metadata") else None,
            }
            return self.vista(sid)

    def vista(self, sid: str) -> dict:
        s = dict(self.solicitudes[sid])
        reg = self.pep.registros.get(sid)
        estado = self.pep.estados_finales.get(sid) or Estado(s["estado_grafo"])
        if reg is not None:
            self.pep._expirar_si_vencida(reg)
            estado = reg.estado
            n = len(reg.firmas)
            s["firmas"] = [f.model_dump(mode="json") for f in reg.firmas]
            s["firmas_requeridas"] = [{"rol": str(r), "etiqueta": etiqueta_rol(r)} for r in reg.firmas_requeridas]
            s["siguiente_rol"] = str(reg.firmas_requeridas[n]) if estado in ESTADOS_PENDIENTES else None
            s["verificacion_telefonica"] = {"requerida": reg.verificacion_telefonica_requerida,
                                            "hecha": reg.verificacion_telefonica_hecha,
                                            "telefono": reg.telefono_registrado}
            s["iniciado_por"] = reg.iniciado_por
            s["pago"] = reg.resultado
        s["estado"] = estado.value
        s["pending_approval"] = estado in ESTADOS_PENDIENTES
        s["bloqueada"] = estado is Estado.BLOQUEADA
        return s

    # ---- canal humano -------------------------------------------------------------------
    def firmar(self, sid: str, usuario_id: str, pin: str, verificacion_telefonica: bool = False) -> dict:
        with self._lock:
            self._existe(sid)
            res = self.pep.firmar(sid, usuario_id, pin, verificacion_telefonica)
            return {**res, "solicitud": self.vista(sid)}

    def rechazar(self, sid: str, usuario_id: str, pin: str, motivo: str = "") -> dict:
        with self._lock:
            self._existe(sid)
            res = self.pep.rechazar(sid, usuario_id, pin, motivo)
            return {**res, "solicitud": self.vista(sid)}

    def revisar_incidente(self, sid: str, usuario_id: str, pin: str, nota: str = "") -> dict:
        with self._lock:
            self._existe(sid)
            res = self.pep.revisar_incidente(sid, usuario_id, pin, nota)
            return {**res, "solicitud": self.vista(sid)}

    def _existe(self, sid: str) -> None:
        if sid not in self.solicitudes:
            raise ErrorFirma("Solicitud inexistente")

    # ---- KPIs ---------------------------------------------------------------------------
    def estado(self) -> dict:
        with self._lock:
            finales = {sid: self.vista(sid)["estado"] for sid in self.solicitudes}
            decisiones = [s["veredicto"]["decision"] for s in self.solicitudes.values()
                          if s["veredicto"] and s["veredicto"].get("control", "PEP") != "NINGUNO"]
            k = self.pack.kpis()
            return {
                "pep_activo": self.pep_activo,
                "modo": self.modo.value,
                "modos": [{"id": m.value, "descripcion": DESCRIPCION_MODO[m],
                           "disponible": m is not Modo.SOLO_LLM or self.llm.es_real} for m in Modo],
                "pack": {"id": self.pack.id, "nombre": self.pack.nombre, "descripcion": self.pack.descripcion,
                         "etiquetas": self.pack.etiquetas_ui},
                "packs": listar_packs(),
                "llm_real": self.llm.es_real,
                "origen_datos": getattr(self.pack, "origen_datos", "—"),
                "llm": self.llm.descripcion,
                # Campos históricos del pack de pagos (saldo); en DevOps son los recursos operativos.
                "saldo_cop": k["activo"],
                "saldo_inicial_cop": k["activo_inicial"],
                "activo": {"valor": k["activo"], "inicial": k["activo_inicial"], "formato": k["activo_formato"]},
                "kpis": {
                    "ataques_bloqueados": sum(d in ("BLOQUEADA", "RECHAZADA") for d in decisiones),
                    "bloqueadas": sum(d == "BLOQUEADA" for d in decisiones),
                    "rechazadas": sum(d == "RECHAZADA" for d in decisiones),
                    "accesos_evitados": sum(e == Estado.CERRADA_NO_FINANCIERA.value for e in finales.values()),
                    "operaciones_aprobadas": k["ejecutadas_con_firma"],
                    "pagos_sin_control": k["ejecutadas_sin_control"],
                    "pendientes_firma": sum(e in {x.value for x in ESTADOS_PENDIENTES} for e in finales.values()),
                    "fondos_desviados_cop": k["danio"],
                    "danio_etiqueta": k["danio_etiqueta"], "danio_formato": k["danio_formato"],
                },
                "movimientos": k["movimientos"],
                "solicitudes": [{"id": sid, "asunto": s["correo"]["asunto"], "estado": finales[sid],
                                 "creada": s["creada"]} for sid, s in reversed(list(self.solicitudes.items()))][:30],
                "integridad": self.audit.verificar(),
            }

    def usuarios(self) -> list[dict]:
        return [{**u, "rol_etiqueta": etiqueta_rol(u["rol"])} for u in self.pack.directorio.usuarios_publicos()]
