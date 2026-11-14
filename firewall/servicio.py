"""Fachada del sistema: arma los componentes, ejecuta el grafo y expone el canal humano."""
from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime

from .agentes import AgenteFinanciero, ExplicadorAgent, OrquestadorAgent, RecepcionistaAgent
from .audit import AuditLogSHA256
from .config import ETIQUETA_ROL, RUNTIME_DIR, Rol
from .grafo import Dependencias, construir_grafo
from .herramientas import ToolGateway, herramientas_orquestador
from .llm import ProveedorLLM
from .pagos import ServicioPagosMock
from .pep import ErrorFirma, PolicyEnforcementPoint
from .repositorio import Repositorio, normalizar_cuenta, reloj_sistema
from .sanitizer import ContextSanitizer
from .schemas import ESTADOS_PENDIENTES, CorreoEntrada, Estado


class FirewallService:
    def __init__(self, *, persistir_auditoria: bool = True, reloj=reloj_sistema, llm: ProveedorLLM | None = None,
                 pep_activo: bool = True, sanitizer_activo: bool = True) -> None:
        self._persistir = persistir_auditoria
        self._reloj = reloj
        self._llm_fijo = llm
        self._lock = threading.RLock()
        self.reiniciar(pep_activo=pep_activo, sanitizer_activo=sanitizer_activo)

    # ------------------------------------------------------------------------------------
    def reiniciar(self, *, pep_activo: bool = True, sanitizer_activo: bool = True) -> None:
        with self._lock:
            self.repo = Repositorio(self._reloj)
            ruta = RUNTIME_DIR / "audit_log.jsonl" if self._persistir else None
            self.audit = AuditLogSHA256(ruta, self._reloj)
            self.pagos = ServicioPagosMock(self.repo)
            self.pep = PolicyEnforcementPoint(self.repo, self.pagos, self.audit, self._reloj)
            self.llm = self._llm_fijo or ProveedorLLM()
            self.explicador = ExplicadorAgent(self.llm)
            self.gateway = ToolGateway(self.pep, self.pagos, self.audit, self.explicador.explicar)
            self.grafo = construir_grafo(Dependencias(
                recepcionista=RecepcionistaAgent(self.llm),
                sanitizer=ContextSanitizer(self.llm, self.repo.dominios_registrados()),
                orquestador=OrquestadorAgent(self.llm, herramientas_orquestador(self.repo.vista_solo_lectura())),
                financiero=AgenteFinanciero(self.llm),
                gateway=self.gateway, audit=self.audit))
            self.solicitudes: dict[str, dict] = {}
            self.sanitizer_activo = sanitizer_activo
            self.pep_activo = True
            self.set_pep(pep_activo, registrar=False)
            self.audit.anexar(actor="sistema", evento="INICIO_SESION",
                              payload={"pep_activo": pep_activo, "llm": self.llm.descripcion,
                                       "saldo_inicial": self.pagos.saldo})

    def set_pep(self, activo: bool, registrar: bool = True) -> None:
        with self._lock:
            self.pep_activo = activo
            self.pagos.exigir_firma_pep = activo
            if registrar:
                self.audit.anexar(actor="humano:operador-demo", evento="CAMBIO_MODO_PEP",
                                  payload={"pep_activo": activo})

    # ------------------------------------------------------------------------------------
    def procesar_correo(self, correo: CorreoEntrada) -> dict:
        with self._lock:
            sid = f"SOL-{uuid.uuid4().hex[:8].upper()}"
            t0 = time.perf_counter()
            out = self.grafo.invoke({"solicitud_id": sid, "pep_activo": self.pep_activo,
                                     "sanitizer_activo": self.sanitizer_activo, "correo": correo, "traza": []})
            total_ms = round((time.perf_counter() - t0) * 1000, 2)
            r = out.get("resultado")
            self.solicitudes[sid] = {
                "id": sid, "creada": self._reloj().isoformat(timespec="seconds"), "correo": correo.model_dump(),
                "traza": out["traza"], "pep_activo": self.pep_activo,
                "financiero_invocado": bool(out.get("financiero_invocado")),
                "estado_grafo": out.get("estado"), "latencia_total_ms": total_ms,
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
            s["firmas_requeridas"] = [{"rol": r.value, "etiqueta": ETIQUETA_ROL[r]} for r in reg.firmas_requeridas]
            s["siguiente_rol"] = reg.firmas_requeridas[n].value if estado in ESTADOS_PENDIENTES else None
            s["verificacion_telefonica"] = {"requerida": reg.verificacion_telefonica_requerida,
                                            "hecha": reg.verificacion_telefonica_hecha,
                                            "telefono": reg.telefono_registrado}
            s["iniciado_por"] = reg.iniciado_por
            s["pago"] = reg.pago
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
            cuentas_maestro = {normalizar_cuenta(self.repo.buscar_proveedor(proveedor_id=p).cuenta_registrada)
                               for p in ("PROV-001", "PROV-002", "PROV-003", "PROV-004")}
            desviado = sum(p["monto_cop"] for p in self.pagos.ejecutados
                           if normalizar_cuenta(p["cuenta_destino"]) not in cuentas_maestro)
            decisiones_pep = [s["veredicto"]["decision"] for s in self.solicitudes.values()
                              if s["veredicto"] and s["veredicto"]["pep_activo"]]
            return {
                "pep_activo": self.pep_activo,
                "llm": self.llm.descripcion,
                "saldo_cop": self.pagos.saldo,
                "saldo_inicial_cop": self.pagos.saldo_inicial,
                "kpis": {
                    "ataques_bloqueados": sum(d in ("BLOQUEADA", "RECHAZADA") for d in decisiones_pep),
                    "bloqueadas": sum(d == "BLOQUEADA" for d in decisiones_pep),
                    "rechazadas": sum(d == "RECHAZADA" for d in decisiones_pep),
                    "accesos_evitados": sum(e == Estado.CERRADA_NO_FINANCIERA.value for e in finales.values()),
                    "operaciones_aprobadas": sum(1 for p in self.pagos.ejecutados if p["con_firma_pep"]),
                    "pagos_sin_control": sum(1 for p in self.pagos.ejecutados if not p["con_firma_pep"]),
                    "pendientes_firma": sum(e in {x.value for x in ESTADOS_PENDIENTES} for e in finales.values()),
                    "fondos_desviados_cop": desviado,
                },
                "pagos": list(reversed(self.pagos.ejecutados))[:20],
                "solicitudes": [{"id": sid, "asunto": s["correo"]["asunto"], "estado": finales[sid],
                                 "creada": s["creada"]} for sid, s in reversed(list(self.solicitudes.items()))][:30],
                "integridad": self.audit.verificar(),
            }

    def usuarios(self) -> list[dict]:
        out = []
        for u in self.repo.usuarios_publicos():
            out.append({**u, "rol_etiqueta": ETIQUETA_ROL[Rol(u["rol"])]})
        return out
