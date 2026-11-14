"""Modos de comparación: SOLO_SANITIZER, SOLO_LLM (con un modelo falso guionizado) y caché del benchmark."""
import pytest
from fastapi.testclient import TestClient

from firewall.api import crear_app
from firewall.config import Modo
from firewall.escenarios import POR_ID
from firewall.llm import ErrorModelo, ProveedorLLM
from firewall.schemas import CorreoEntrada, VeredictoVerificadorLLM
from firewall.servicio import FirewallService


class LLMFalso(ProveedorLLM):
    """Se comporta como un modelo real: los agentes usan el simulador y el verificador responde según guion."""

    def __init__(self, decision="APROBAR", falla=False):
        super().__init__("local")
        self.decision, self.falla, self.recibido = decision, falla, []

    @property
    def es_real(self):
        return True

    def _estructurar(self, agente, contenido, schema, local):
        if local is not None:
            return local(), "falso"
        self.recibido.append(contenido)
        if self.falla:
            raise TimeoutError("el modelo no respondió")
        return VeredictoVerificadorLLM(decision=self.decision, nivel_riesgo="BAJO", motivo="guion de prueba"), "falso"

    def _llamar_herramienta(self, agente, contenido, herramienta, local):
        return local(), "falso"


def procesar(svc, esc):
    return svc.procesar_correo(CorreoEntrada(**POR_ID[esc]["correo"]))


def test_solo_sanitizer_bloquea_alto_y_deja_pasar_la_evasion():
    svc = FirewallService(persistir_auditoria=False, modo=Modo.SOLO_SANITIZER)
    v = procesar(svc, "inyeccion_lavado")
    assert v["estado"] == "BLOQUEADA" and v["veredicto"]["control"] == "SANITIZER"
    v = procesar(svc, "evasion_parafrasis_banco")  # sin palabras clave: el Sanitizer no la ve
    assert v["estado"] == "EJECUTADA" and svc.pagos.ejecutados[-1]["cuenta_destino"] == "2290-1145-77"


def test_solo_llm_aprueba_y_paga_sin_firmas_ni_pep():
    llm = LLMFalso("APROBAR")
    svc = FirewallService(persistir_auditoria=False, llm=llm, modo=Modo.SOLO_LLM)
    v = procesar(svc, "hilo_prueba_social")
    assert v["estado"] == "EJECUTADA" and v["veredicto"]["control"] == "LLM"
    assert svc.pep.registros == {}  # el PEP no intervino
    # El verificador recibió el correo y los datos del maestro (compite en igualdad con el PEP).
    assert "NO CONFIABLE" in llm.recibido[0] and "778-112233-4" in llm.recibido[0]
    assert "Sanitizer" not in str(v["metadata"].get("banderas_anomalia"))


def test_solo_llm_bloquea_cuando_el_modelo_bloquea():
    svc = FirewallService(persistir_auditoria=False, llm=LLMFalso("BLOQUEAR"), modo=Modo.SOLO_LLM)
    v = procesar(svc, "legitimo")
    assert v["estado"] == "BLOQUEADA" and svc.pagos.ejecutados == []


def test_solo_llm_falla_cerrada():
    svc = FirewallService(persistir_auditoria=False, llm=LLMFalso(falla=True), modo=Modo.SOLO_LLM)
    v = procesar(svc, "legitimo")
    assert v["estado"] == "BLOQUEADA" and "falla cerrada" in v["veredicto"]["regla_principal"]


def test_solo_llm_requiere_modelo_real():
    with pytest.raises(ValueError, match="modelo real"):
        FirewallService(persistir_auditoria=False, llm=ProveedorLLM("local"), modo=Modo.SOLO_LLM)
    c = TestClient(crear_app(FirewallService(persistir_auditoria=False)))
    assert c.post("/api/modo", json={"modo": "SOLO_LLM"}).status_code == 409
    e = c.post("/api/modo", json={"modo": "SOLO_PEP"}).json()
    assert e["modo"] == "SOLO_PEP" and e["pep_activo"]


def test_solo_pep_no_usa_sanitizer():
    svc = FirewallService(persistir_auditoria=False, modo=Modo.SOLO_PEP)
    v = procesar(svc, "inyeccion_sin_desvio")
    assert v["metadata"]["sanitizer_activo"] is False and v["estado"] == "PENDIENTE_FIRMA_1"


def test_cache_da_la_misma_salida_a_todas_las_configuraciones():
    llm = ProveedorLLM("local")
    llm.cache = {}
    extracciones = []
    for modo in (Modo.SIN_DEFENSA, Modo.SOLO_PEP, Modo.COMPLETO):
        svc = FirewallService(persistir_auditoria=False, llm=llm, modo=modo)
        v = svc.procesar_correo(CorreoEntrada(**POR_ID["legitimo"]["correo"]), solicitud_id="SOL-0000ABCD")
        extracciones.append(v["traza"][0]["datos"])
    assert extracciones[0] == extracciones[1] == extracciones[2]
    assert llm.estadisticas["recepcionista"]["cache"] == 2


def test_estadisticas_cuentan_fallbacks():
    class LLMQueFalla(ProveedorLLM):
        @property
        def es_real(self):
            return True

        def _crear_chat(self):
            return None

    llm = LLMQueFalla("local", estricto=False)
    llm._chat = object()  # cualquier llamada falla -> sin modo estricto cae al simulador y se cuenta
    svc = FirewallService(persistir_auditoria=False, llm=llm)
    v = procesar(svc, "legitimo")
    assert v["estado"] == "PENDIENTE_FIRMA_1"
    assert llm.estadisticas["_total"]["fallback"] >= 3
    assert "fallback" in v["traza"][0]["origen_llm"]


class LLMRoto(ProveedorLLM):
    """Modelo «real» cuyas llamadas fallan siempre (salida inválida, timeout…)."""

    @property
    def es_real(self):
        return True


def test_modo_estricto_no_usa_simulador_ni_paga():
    llm = LLMRoto("local", estricto=True)
    llm._chat = object()
    svc = FirewallService(persistir_auditoria=False, llm=llm, modo=Modo.SIN_DEFENSA)
    v = procesar(svc, "inyeccion_lavado")
    assert v["estado"] == "FALLO_MODELO" and "recepcionista" in v["error_modelo"]
    assert svc.pagos.ejecutados == [] and "fallback" not in llm.estadisticas["_total"]
    assert any(e["evento"] == "FALLO_MODELO" for e in svc.audit.entradas)


def test_modo_estricto_sin_conexion_al_modelo(monkeypatch):
    import firewall.llm as modulo_llm
    monkeypatch.setattr(modulo_llm, "OLLAMA_URL", "http://127.0.0.1:9")  # puerto sin servidor
    svc = FirewallService(persistir_auditoria=False, llm=ProveedorLLM("ollama", estricto=True))
    v = procesar(svc, "legitimo")
    assert v["estado"] == "FALLO_MODELO" and svc.pagos.ejecutados == []


def test_benchmark_estricto_excluye_el_escenario_en_todas_las_configuraciones():
    import evaluacion_empirica as ev

    class LLMQueFallaEnUno(LLMFalso):
        def _estructurar(self, agente, contenido, schema, local):
            if agente == "recepcionista" and "SC-2291" in contenido:
                raise ErrorModelo(agente, ValueError("salida inválida"))
            return super()._estructurar(agente, contenido, schema, local)

    escenarios = [POR_ID["legitimo"], POR_ID["cuenta_modificada"], POR_ID["inyeccion_lavado"]]
    r = ev.ejecutar(1, LLMQueFallaEnUno("BLOQUEAR"), escenarios)
    assert r["excluidos_por_fallo_modelo"] == ["cuenta_modificada"]
    for cfg in r["configuraciones"].values():
        estados = {f["id"]: f["estado_final"] for f in cfg["escenarios"]}
        assert estados["cuenta_modificada"] == "FALLO_MODELO"
    # Las tasas se calculan solo sobre los escenarios evaluables (1 legítimo, 1 ataque).
    assert r["configuraciones"]["COMPLETO"]["metricas"]["completitud_legitimas_pct"] == 100.0
