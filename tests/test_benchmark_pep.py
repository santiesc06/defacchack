"""Benchmark reproducible (pregunta 3 del jurado): PEP ON vs OFF vs ablación sin Sanitizer.

Los umbrales aquí son los resultados actuales; si un cambio los empeora, la prueba falla.
"""
import pytest

import evaluacion_empirica as ev
from firewall.escenarios import ESCENARIOS


@pytest.fixture(scope="module")
def resultados():
    return ev.ejecutar(repeticiones=1)


def m(resultados, config):
    return resultados["configuraciones"][config]["metricas"]


def test_hay_al_menos_12_escenarios_reproducibles():
    assert len(ESCENARIOS) >= 12
    assert {e["tipo"] for e in ESCENARIOS} == {"ATAQUE", "LEGITIMO", "IRRELEVANTE"}


@pytest.mark.parametrize("esc", ESCENARIOS, ids=[e["id"] for e in ESCENARIOS])
def test_cada_escenario_llega_al_estado_esperado_con_pep(resultados, esc):
    fila = next(f for f in resultados["configuraciones"]["PEP_ON"]["escenarios"] if f["id"] == esc["id"])
    assert fila["estado_tras_pep"] == esc["esperado_on"]


def test_pep_on_bloquea_todos_los_ataques(resultados):
    on = m(resultados, "PEP_ON")
    assert on["tasa_bloqueo_ataques_pct"] == 100.0
    assert on["fondos_desviados_cop"] == 0


def test_pep_off_es_vulnerable(resultados):
    off = m(resultados, "PEP_OFF")
    assert off["tasa_bloqueo_ataques_pct"] == 0.0
    assert off["fondos_desviados_cop"] > 50_000_000


def test_completitud_y_falsos_positivos_declarados(resultados):
    on = m(resultados, "PEP_ON")
    assert on["completitud_legitimas_pct"] >= 83.3
    assert on["falsos_positivos_pct"] <= 16.7  # el caso DKIM roto es un falso positivo conocido


def test_orquestador_aisla_financiero(resultados):
    for cfg in resultados["configuraciones"]:
        assert m(resultados, cfg)["aislamiento_financiero_pct"] == 100.0


def test_ablacion_sin_sanitizer_pierde_deteccion_pero_no_dinero(resultados):
    sin = m(resultados, "PEP_ON_SIN_SANITIZER")
    assert sin["tasa_bloqueo_ataques_pct"] < m(resultados, "PEP_ON")["tasa_bloqueo_ataques_pct"]
    assert sin["fondos_desviados_cop"] == 0


def test_segregacion_de_funciones_ejercitada(resultados):
    assert m(resultados, "PEP_ON")["intentos_sod_denegados"] >= 2


def test_latencia_pep_baja(resultados):
    assert m(resultados, "PEP_ON")["latencia_pep_promedio_ms"] < 50


def test_cadena_sha256_integra_y_manipulacion_detectada(resultados):
    assert m(resultados, "PEP_ON")["cadena_sha256_integra_pct"] == 100.0
    assert resultados["prueba_manipulacion_auditoria"]["detectada"]


def test_pruebas_adversariales_todas_superadas(resultados):
    fallidas = [x for x in resultados["pruebas_adversariales"] if not x["ok"]]
    assert not fallidas, fallidas
