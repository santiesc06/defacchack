"""La pantalla Benchmark prefiere reportes con modelo real y nunca muestra cifras de otro dominio."""
import json
import os

from firewall.benchmark_resumen import resumen_benchmark

METRICAS = {"tasa_bloqueo_ataques_pct": 100.0}


def _reporte(carpeta, nombre, llm, packs, mtime):
    datos = {"llm": llm, "generado": "2026-11-14T00:00:00+00:00",
             "packs": {p: {"nombre": p, "n": {"ATAQUE": 1},
                           "configuraciones": {"COMPLETO": {"metricas": METRICAS, "escenarios": []}}} for p in packs}}
    ruta = carpeta / nombre
    ruta.write_text(json.dumps(datos), encoding="utf-8")
    os.utime(ruta, (mtime, mtime))


def test_prefiere_modelo_real_aunque_el_simulador_sea_mas_reciente(tmp_path):
    _reporte(tmp_path, "resultados_ollama.json", "ollama · qwen2.5:7b", ["pagos_iso42001"], 1_000)
    _reporte(tmp_path, "resultados.json", "local · simulador determinista", ["pagos_iso42001", "devops_cloud"], 2_000)
    r = resumen_benchmark(tmp_path, "pagos_iso42001", [])
    assert r["archivo"] == "resultados_ollama.json" and not r["simulador"]


def test_si_el_reporte_real_no_tiene_el_dominio_usa_otro_que_si(tmp_path):
    _reporte(tmp_path, "resultados_ollama.json", "ollama · qwen2.5:7b", ["pagos_iso42001"], 2_000)
    _reporte(tmp_path, "resultados.json", "local · simulador determinista", ["pagos_iso42001", "devops_cloud"], 1_000)
    r = resumen_benchmark(tmp_path, "devops_cloud", [])
    assert r["archivo"] == "resultados.json" and r["simulador"] and r["dominio"] == "devops_cloud"


def test_sin_reportes_del_dominio_no_inventa_nada(tmp_path):
    _reporte(tmp_path, "resultados.json", "local · simulador determinista", ["pagos_iso42001"], 1_000)
    assert resumen_benchmark(tmp_path, "devops_cloud", []) is None
