"""Resumen del último reporte del benchmark para la pantalla «Benchmark» de la interfaz.

Prefiere los reportes hechos con un modelo real (la app siempre corre con un modelo) sobre los del simulador, y
dentro de cada grupo el más reciente. Solo usa un reporte que contenga el dominio pedido.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

PACK_PAGOS = "pagos_iso42001"


def _cargar(ruta: Path) -> dict | None:
    try:
        return json.loads(ruta.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _packs(r: dict) -> dict:
    # Reportes multi-dominio (packs) o antiguos (solo pagos en la raíz).
    return r.get("packs") or {PACK_PAGOS: {"configuraciones": r.get("configuraciones", {}), "n": r.get("n", {}),
                                           "nombre": "Tesorería y Pagos (ISO 42001)"}}


def _es_simulador(r: dict) -> bool:
    return str(r.get("llm", "")).lower().startswith("local")


def elegir_reporte(carpeta: Path, pack_id: str) -> tuple[Path, dict] | None:
    reportes = [(p, r) for p in carpeta.glob("resultados*.json") if (r := _cargar(p)) is not None]
    reportes.sort(key=lambda x: (not _es_simulador(x[1]), x[0].stat().st_mtime), reverse=True)
    for ruta, r in reportes:
        rp = _packs(r).get(pack_id)
        if rp and rp.get("configuraciones"):
            return ruta, r
    return None


def resumen_benchmark(carpeta: Path, pack_id: str, escenarios_pack: list[dict]) -> dict | None:
    elegido = elegir_reporte(carpeta, pack_id)
    if elegido is None:
        return None
    ruta, r = elegido
    rp = _packs(r)[pack_id]
    configs = rp["configuraciones"]
    vector = {e["id"]: e.get("vector", "—") for e in escenarios_pack}
    completo = configs.get("COMPLETO") or next(iter(configs.values()))
    por_tipo: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for f in completo.get("escenarios", []):
        if f.get("tipo") == "ATAQUE" and not f.get("fallo_modelo"):
            v = vector.get(f["id"], "Otros")
            por_tipo[v][1] += 1
            por_tipo[v][0] += f.get("estado_final") != "EJECUTADA"
    return {
        "archivo": ruta.name, "generado": r.get("generado"), "llm": r.get("llm"), "repeticiones": r.get("repeticiones"),
        "simulador": _es_simulador(r),
        "dominio": pack_id, "nombre_dominio": rp.get("nombre"), "n": rp.get("n", {}),
        "configuraciones": {c: v.get("metricas", {}) for c, v in configs.items()},
        "consolidado": {c: v.get("metricas", {}) for c, v in (r.get("consolidado") or {}).items()},
        "n_packs": len(_packs(r)),
        "por_tipo": [{"tipo": t, "bloqueados": b, "total": n} for t, (b, n) in sorted(por_tipo.items())],
        "excluidos_por_fallo_modelo": r.get("excluidos_por_fallo_modelo", []),
        "pruebas_adversariales": r.get("pruebas_adversariales_superadas"),
    }
