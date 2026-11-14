"""Conexión a base SQL (db/contrato_cfzt.sql).

No agrega datos nuevos: vuelca los datos de demostración actuales a una base SQLite temporal y
comprueba que el firewall da EXACTAMENTE los mismos resultados leyendo desde SQL. Así, cuando llegue
la base de pruebas del equipo, solo cambia la fuente.
"""
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text

from firewall import fuente_datos
from firewall.config import Modo
from firewall.data import seed
from firewall.escenarios import ESCENARIOS
from firewall.schemas import CorreoEntrada
from firewall.servicio import FirewallService

CONTRATO = Path(__file__).resolve().parent.parent / "db" / "contrato_cfzt.sql"


def _inserts(con_usuarios: bool = True) -> list[tuple[str, dict]]:
    filas = []
    for p in seed.PROVEEDORES:
        filas.append(("INSERT INTO cfzt_proveedores (proveedor_id, razon_social, nit, dominio, banco, cuenta, telefono, "
                      "dias_desde_cambio_cuenta, cambio_aprobado_por) VALUES (:proveedor_id, :razon_social, :nit, "
                      ":dominio, :banco, :cuenta, :telefono, :cambio_cuenta_hace_dias, :cambio_aprobado_por)", p))
    for o in seed.ORDENES_COMPRA:
        filas.append(("INSERT INTO cfzt_ordenes_compra VALUES (:numero_oc, :proveedor_id, :monto_cop, :factura)", o))
    for h in seed.HISTORIAL_PAGOS:
        filas.append(("INSERT INTO cfzt_historial_pagos (pago_id, proveedor_id, factura, monto_cop, cuenta, hace_dias) "
                      "VALUES (:pago_id, :proveedor_id, :factura, :monto_cop, :cuenta, :hace_dias)", h))
    if con_usuarios:
        for u in seed.USUARIOS:
            filas.append(("INSERT INTO cfzt_usuarios VALUES (:usuario_id, :nombre, :rol, :pin)", {**u, "rol": str(u["rol"])}))
    return filas


@pytest.fixture
def base_sqlite(tmp_path, monkeypatch):
    ruta = tmp_path / "pruebas.db"
    motor = create_engine(f"sqlite:///{ruta}")
    crudo = motor.raw_connection()
    crudo.executescript(CONTRATO.read_text(encoding="utf-8"))
    crudo.close()
    with motor.begin() as c:
        for sql, params in _inserts():
            c.execute(text(sql), params)
    motor.dispose()
    fuente_datos.limpiar_cache()
    monkeypatch.setenv("CFZT_DB_URL", f"sqlite:///{ruta}")
    yield ruta
    fuente_datos.limpiar_cache()


def _estados(modo=Modo.COMPLETO):
    out = {}
    for e in ESCENARIOS:
        svc = FirewallService(persistir_auditoria=False, modo=modo)
        out[e["id"]] = svc.procesar_correo(CorreoEntrada(**e["correo"]))["estado"]
    return out


def test_mismos_resultados_desde_sql_que_desde_memoria(base_sqlite, monkeypatch):
    desde_sql = _estados()
    assert FirewallService(persistir_auditoria=False).repo.origen_datos.startswith("SQL")
    monkeypatch.delenv("CFZT_DB_URL")
    fuente_datos.limpiar_cache()
    assert _estados() == desde_sql
    assert desde_sql == {e["id"]: e["esperado_on"] for e in ESCENARIOS}


def test_firmas_y_personas_desde_sql(base_sqlite):
    svc = FirewallService(persistir_auditoria=False)
    v = svc.procesar_correo(CorreoEntrada(**next(e for e in ESCENARIOS if e["id"] == "legitimo")["correo"]))
    assert svc.firmar(v["id"], "u-tomas", "3333")["estado"] == "EJECUTADA"


def test_la_base_no_se_modifica(base_sqlite):
    svc = FirewallService(persistir_auditoria=False, modo=Modo.SIN_DEFENSA)
    svc.procesar_correo(CorreoEntrada(**next(e for e in ESCENARIOS if e["id"] == "inyeccion_lavado")["correo"]))
    assert svc.pagos.ejecutados
    with create_engine(f"sqlite:///{base_sqlite}").connect() as c:
        assert c.execute(text("SELECT COUNT(*) FROM cfzt_historial_pagos")).scalar() == len(seed.HISTORIAL_PAGOS)


def test_archivo_sql_en_memoria(tmp_path, monkeypatch):
    lineas = [CONTRATO.read_text(encoding="utf-8")]
    def lit(v):
        return "NULL" if v is None else (str(v) if isinstance(v, int) else "'" + str(v).replace("'", "''") + "'")
    for sql, params in _inserts(con_usuarios=False):
        for k, v in sorted(params.items(), key=lambda kv: -len(kv[0])):
            sql = sql.replace(f":{k}", lit(v))
        lineas.append(sql + ";")
    script = tmp_path / "dump.sql"
    script.write_text("\n".join(lineas), encoding="utf-8")
    fuente_datos.limpiar_cache()
    monkeypatch.setenv("CFZT_DB_SQL", str(script))
    try:
        svc = FirewallService(persistir_auditoria=False)
        assert "dump.sql" in svc.repo.origen_datos
        assert svc.usuarios()  # sin cfzt_usuarios usa las personas de demostración
        v = svc.procesar_correo(CorreoEntrada(**next(e for e in ESCENARIOS if e["id"] == "lavado_parafraseado")["correo"]))
        assert v["estado"] == "BLOQUEADA"
    finally:
        fuente_datos.limpiar_cache()


def test_validador_acepta_una_base_correcta(base_sqlite):
    hallazgos = fuente_datos.validar(fuente_datos.cargar())
    assert [m for n, m in hallazgos if n == "ERROR"] == []
    assert not any("Sin datos para probar" in m for _, m in hallazgos)  # cubre R4 y R6 a R9


def test_validador_detecta_formatos_y_referencias():
    datos = {
        "proveedores": [{"proveedor_id": "P1", "razon_social": "X", "dominio": "a@b.com", "cuenta": "ES12 3456",
                         "cambio_aprobado_por": "u-nadie"}],
        "ordenes": [{"numero_oc": "OC-1", "proveedor_id": "PROV-999", "monto_cop": "1.250.000,50", "factura": "8812"}],
        "historial": [],
        "usuarios": [{"usuario_id": "u-a", "nombre": "A", "rol": "JEFE", "pin": "12"}],
    }
    errores = " | ".join(m for n, m in fuente_datos.validar(datos) if n == "ERROR")
    for esperado in ("PROV-001", "solo admite dígitos", "solo el dominio", "u-nadie", "OC-2026-0141",
                     "no existe en cfzt_proveedores", "FV-8812", "entero en pesos", "rol «JEFE»", "PIN"):
        assert esperado in errores, esperado


def test_error_claro_si_faltan_columnas(tmp_path, monkeypatch):
    ruta = tmp_path / "incompleta.db"
    with create_engine(f"sqlite:///{ruta}").begin() as c:
        c.execute(text("CREATE TABLE cfzt_proveedores (proveedor_id TEXT, razon_social TEXT)"))
    fuente_datos.limpiar_cache()
    monkeypatch.setenv("CFZT_DB_URL", f"sqlite:///{ruta}")
    try:
        with pytest.raises(fuente_datos.ErrorFuenteDatos, match="cuenta, dominio"):
            FirewallService(persistir_auditoria=False)
    finally:
        fuente_datos.limpiar_cache()
