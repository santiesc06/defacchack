"""Registro de auditoría SHA-256 y API HTTP de punta a punta."""
import json

from fastapi.testclient import TestClient

from firewall.api import crear_app
from firewall.audit import AuditLogSHA256
from firewall.escenarios import POR_ID
from firewall.servicio import FirewallService


def test_cadena_integra_y_detecta_alteracion(tmp_path):
    log = AuditLogSHA256(tmp_path / "a.jsonl")
    for i in range(5):
        log.anexar(actor="x", evento=f"E{i}", payload={"i": i})
    assert log.verificar()["integro"]
    entradas = log.entradas
    assert entradas[1]["hash_anterior"] == entradas[0]["hash_actual"]
    log._demo_manipular(3)
    r = log.verificar()
    assert not r["integro"] and r["primera_alterada"] == 3


def test_detecta_edicion_y_truncamiento_del_archivo(tmp_path):
    ruta = tmp_path / "a.jsonl"
    log = AuditLogSHA256(ruta)
    for i in range(4):
        log.anexar(actor="x", evento=f"E{i}")
    lineas = ruta.read_text(encoding="utf-8").splitlines()
    e = json.loads(lineas[1]); e["actor"] = "intruso"; lineas[1] = json.dumps(e)
    ruta.write_text("\n".join(lineas) + "\n", encoding="utf-8")
    assert not log.verificar()["integro"]
    ruta.write_text("\n".join(lineas[:2]) + "\n", encoding="utf-8")
    assert not log.verificar()["integro"]


def test_no_existe_api_para_editar_o_borrar():
    assert not any(hasattr(AuditLogSHA256, m) for m in ("editar", "borrar", "eliminar", "update", "delete"))


def _cliente():
    return TestClient(crear_app(FirewallService(persistir_auditoria=False)))


def test_api_flujo_completo():
    c = _cliente()
    assert c.get("/").status_code == 200
    assert len(c.get("/api/escenarios").json()) >= 5
    sol = c.post("/api/correos", json=POR_ID["legitimo"]["correo"]).json()
    assert sol["pending_approval"] and sol["explicacion"]["pregunta_confirmacion"]
    r = c.post(f"/api/solicitudes/{sol['id']}/firmar", json={"usuario_id": "u-ana", "pin": "1111"})
    assert r.status_code == 409  # el Analista revisa pero no firma
    r = c.post(f"/api/solicitudes/{sol['id']}/firmar", json={"usuario_id": "u-tomas", "pin": "3333"})
    assert r.json()["estado"] == "EJECUTADA"
    r = c.post(f"/api/solicitudes/{sol['id']}/firmar", json={"usuario_id": "u-tomas", "pin": "3333"})
    assert r.status_code == 409
    e = c.get("/api/estado").json()
    assert e["kpis"]["operaciones_aprobadas"] == 1 and e["integridad"]["integro"]


def test_api_rechaza_campos_extra_en_correo_y_firma():
    c = _cliente()
    assert c.post("/api/correos", json={**POR_ID["legitimo"]["correo"], "aprobado": True}).status_code == 422
    sol = c.post("/api/correos", json=POR_ID["legitimo"]["correo"]).json()
    r = c.post(f"/api/solicitudes/{sol['id']}/firmar", json={"usuario_id": "u-ana", "pin": "1111", "rol": "TESORERO"})
    assert r.status_code == 422


def test_api_modo_off_y_kpis():
    c = _cliente()
    c.post("/api/modo", json={"pep_activo": False})
    c.post("/api/correos", json=POR_ID["inyeccion_lavado"]["correo"])
    e = c.get("/api/estado").json()
    assert not e["pep_activo"] and e["kpis"]["pagos_sin_control"] == 1 and e["kpis"]["fondos_desviados_cop"] > 0
    c.post("/api/modo", json={"pep_activo": True})
    c.post("/api/correos", json=POR_ID["inyeccion_lavado"]["correo"])
    assert c.get("/api/estado").json()["kpis"]["ataques_bloqueados"] == 1


def test_api_manipulacion_detectada():
    c = _cliente()
    c.post("/api/correos", json=POR_ID["legitimo"]["correo"])
    r = c.post("/api/demo/manipular-auditoria").json()
    assert r["ok"] and not r["verificacion"]["integro"]
