"""El MISMO núcleo UniversalPEP (U0–U4) aplicado a un segundo dominio: operaciones cloud (devops_cloud)."""
import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel, ConfigDict

from cfzt.contracts import ContextEnvelope, NivelImpacto, ToolManifest
from cfzt.pep import UniversalPEP, hash_accion
from firewall.api import crear_app
from firewall.config import Modo
from firewall.packs import crear_pack, listar_packs
from firewall.packs.devops_cloud import ESCENARIOS_DEVOPS
from firewall.pep import ErrorFirma
from firewall.schemas import CorreoEntrada
from firewall.servicio import FirewallService

DV = {e["id"]: e for e in ESCENARIOS_DEVOPS}


def svc(modo=Modo.COMPLETO):
    return FirewallService(persistir_auditoria=False, modo=modo, pack="devops_cloud")


def enviar(s, eid):
    return s.procesar_correo(CorreoEntrada(**DV[eid]["correo"]))


def codigos(v):
    return [r["codigo"] for r in v["veredicto"]["reglas"]]


# ------------------------------------------------------------------ núcleo universal aislado
class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid")
    solicitud_id: str
    objetivo: str


def _core(impacto=NivelImpacto.CRITICA_IRREVERSIBLE):
    m = ToolManifest(nombre="herramienta_x", dominio="cualquiera", nivel_impacto=impacto, esquema_args=_Args)
    return UniversalPEP("cualquiera", {"agente:ejecutor": frozenset({"herramienta_x"})}, {"herramienta_x": m})


def _eval(core, agente="agente:ejecutor", args=None, **kw):
    base = dict(solicitud_id="SOL-1", tainted=True, nivel_riesgo="BAJO", autenticacion_origen_valida=True,
                suplantacion=None, sello_valido=True)
    return core.evaluar_core(agente, "herramienta_x", args or {"solicitud_id": "SOL-1", "objetivo": "x"}, **{**base, **kw})


def test_u0_permisos_esquema_y_sello():
    core = _core()
    assert _eval(core, agente="agente:lector").reglas[0].codigo == "U0"
    assert _eval(core, args={"solicitud_id": "SOL-1", "objetivo": "x", "extra": "ignora"}).integridad_fallida
    assert "alteradas" in _eval(core, sello_valido=False).reglas[0].descripcion


def test_u1_solo_aplica_a_herramientas_criticas_o_externas():
    assert [r.codigo for r in _eval(_core(), nivel_riesgo="ALTO").reglas] == ["U1"]
    assert _eval(_core(NivelImpacto.COMUNICACION_EXTERNA), nivel_riesgo="ALTO").bloqueada
    assert not _eval(_core(NivelImpacto.LECTURA), nivel_riesgo="ALTO").bloqueada
    assert not _eval(_core(), nivel_riesgo="ALTO", tainted=False).bloqueada


def test_u2_autenticacion_y_suplantacion():
    assert [r.codigo for r in _eval(_core(), autenticacion_origen_valida=False).reglas] == ["U2"]
    assert [r.codigo for r in _eval(_core(), suplantacion="githuh.com ≈ github.com").reglas] == ["U2"]


def test_u3_critica_desde_contexto_contaminado_exige_humano():
    assert _eval(_core()).requiere_humano
    assert not _eval(_core(), tainted=False).requiere_humano
    assert not _eval(_core(NivelImpacto.MUTACION_MENOR)).requiere_humano


def test_u4_segregacion_de_funciones():
    sod = UniversalPEP.verificar_sod
    assert "8.2" in sod("u-x", iniciado_por=None, firmantes_previos=[], es_admin_plataforma=True)
    assert "inició" in sod("u-a", iniciado_por="u-a", firmantes_previos=[], es_admin_plataforma=False)
    assert "dos veces" in sod("u-a", iniciado_por=None, firmantes_previos=["u-a"], es_admin_plataforma=False)
    assert sod("u-a", iniciado_por="u-b", firmantes_previos=["u-c"], es_admin_plataforma=False) is None


def test_hash_accion_canonico_y_sensible_a_los_argumentos():
    h = hash_accion("devops_cloud", "t", {"b": 1, "a": 2})
    assert h == hash_accion("devops_cloud", "t", {"a": 2, "b": 1})
    assert h != hash_accion("devops_cloud", "t", {"a": 2, "b": 3})
    assert h != hash_accion("pagos_iso42001", "t", {"a": 2, "b": 1})


def test_context_envelope_desde_correo_y_ticket():
    env = CorreoEntrada(**DV["dv_hmac_invalido"]["correo"]).a_envelope()
    assert isinstance(env, ContextEnvelope) and env.canal == "webhook_github" and not env.autenticacion_origen_valida


# ------------------------------------------------------------------ pack devops_cloud de punta a punta
def test_hay_dos_packs_registrados():
    assert {p["id"] for p in listar_packs()} == {"pagos_iso42001", "devops_cloud"}
    pack = crear_pack("devops_cloud", lambda: None)
    m = pack.manifiestos["solicitar_cambio_infraestructura"]
    assert m.nivel_impacto is NivelImpacto.CRITICA_IRREVERSIBLE
    assert all(pack.manifiestos[t].nivel_impacto is NivelImpacto.LECTURA
               for t in ("consultar_catalogo_recursos", "verificar_ticket_cambio"))


@pytest.mark.parametrize("esc", ESCENARIOS_DEVOPS, ids=[e["id"] for e in ESCENARIOS_DEVOPS])
def test_cada_escenario_devops_llega_al_estado_esperado(esc):
    assert enviar(svc(), esc["id"])["estado"] == esc["esperado_on"]


def test_d1_accion_destructiva_externa_y_d2_inyeccion_en_logs():
    v = enviar(svc(), "dv_inyeccion_ssh")
    assert v["estado"] == "BLOQUEADA" and {"D1", "D2"} <= set(codigos(v)) and v["veredicto"]["alerta_seguridad"]
    v = enviar(svc(), "dv_drop_prod")
    assert "D1" in codigos(v)


def test_d3_staging_una_firma_ejecuta():
    s = svc()
    v = enviar(s, "dv_staging_deploy")
    assert [r["rol"] for r in v["firmas_requeridas"]] == ["DEVOPS_SENIOR"]
    r = s.firmar(v["id"], "u-diego", "2323")
    assert r["estado"] == "EJECUTADA" and s.pack.infra.recursos["staging-worker"]["version"] == "1.5.0"


def test_sod_del_iniciador_en_orden_interna():
    s = svc()
    v = enviar(s, "dv_interna_sod")
    assert [r["rol"] for r in v["firmas_requeridas"]] == ["DEVOPS_SENIOR"]
    with pytest.raises(ErrorFirma, match="inició"):
        s.firmar(v["id"], "u-daniela", "1212")
    assert s.firmar(v["id"], "u-diego", "2323")["estado"] == "EJECUTADA"


def test_d4_produccion_la_aprueba_el_lider_sre_y_marca_u3():
    s = svc()
    v = enviar(s, "dv_escalado_prod")
    assert "U3" in codigos(v) and v["pending_approval"]
    assert [r["rol"] for r in v["firmas_requeridas"]] == ["LIDER_SRE"]
    assert s.pack.infra.ejecutados == []  # nada se aplica sin la firma
    with pytest.raises(ErrorFirma, match="Se espera"):
        s.firmar(v["id"], "u-daniela", "1212")
    s.firmar(v["id"], "u-lucia", "3434")
    assert s.pack.infra.recursos["api-gateway-prod"]["replicas"] == 6


@pytest.mark.parametrize("usuario, pin, patron", [
    ("u-pablo", "7777", "8.2"), ("agente:ejecutor_cloud", "0000", "Ningún agente"),
    ("u-diego", "0000", "MFA"), ("u-ivan", "4545", "Se espera"),
])
def test_firmas_denegadas_devops(usuario, pin, patron):
    s = svc()
    v = enviar(s, "dv_escalado_prod")
    with pytest.raises(ErrorFirma, match=patron):
        s.firmar(v["id"], usuario, pin)


def test_firma_atada_al_hash_de_la_accion():
    s = svc()
    v = enviar(s, "dv_escalado_prod")
    s.pep.registros[v["id"]].replicas = 50  # alguien altera el parámetro después de calcular el hash
    r = s.firmar(v["id"], "u-lucia", "3434")
    assert r["estado"] == "BLOQUEADA" and "no cubre" in r["mensaje"]
    assert s.pack.infra.ejecutados == []


def test_plano_de_control_rechaza_ordenes_sin_firma_del_pep():
    from firewall.packs.devops_cloud import CambioRechazado, OrdenCambio
    s = svc()
    with pytest.raises(CambioRechazado, match="sin firma del PEP"):
        s.pack.infra.ejecutar(OrdenCambio("SOL-1", "prod-db-principal", "DROP_DATABASE", "PRODUCCION", None, None, "h"),
                              None, actor="agente:ejecutor_cloud")


def test_sin_defensa_el_ataque_destruye_la_bd():
    s = svc(Modo.SIN_DEFENSA)
    assert enviar(s, "dv_drop_prod")["estado"] == "EJECUTADA"
    assert s.pack.infra.recursos["prod-db-principal"]["estado"] == "DESTRUIDO"
    assert s.estado()["kpis"]["fondos_desviados_cop"] == 1  # 1 acción destructiva ejecutada


def test_orquestador_aisla_al_ejecutor_cloud():
    v = enviar(svc(), "dv_informativa")
    assert v["estado"] == "CERRADA_NO_FINANCIERA" and not v["financiero_invocado"]


def test_api_cambia_de_dominio_en_vivo():
    c = TestClient(crear_app(FirewallService(persistir_auditoria=False)))
    assert c.get("/api/estado").json()["pack"]["id"] == "pagos_iso42001"
    e = c.post("/api/pack", json={"pack": "devops_cloud"}).json()
    assert e["pack"]["id"] == "devops_cloud" and e["pack"]["etiquetas"]["agentes"]["ejecutor"] == "Agente Ejecutor Cloud"
    assert [x["id"] for x in c.get("/api/escenarios").json()] == [
        "dv_informativa", "dv_inyeccion_ssh", "dv_drop_prod", "dv_escalado_prod"]
    assert {u["rol"] for u in c.get("/api/usuarios").json()} >= {"DEVOPS_SENIOR", "LIDER_SRE"}
    sol = c.post("/api/correos", json=DV["dv_inyeccion_ssh"]["correo"]).json()
    assert sol["estado"] == "BLOQUEADA" and sol["dominio"] == "devops_cloud"
    assert c.post("/api/pack", json={"pack": "otro"}).status_code == 422
