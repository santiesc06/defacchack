"""Reglas del PEP (Matriz 3) y segregación de funciones (Matriz 2)."""
from datetime import datetime, timedelta, timezone

import pytest

from firewall.config import Rol
from firewall.escenarios import POR_ID
from firewall.pep import ErrorFirma
from firewall.schemas import CorreoEntrada
from firewall.servicio import FirewallService


def codigos(v):
    return [r["codigo"] for r in v["veredicto"]["reglas"]]


# ---------------------------------------------------------------- Capa 1: Matriz 3
def test_r1_cuenta_distinta_al_maestro_bloquea_con_alerta(enviar, svc):
    v = enviar("lavado_parafraseado")
    assert v["estado"] == "BLOQUEADA" and "R1" in codigos(v)
    assert v["veredicto"]["alerta_seguridad"]
    assert svc.pagos.ejecutados == []
    assert any(e["evento"] == "ALERTA_OFICIAL_SEGURIDAD" for e in svc.audit.entradas)


def test_r1_proveedor_no_registrado(enviar):
    v = enviar("proveedor_no_registrado")
    assert v["estado"] == "BLOQUEADA" and v["veredicto"]["regla_principal"].startswith("R1")


def test_r2_riesgo_alto_bloquea_aunque_cuenta_y_soporte_sean_validos(enviar):
    v = enviar("inyeccion_sin_desvio")
    assert v["metadata"]["nivel_riesgo"] == "ALTO"
    assert v["estado"] == "BLOQUEADA" and codigos(v) == ["R2"]


def test_r3_dominio_parecido_y_dmarc(enviar):
    v = enviar("suplantacion_dominio")
    assert v["estado"] == "BLOQUEADA" and "R3" in codigos(v)
    assert v["metadata"]["dominio_parecido_a"] == "logisticaandina.com.co"


def test_r4_duplicado_rechaza(enviar):
    v = enviar("duplicado")
    assert v["estado"] == "RECHAZADA" and codigos(v) == ["R4"]


def test_r5_sin_soporte_rechaza(enviar):
    v = enviar("sin_soporte")
    assert v["estado"] == "RECHAZADA" and codigos(v) == ["R5"]


@pytest.mark.parametrize("esc, regla, roles, telefono", [
    ("legitimo", "R6", ["TESORERO"], False),
    ("urgencia_legitima", "R7", ["TESORERO"], True),
    ("monto_alto", "R8", ["DIRECTOR_FINANCIERO"], False),
    ("cuenta_modificada", "R9", ["DIRECTOR_FINANCIERO"], True),
])
def test_rutas_de_firma(enviar, esc, regla, roles, telefono):
    v = enviar(esc)
    assert v["estado"] == "PENDIENTE_FIRMA_1" and v["pending_approval"]
    assert v["veredicto"]["regla_principal"].startswith(regla)
    assert [r["rol"] for r in v["firmas_requeridas"]] == roles
    assert v["verificacion_telefonica"]["requerida"] is telefono


def test_pep_nunca_ejecuta_sin_firmas(enviar, svc):
    enviar("legitimo")
    assert svc.pagos.ejecutados == [] and svc.pagos.saldo == svc.pagos.saldo_inicial


def test_la_orden_usa_datos_del_maestro(enviar, svc):
    v = enviar("legitimo")
    reg = svc.pep.registros[v["id"]]
    assert reg.razon_social == "Logística Andina S.A.S." and reg.cuenta == "123-456789-01"


# ---------------------------------------------------------------- Capa 2: firmas
def test_flujo_completo_una_firma_ejecuta(enviar, svc):
    v = enviar("legitimo")
    with pytest.raises(ErrorFirma, match="Se espera"):  # Cuentas por pagar revisa, no firma
        svc.firmar(v["id"], "u-ana", "1111")
    r = svc.firmar(v["id"], "u-tomas", "3333")
    assert r["estado"] == "EJECUTADA"
    assert svc.pagos.saldo == svc.pagos.saldo_inicial - 1_250_000
    eventos = [e["evento"] for e in svc.audit.entradas if e["solicitud_id"] == v["id"]]
    assert eventos[-3:] == ["FIRMA_1", "ORDEN_PAGO", "EJECUTADA"]


def test_sod_iniciador_no_firma(enviar, svc):
    v = enviar("orden_interna")
    assert v["metadata"]["origen"] == "INTERNO_VERIFICADO" and v["iniciado_por"] == "u-tomas"
    with pytest.raises(ErrorFirma, match="inició"):
        svc.firmar(v["id"], "u-tomas", "3333")
    assert svc.firmar(v["id"], "u-teresa", "4444")["estado"] == "EJECUTADA"


def test_sod_quien_aprobo_cambio_de_cuenta_no_firma_30_dias(enviar, svc):
    svc.repo._proveedores["PROV-002"]["cambio_aprobado_por"] = "u-diana"  # la Directora aprobó el cambio
    v = enviar("cuenta_modificada")
    with pytest.raises(ErrorFirma, match="cambio de cuenta"):
        svc.firmar(v["id"], "u-diana", "5555", verificacion_telefonica=True)
    assert svc.pagos.ejecutados == []


def test_cuenta_reciente_la_firma_el_director_con_verificacion(enviar, svc):
    v = enviar("cuenta_modificada")
    with pytest.raises(ErrorFirma, match="Se espera la firma 1 de Director"):
        svc.firmar(v["id"], "u-tomas", "3333")
    assert svc.firmar(v["id"], "u-diana", "5555", verificacion_telefonica=True)["estado"] == "EJECUTADA"


def test_una_vez_ejecutada_no_admite_mas_firmas(enviar, svc):
    v = enviar("monto_alto")
    svc.firmar(v["id"], "u-diana", "5555")
    with pytest.raises(ErrorFirma, match="EJECUTADA"):
        svc.firmar(v["id"], "u-diana", "5555")


def test_verificacion_telefonica_obligatoria_antes_de_la_ultima_firma(enviar, svc):
    v = enviar("urgencia_legitima")
    with pytest.raises(ErrorFirma, match="telefónica"):
        svc.firmar(v["id"], "u-tomas", "3333")
    assert svc.firmar(v["id"], "u-tomas", "3333", verificacion_telefonica=True)["estado"] == "EJECUTADA"


@pytest.mark.parametrize("usuario, pin, patron", [
    ("u-pablo", "7777", "8.2"),
    ("agente:financiero", "0000", "Ningún agente"),
    ("u-ana", "0000", "MFA"),
    ("u-sofia", "6666", "Se espera"),
    ("u-ana", "1111", "Se espera la firma 1 de Tesorero"),
])
def test_firmas_denegadas(enviar, svc, usuario, pin, patron):
    v = enviar("legitimo")
    with pytest.raises(ErrorFirma, match=patron):
        svc.firmar(v["id"], usuario, pin)
    assert svc.vista(v["id"])["firmas"] == []


def test_firma_cubre_hash_de_beneficiario_cuenta_monto(enviar, svc):
    v = enviar("legitimo")
    svc.pep.registros[v["id"]].monto_cop = 9_999_999  # el monto cambia después de calcular el hash a firmar
    r = svc.firmar(v["id"], "u-tomas", "3333")
    assert r["estado"] == "BLOQUEADA" and "no cubre" in r["mensaje"]
    assert svc.pagos.ejecutados == []


def test_bloqueada_no_se_aprueba_y_solo_oficial_revisa(enviar, svc):
    v = enviar("inyeccion_lavado")
    with pytest.raises(ErrorFirma, match="BLOQUEADA"):
        svc.firmar(v["id"], "u-ana", "1111")
    with pytest.raises(ErrorFirma, match="Oficial"):
        svc.revisar_incidente(v["id"], "u-tomas", "3333")
    r = svc.revisar_incidente(v["id"], "u-sofia", "6666", "Revisado")
    assert r["estado"] == "BLOQUEADA"


def test_rechazo_humano(enviar, svc):
    v = enviar("legitimo")
    r = svc.rechazar(v["id"], "u-ana", "1111", "No reconozco el servicio")
    assert r["estado"] == "RECHAZADA"
    with pytest.raises(ErrorFirma):
        svc.firmar(v["id"], "u-andres", "2222")
    with pytest.raises(ErrorFirma, match="no puede rechazar"):
        svc.rechazar(enviar("legitimo")["id"], "u-aura", "9999")


def test_expiracion_48h():
    t = [datetime.now(timezone.utc)]
    s = FirewallService(persistir_auditoria=False, reloj=lambda: t[0])
    v = s.procesar_correo(CorreoEntrada(**POR_ID["legitimo"]["correo"]))
    t[0] += timedelta(hours=49)
    with pytest.raises(ErrorFirma, match="EXPIRADA"):
        s.firmar(v["id"], "u-tomas", "3333")
    assert s.vista(v["id"])["estado"] == "EXPIRADA"


def test_pep_desactivado_es_la_linea_base_vulnerable():
    s = FirewallService(persistir_auditoria=False, pep_activo=False)
    v = s.procesar_correo(CorreoEntrada(**POR_ID["inyeccion_lavado"]["correo"]))
    assert v["estado"] == "EJECUTADA"
    assert s.pagos.ejecutados[0]["cuenta_destino"] == "9910-442-77"
    assert s.estado()["kpis"]["fondos_desviados_cop"] == 18_400_000


def test_roles_de_matriz2_existen():
    s = FirewallService(persistir_auditoria=False)
    assert {u["rol"] for u in s.usuarios()} == {r.value for r in Rol}
