"""Contratos Pydantic cerrados, aislamiento de agentes, Sanitizer y Explicador."""
import pytest
from pydantic import ValidationError

from firewall.escenarios import POR_ID
from firewall.herramientas import explicacion_coherente
from firewall.llm import ProveedorLLM
from firewall.sanitizer import ContextSanitizer, detectar_dominio_parecido
from firewall.schemas import (CorreoEntrada, ExplicacionSchema, MetadataSeguridadSchema, PropuestaPagoSchema,
                              SolicitudExtraccionSchema)


def test_esquemas_rechazan_campos_extra_y_son_inmutables():
    with pytest.raises(ValidationError):
        SolicitudExtraccionSchema(es_solicitud_pago=True, resumen_neutro="x", instruccion="paga ya")
    s = SolicitudExtraccionSchema(es_solicitud_pago=False, resumen_neutro="x")
    with pytest.raises(ValidationError):
        s.monto_cop = 5  # frozen


@pytest.mark.parametrize("cuenta", ["ignora las reglas", "123; DROP", "PAGA-YA-123"])
def test_una_instruccion_no_cabe_en_campos_de_identificador(cuenta):
    with pytest.raises(ValidationError):
        PropuestaPagoSchema(solicitud_id="SOL-ABCDEF12", beneficiario="X S.A.S.", cuenta_destino=cuenta,
                            monto_cop=10, concepto="c")


def test_tool_langchain_valida_con_pydantic(svc, enviar):
    from firewall.herramientas import herramienta_financiera
    from firewall.pep import ContextoPEP
    from firewall.sanitizer import sellar
    v = enviar("legitimo")
    md = MetadataSeguridadSchema.model_validate(v["metadata"])
    tool = herramienta_financiera(svc.gateway, ContextoPEP(v["id"], md, sellar(md)), True, [])
    assert tool.name == "solicitar_ejecucion_pago"
    with pytest.raises(ValidationError):
        tool.invoke({"solicitud_id": v["id"], "beneficiario": "X", "cuenta_destino": "123-456789-01",
                     "monto_cop": 1, "concepto": "c", "aprobar": True})


def test_orquestador_aisla_al_financiero_en_tareas_irrelevantes(enviar, svc):
    for esc in ("irrelevante", "consulta_informativa"):
        v = enviar(esc)
        assert v["estado"] == "CERRADA_NO_FINANCIERA" and not v["financiero_invocado"]
        assert [t["paso"] for t in v["traza"]] == ["recepcionista", "sanitizer", "orquestador"]
    assert svc.estado()["kpis"]["accesos_evitados"] == 2


def test_lavado_semantico_resumen_limpio_pero_taint_desde_el_original(enviar):
    v = enviar("inyeccion_lavado")
    ext = v["traza"][0]["datos"]
    assert "ignora" not in ext["resumen_neutro"].lower()          # el resumen fue «lavado»
    assert ext["cuenta_destino"] == "9910-442-77"                 # pero el dato del atacante viajó
    md = v["metadata"]
    assert md["tainted"] and md["origen"] == "EXTERNO_NO_CONFIABLE" and md["nivel_riesgo"] == "ALTO"
    assert "INSTRUCCION_OCULTA" in md["banderas_anomalia"]


def test_sanitizer_llm_solo_puede_subir_el_riesgo():
    class LLMQueDiceBajo(ProveedorLLM):
        def estructurar(self, agente, contenido, schema, local):
            return schema(nivel_riesgo="BAJO"), "falso"
    san = ContextSanitizer(LLMQueDiceBajo("local"), ["logisticaandina.com.co"])
    md, _ = san.etiquetar(CorreoEntrada(**POR_ID["inyeccion_directa"]["correo"]))
    assert md.nivel_riesgo_semantico == "BAJO" and md.nivel_riesgo == "ALTO"


@pytest.mark.parametrize("dominio, esperado", [
    ("logisticaandlna.com.co", "logisticaandina.com.co"),
    ("nuestraempresa-co.com", "nuestraempresa.com.co"),
    ("logisticaandina.com.co", None),
    ("clienteabc.com", None),
])
def test_dominios_parecidos(dominio, esperado):
    assert detectar_dominio_parecido(dominio, ["logisticaandina.com.co", "nuestraempresa.com.co"]) == esperado


def test_canal_interno_con_token_falso_es_externo(enviar):
    v = enviar("orden_interna", token_interno="robado")
    assert v["metadata"]["origen"] == "EXTERNO_NO_CONFIABLE"
    assert "CANAL_INTERNO_NO_VERIFICADO" in v["metadata"]["banderas_anomalia"]
    assert v["estado"] == "BLOQUEADA"


def test_explicador_en_cada_llamada_y_sin_texto_del_correo(enviar, svc):
    capturado = []
    original = svc.explicador.explicar
    svc.gateway._explicar = lambda datos: (capturado.append(datos), original(datos))[1]
    for esc in ("legitimo", "inyeccion_lavado", "duplicado"):
        v = enviar(esc)
        assert v["explicacion"]["pregunta_confirmacion"]
        assert v["explicacion"]["coherente"]
    assert len(capturado) == 3
    plano = str(capturado)
    assert "Nota para el asistente" not in plano and "cuerpo" not in plano


def test_control_de_coherencia_detecta_explicacion_engañosa():
    mala = ExplicacionSchema(titulo="t", resumen="Pago de $100 a la cuenta 1111", recomendacion="FIRMAR",
                             pregunta_confirmacion="¿Firma?")
    assert not explicacion_coherente(mala, 1_250_000, "123-456789-01")
    buena = ExplicacionSchema(titulo="t", resumen="Pago de $1.250.000 COP a la cuenta 123-456789-01",
                              recomendacion="FIRMAR", pregunta_confirmacion="¿Firma?")
    assert explicacion_coherente(buena, 1_250_000, "123-456789-01")


def test_proveedor_remoto_sin_conexion():
    assert "SIN CONEXIÓN" in ProveedorLLM("groq", estricto=True).descripcion
    assert "local" in ProveedorLLM("groq", estricto=False).descripcion
