"""API FastAPI + frontend estático.

Canal humano autenticado (PIN = MFA simulado). Ningún endpoint permite a un agente firmar,
cambiar el maestro de proveedores, las políticas o los umbrales.
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .config import ROOT
from .escenarios import POR_ID, escenarios_ui
from .pep import DESCRIPCION_REGLAS, ErrorFirma
from .schemas import CorreoEntrada, PeticionFirma, PeticionModo, PeticionRechazo
from .servicio import FirewallService

FRONTEND = ROOT / "frontend"


def crear_app(servicio: FirewallService | None = None) -> FastAPI:
    svc = servicio or FirewallService()
    app = FastAPI(title="Context Firewall Zero-Trust", version="1.0.0",
                  description="Pagos autónomos desde correo con PEP determinista y supervisión humana.")
    app.state.svc = svc

    def _err(e: Exception) -> HTTPException:
        return HTTPException(status_code=409, detail=str(e))

    @app.get("/api/estado")
    def estado():
        return svc.estado()

    @app.post("/api/modo")
    def modo(p: PeticionModo):
        svc.set_pep(p.pep_activo)
        return svc.estado()

    @app.post("/api/reiniciar")
    def reiniciar():
        svc.reiniciar(pep_activo=svc.pep_activo)
        return svc.estado()

    @app.get("/api/escenarios")
    def escenarios():
        return [{k: e[k] for k in ("id", "etiqueta", "descripcion", "tipo", "vector", "correo")} for e in escenarios_ui()]

    @app.get("/api/escenarios/{eid}")
    def escenario(eid: str):
        if eid not in POR_ID:
            raise HTTPException(404, "Escenario inexistente")
        return POR_ID[eid]

    @app.get("/api/usuarios")
    def usuarios():
        return svc.usuarios()

    @app.get("/api/reglas")
    def reglas():
        return DESCRIPCION_REGLAS

    @app.post("/api/correos")
    def recibir(correo: CorreoEntrada):
        return svc.procesar_correo(correo)

    @app.get("/api/solicitudes/{sid}")
    def solicitud(sid: str):
        if sid not in svc.solicitudes:
            raise HTTPException(404, "Solicitud inexistente")
        return svc.vista(sid)

    @app.post("/api/solicitudes/{sid}/firmar")
    def firmar(sid: str, p: PeticionFirma):
        try:
            return svc.firmar(sid, p.usuario_id, p.pin, p.verificacion_telefonica)
        except ErrorFirma as e:
            raise _err(e)

    @app.post("/api/solicitudes/{sid}/rechazar")
    def rechazar(sid: str, p: PeticionRechazo):
        try:
            return svc.rechazar(sid, p.usuario_id, p.pin, p.motivo)
        except ErrorFirma as e:
            raise _err(e)

    @app.post("/api/solicitudes/{sid}/revisar-incidente")
    def revisar(sid: str, p: PeticionRechazo):
        try:
            return svc.revisar_incidente(sid, p.usuario_id, p.pin, p.motivo)
        except ErrorFirma as e:
            raise _err(e)

    @app.get("/api/auditoria")
    def auditoria(limite: int = 200):
        return {"entradas": svc.audit.entradas[-limite:], "integridad": svc.audit.verificar()}

    @app.get("/api/auditoria/verificar")
    def verificar():
        return svc.audit.verificar()

    @app.post("/api/demo/manipular-auditoria")
    def manipular():
        """Solo demo: simula a un intruso editando una entrada para mostrar la detección."""
        res = svc.audit._demo_manipular()
        return {**res, "verificacion": svc.audit.verificar()}

    if FRONTEND.exists():
        app.mount("/static", StaticFiles(directory=FRONTEND), name="static")

        @app.get("/", include_in_schema=False)
        def index():
            return FileResponse(FRONTEND / "index.html")

    return app


app = crear_app()
