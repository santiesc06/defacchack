"""API FastAPI + frontend estático.

Canal humano autenticado (PIN = MFA simulado). Ningún endpoint permite a un agente firmar,
cambiar los datos de referencia del pack (maestro, catálogo), las políticas o los umbrales.
`/api/pack` cambia el dominio activo (Policy Pack) sobre el mismo núcleo Zero-Trust.
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .config import ROOT
from cfzt.pep import REGLAS_UNIVERSALES

from .benchmark_resumen import resumen_benchmark
from .packs import listar_packs
from .pep import ErrorFirma
from .schemas import CorreoEntrada, PeticionFirma, PeticionModo, PeticionPack, PeticionRechazo
from .servicio import FirewallService

FRONTEND = ROOT / "frontend"


def crear_app(servicio: FirewallService | None = None) -> FastAPI:
    svc = servicio or FirewallService()
    app = FastAPI(title="Context Firewall Zero-Trust", version="2.0.0",
                  description="Middleware Zero-Trust para agentes que ejecutan herramientas: núcleo universal + Policy Packs.")
    app.state.svc = svc

    def _err(e: Exception) -> HTTPException:
        return HTTPException(status_code=409, detail=str(e))

    @app.get("/api/estado")
    def estado():
        return svc.estado()

    @app.post("/api/modo")
    def modo(p: PeticionModo):
        try:
            if p.modo is not None:
                svc.set_modo(p.modo)
            elif p.pep_activo is not None:
                svc.set_pep(p.pep_activo)
            else:
                raise ValueError("Indique `modo` o `pep_activo`")
        except ValueError as e:
            raise _err(e)
        return svc.estado()

    @app.post("/api/reiniciar")
    def reiniciar():
        svc.reiniciar(modo=svc.modo)
        return svc.estado()

    @app.get("/api/packs")
    def packs():
        return {"activo": svc.pack.id, "disponibles": listar_packs()}

    @app.post("/api/pack")
    def cambiar_pack(p: PeticionPack):
        try:
            svc.set_pack(p.pack)
        except ValueError as e:
            raise _err(e)
        return svc.estado()

    @app.get("/api/escenarios")
    def escenarios(todos: bool = False):
        esc = svc.pack.escenarios()
        lista = esc if todos else sorted((e for e in esc if e.get("ui")), key=lambda e: e["orden"])
        return [{k: e[k] for k in ("id", "etiqueta", "descripcion", "tipo", "vector", "correo")} for e in lista]

    @app.get("/api/solicitudes")
    def solicitudes():
        """Todas las solicitudes del dominio activo, con sus eventos del registro SHA-256 (para la UI)."""
        entradas = svc.audit.entradas
        return {"solicitudes": [{**svc.vista(sid), "eventos": [e for e in entradas if e["solicitud_id"] == sid]}
                                for sid in svc.solicitudes],
                "integridad": svc.audit.verificar()}

    @app.get("/api/benchmark")
    def benchmark():
        """Resumen del último reporte de evaluacion_empirica.py (reports/resultados*.json)."""
        resumen = resumen_benchmark(ROOT / "reports", svc.pack.id, svc.pack.escenarios())
        if resumen is None:
            raise HTTPException(404, "Todavía no hay resultados: ejecute evaluacion_empirica.py")
        return resumen

    @app.get("/api/escenarios/{eid}")
    def escenario(eid: str):
        por_id = {e["id"]: e for e in svc.pack.escenarios()}
        if eid not in por_id:
            raise HTTPException(404, "Escenario inexistente")
        return por_id[eid]

    @app.get("/api/usuarios")
    def usuarios():
        return svc.usuarios()

    @app.get("/api/reglas")
    def reglas():
        return {"universales": REGLAS_UNIVERSALES, "pack": svc.pack.descripcion_reglas,
                "alias": svc.pack.alias_reglas}

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

        @app.middleware("http")
        async def sin_cache_frontend(request, call_next):
            # La interfaz cambia durante la demo: el navegador siempre revalida index.html y /static.
            resp = await call_next(request)
            if request.url.path == "/" or request.url.path.startswith("/static/"):
                resp.headers["Cache-Control"] = "no-cache"
            return resp

        @app.get("/", include_in_schema=False)
        def index():
            return FileResponse(FRONTEND / "index.html")

    return app


app = crear_app()
