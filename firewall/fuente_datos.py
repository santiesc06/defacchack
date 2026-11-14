"""Fuente de datos del maestro de proveedores, órdenes de compra, historial y personas.

Se elige con variables de entorno:
  CFZT_DB_URL   URL de SQLAlchemy de una base existente, p. ej.
                  sqlite:///C:/ruta/pruebas.db
                  postgresql+psycopg://usuario:clave@host:5432/base
                  mysql+pymysql://usuario:clave@host:3306/base
  CFZT_DB_SQL   ruta a un archivo .sql (script con CREATE TABLE / INSERT) que se carga en una
                base SQLite en memoria. El script debe ser compatible con SQLite.
Si no hay ninguna, se usan los datos de demostración del aplicativo (`data/seed.py`).

La base se lee UNA vez por proceso (instantánea) y nunca se escribe: los pagos ejecutados durante
una prueba quedan en memoria, así cada corrida del benchmark parte del mismo estado. El contrato de
columnas está en `db/contrato_cfzt.sql`.
"""
from __future__ import annotations

import os
import threading
from datetime import date, datetime, timezone
from pathlib import Path

from . import config  # noqa: F401  (carga el .env antes de leer CFZT_DB_URL / CFZT_DB_SQL)

REQUERIDAS = {
    "cfzt_proveedores": {"proveedor_id", "razon_social", "dominio", "cuenta"},
    "cfzt_ordenes_compra": {"numero_oc", "proveedor_id", "monto_cop"},
    "cfzt_historial_pagos": {"pago_id", "proveedor_id", "monto_cop"},
}
OPCIONALES = {"cfzt_usuarios": {"usuario_id", "nombre", "rol", "pin"}}


class ErrorFuenteDatos(RuntimeError):
    pass


_cache: dict[tuple, dict] = {}
_lock = threading.Lock()


def configuracion() -> tuple[str | None, str | None]:
    return os.environ.get("CFZT_DB_URL") or None, os.environ.get("CFZT_DB_SQL") or None


def _fecha(v) -> datetime | None:
    if v is None or v == "":
        return None
    if isinstance(v, datetime):
        d = v
    elif isinstance(v, date):
        d = datetime(v.year, v.month, v.day)
    else:
        d = datetime.fromisoformat(str(v).strip().replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _motor(url: str | None, script: str | None):
    from sqlalchemy import create_engine
    from sqlalchemy.pool import StaticPool
    if url:
        return create_engine(url)
    ruta = Path(script)
    if not ruta.exists():
        raise ErrorFuenteDatos(f"No existe el archivo SQL {ruta}")
    motor = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    crudo = motor.raw_connection()
    try:
        crudo.executescript(ruta.read_text(encoding="utf-8"))
        crudo.commit()
    except Exception as e:
        raise ErrorFuenteDatos(f"El script {ruta.name} no se pudo cargar en SQLite ({e}). Si viene de MySQL o "
                               "PostgreSQL, cárgalo en ese motor y usa CFZT_DB_URL.") from e
    finally:
        crudo.close()
    return motor


def _leer(conn, tabla: str, columnas: set[str], opcional: bool = False) -> list[dict] | None:
    from sqlalchemy import text
    try:
        filas = [{k.lower(): v for k, v in fila.items()} for fila in conn.execute(text(f"SELECT * FROM {tabla}")).mappings()]
        presentes = set(conn.execute(text(f"SELECT * FROM {tabla} WHERE 1=0")).keys())
    except Exception as e:
        conn.rollback()
        if opcional:
            return None
        raise ErrorFuenteDatos(f"No se pudo leer «{tabla}»: {type(e).__name__}. Ver db/contrato_cfzt.sql") from e
    faltan = columnas - {c.lower() for c in presentes}
    if faltan:
        if opcional:
            return None
        raise ErrorFuenteDatos(f"«{tabla}» no tiene las columnas: {', '.join(sorted(faltan))} (ver db/contrato_cfzt.sql)")
    return filas


def cargar() -> dict | None:
    """Datos normalizados desde SQL, o None si no hay base configurada."""
    url, script = configuracion()
    if not url and not script:
        return None
    clave = (url, script)
    with _lock:
        if clave not in _cache:
            motor = _motor(url, script)
            try:
                conn_ctx = motor.connect()
            except Exception as e:
                detalle = " | ".join(l.strip() for l in str(getattr(e, "orig", e)).splitlines() if l.strip())[:300]
                pista = (" En Oracle Autonomous Database: usa dsn=tcps://HOST:1522/SERVICIO y agrega tu IP pública a la "
                         "lista de acceso (ACL) de la base." if "oracle" in (url or "") else "")
                raise ErrorFuenteDatos(f"No se pudo conectar a {describir(url, script)}: {detalle}.{pista}") from None
            with conn_ctx as conn:
                datos = {
                    "proveedores": _leer(conn, "cfzt_proveedores", REQUERIDAS["cfzt_proveedores"]),
                    "ordenes": _leer(conn, "cfzt_ordenes_compra", REQUERIDAS["cfzt_ordenes_compra"]),
                    "historial": _leer(conn, "cfzt_historial_pagos", REQUERIDAS["cfzt_historial_pagos"]),
                    "usuarios": _leer(conn, "cfzt_usuarios", OPCIONALES["cfzt_usuarios"], opcional=True),
                }
            motor.dispose()
            for p in datos["proveedores"]:
                p["fecha_cambio_cuenta"] = _fecha(p.get("fecha_cambio_cuenta"))
            for h in datos["historial"]:
                h["fecha"] = _fecha(h.get("fecha"))
            datos["origen"] = describir(url, script)
            _cache[clave] = datos
        return _cache[clave]


def describir(url: str | None, script: str | None) -> str:
    if url:
        from sqlalchemy.engine import make_url
        return "SQL · " + make_url(url).render_as_string(hide_password=True)
    if script:
        return f"SQL · {Path(script).name} (cargado en SQLite en memoria)"
    return "datos de demostración (firewall/data/seed.py)"


def validar(datos: dict) -> list[tuple[str, str]]:
    """Revisa formatos, referencias y cobertura de las reglas. Devuelve [(nivel, mensaje)], nivel ERROR o AVISO."""
    import re

    from .config import UMBRAL_ALTO_COP, UMBRAL_BAJO_COP
    from .schemas import PATRON_CUENTA, PATRON_FACTURA, PATRON_OC

    out: list[tuple[str, str]] = []

    def err(m):
        out.append(("ERROR", m))

    def aviso(m):
        out.append(("AVISO", m))

    provs = datos.get("proveedores") or []
    ocs = datos.get("ordenes") or []
    hist = datos.get("historial") or []
    users = datos.get("usuarios")
    ids = {str(p["proveedor_id"]) for p in provs}

    for p in provs:
        pid = str(p["proveedor_id"])
        if not re.fullmatch(r"PROV-[0-9]{3}", pid):
            err(f"proveedor_id «{pid}» debe tener el formato PROV-001")
        if not re.fullmatch(PATRON_CUENTA, str(p["cuenta"])):
            err(f"{pid}: cuenta «{p['cuenta']}» solo admite dígitos y guiones (6 a 24 caracteres)")
        if "@" in str(p["dominio"]) or "." not in str(p["dominio"]):
            err(f"{pid}: dominio «{p['dominio']}» debe ser solo el dominio, p. ej. proveedor.com.co")
        if p.get("fecha_cambio_cuenta") is None and p.get("dias_desde_cambio_cuenta") is None:
            aviso(f"{pid}: sin fecha_cambio_cuenta ni dias_desde_cambio_cuenta (la regla R9 nunca aplicará)")
        apr = p.get("cambio_aprobado_por")
        if users and apr and apr not in {str(u["usuario_id"]) for u in users}:
            err(f"{pid}: cambio_aprobado_por «{apr}» no existe en cfzt_usuarios")
    for o in ocs:
        if not re.fullmatch(PATRON_OC, str(o["numero_oc"])):
            err(f"numero_oc «{o['numero_oc']}» debe tener el formato OC-2026-0141")
        if str(o["proveedor_id"]) not in ids:
            err(f"{o['numero_oc']}: proveedor_id «{o['proveedor_id']}» no existe en cfzt_proveedores")
        if o.get("factura") and not re.fullmatch(PATRON_FACTURA, str(o["factura"])):
            err(f"{o['numero_oc']}: factura «{o['factura']}» debe tener el formato FV-8812 (1-5 letras, 2-8 dígitos)")
        try:
            if int(o["monto_cop"]) <= 0:
                err(f"{o['numero_oc']}: monto_cop debe ser positivo")
        except (TypeError, ValueError):
            err(f"{o['numero_oc']}: monto_cop «{o['monto_cop']}» debe ser un entero en pesos, sin decimales")
    for h in hist:
        if str(h["proveedor_id"]) not in ids:
            err(f"{h['pago_id']}: proveedor_id «{h['proveedor_id']}» no existe en cfzt_proveedores")
        if h.get("fecha") is None and h.get("hace_dias") is None:
            aviso(f"{h['pago_id']}: sin fecha ni hace_dias")

    montos = [int(o["monto_cop"]) for o in ocs if str(o["monto_cop"]).lstrip("-").isdigit()]
    cobertura = {
        "R6 (OC de hasta $2.000.000)": any(m <= UMBRAL_BAJO_COP for m in montos),
        "R7 (OC entre $2.000.000 y $20.000.000)": any(UMBRAL_BAJO_COP < m <= UMBRAL_ALTO_COP for m in montos),
        "R8 (OC de más de $20.000.000)": any(m > UMBRAL_ALTO_COP for m in montos),
        "R9 (proveedor con cuenta cambiada hace menos de 30 días)": any(
            (p.get("dias_desde_cambio_cuenta") is not None and int(p["dias_desde_cambio_cuenta"]) < 30)
            or (p.get("fecha_cambio_cuenta") is not None
                and (datetime.now(timezone.utc) - p["fecha_cambio_cuenta"]).days < 30) for p in provs),
        "R4 (al menos un pago en el historial con factura)": any(h.get("factura") for h in hist),
    }
    for regla, ok in cobertura.items():
        if not ok:
            aviso(f"Sin datos para probar {regla}")
    if len(provs) < 3:
        aviso("Se recomiendan al menos 3 proveedores")

    if users is None:
        aviso("No hay cfzt_usuarios: se usarán las personas de demostración del aplicativo")
    else:
        from .config import Rol
        roles = []
        for u in users:
            try:
                roles.append(Rol(str(u["rol"]).strip().upper()))
            except ValueError:
                err(f"Usuario {u['usuario_id']}: rol «{u['rol']}» no válido ({', '.join(r.value for r in Rol)})")
            if not re.fullmatch(r"[0-9]{4,12}", str(u["pin"])):
                err(f"Usuario {u['usuario_id']}: el PIN debe tener de 4 a 12 dígitos")
        minimos = {Rol.ANALISTA_CXP: 2, Rol.TESORERO: 2, Rol.DIRECTOR_FINANCIERO: 1, Rol.OFICIAL_SEGURIDAD: 1,
                   Rol.ADMIN_PLATAFORMA: 1}
        for rol, n in minimos.items():
            if roles.count(rol) < n:
                aviso(f"Se necesitan al menos {n} usuario(s) con rol {rol.value} para probar la segregación de funciones")
    return out


def limpiar_cache() -> None:
    with _lock:
        _cache.clear()
