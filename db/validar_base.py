"""Valida una base de pruebas contra db/contrato_cfzt.sql antes de usarla.

Uso (desde la raíz del proyecto):
  .venv/Scripts/python db/validar_base.py                       (usa la base definida en el .env)
  .venv/Scripts/python db/validar_base.py ruta/dump.sql
  .venv/Scripts/python db/validar_base.py "sqlite:///C:/ruta/pruebas.db"
  .venv/Scripts/python db/validar_base.py "postgresql+psycopg://usuario:clave@host/base"

Sale con código 1 si hay errores. Los AVISOS indican reglas que no se podrán probar con esos datos.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))


def main() -> int:
    for flujo in (sys.stdout, sys.stderr):
        try:
            flujo.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    if len(sys.argv) > 2:
        print(__doc__)
        return 2
    if len(sys.argv) == 2:  # base indicada en la línea de comandos (ignora el .env)
        destino = sys.argv[1]
        os.environ["CFZT_SIN_ENV"] = "1"
        os.environ.pop("CFZT_DB_URL", None)
        os.environ.pop("CFZT_DB_SQL", None)
        os.environ["CFZT_DB_URL" if "://" in destino else "CFZT_DB_SQL"] = destino
    # sin argumento: usa CFZT_DB_URL / CFZT_DB_SQL del .env o de la terminal

    from firewall import fuente_datos
    try:
        datos = fuente_datos.cargar()
    except Exception as e:  # noqa: BLE001 - conexión, driver o contrato
        print(f"ERROR  {type(e).__name__}: {e}")
        return 1
    if datos is None:
        print("No hay base configurada: defina CFZT_DB_URL o CFZT_DB_SQL en el .env, o pase la ruta como argumento.")
        return 2
    print(f"Fuente: {datos['origen']}")
    print(f"  proveedores: {len(datos['proveedores'])} · órdenes de compra: {len(datos['ordenes'])} · "
          f"pagos en historial: {len(datos['historial'])} · usuarios: "
          f"{len(datos['usuarios']) if datos['usuarios'] is not None else 'no incluidos'}")
    hallazgos = fuente_datos.validar(datos)
    for nivel, msg in hallazgos:
        print(f"{nivel:6} {msg}")
    errores = sum(n == "ERROR" for n, _ in hallazgos)
    print(f"\n{'✅ Base válida' if not errores else f'❌ {errores} error(es)'}"
          f"{f' · {len(hallazgos) - errores} aviso(s)' if len(hallazgos) - errores else ''}")
    return 1 if errores else 0


if __name__ == "__main__":
    sys.exit(main())
