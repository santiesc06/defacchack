"""Arranque con un solo comando:  python start.py

1. Crea .venv si no existe e instala requirements.txt (solo la primera vez).
2. Arranca la API + frontend en http://127.0.0.1:8000 y abre el navegador.

Opciones:  python start.py --puerto 8080 --sin-navegador
LLM real (opcional):  CFZT_LLM=groq GROQ_API_KEY=... python start.py   (ver DECISIONES_DISENO.md, P1)
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import threading
import time
import venv
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"
PY = VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def asegurar_entorno() -> None:
    if not PY.exists():
        print("» Creando entorno virtual .venv …")
        venv.EnvBuilder(with_pip=True).create(VENV)
    marca = VENV / ".cfzt_instalado"
    req = ROOT / "requirements.txt"
    if not marca.exists() or marca.read_text() != req.read_text():
        print("» Instalando dependencias (solo la primera vez) …")
        subprocess.check_call([str(PY), "-m", "pip", "install", "-q", "--upgrade", "pip"])
        subprocess.check_call([str(PY), "-m", "pip", "install", "-q", "-r", str(req)])
        if os.environ.get("CFZT_LLM", "local") != "local":
            subprocess.call([str(PY), "-m", "pip", "install", "-q", "-r", str(ROOT / "requirements-llm.txt")])
        marca.write_text(req.read_text())


def main() -> None:
    for flujo in (sys.stdout, sys.stderr):  # consolas Windows cp1252
        try:
            flujo.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(description="Context Firewall Zero-Trust — demo")
    ap.add_argument("--puerto", type=int, default=8000)
    ap.add_argument("--sin-navegador", action="store_true")
    a = ap.parse_args()

    if Path(sys.executable).resolve() != PY.resolve():
        asegurar_entorno()
        cmd = [str(PY), str(Path(__file__).resolve()), *sys.argv[1:]]
        try:
            sys.exit(subprocess.call(cmd))
        except KeyboardInterrupt:
            sys.exit(0)

    url = f"http://127.0.0.1:{a.puerto}"
    print(f"\n  Context Firewall Zero-Trust  →  {url}\n  (Ctrl+C para detener)\n")
    if not a.sin_navegador:
        threading.Thread(target=lambda: (time.sleep(1.5), webbrowser.open(url)), daemon=True).start()
    import uvicorn
    os.chdir(ROOT)
    sys.path.insert(0, str(ROOT))
    uvicorn.run("firewall.api:app", host="127.0.0.1", port=a.puerto, log_level="warning")


if __name__ == "__main__":
    main()
