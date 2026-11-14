import os
import sys
import tempfile
from pathlib import Path

# Antes de importar `firewall`: LLM local (reproducible) y auditoría en un directorio temporal.
os.environ["CFZT_LLM"] = "local"
os.environ["CFZT_RUNTIME_DIR"] = tempfile.mkdtemp(prefix="cfzt-test-")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402

from firewall.escenarios import POR_ID  # noqa: E402
from firewall.schemas import CorreoEntrada  # noqa: E402
from firewall.servicio import FirewallService  # noqa: E402


@pytest.fixture
def svc():
    return FirewallService(persistir_auditoria=False)


@pytest.fixture
def enviar(svc):
    def _enviar(escenario_id: str, **override):
        datos = {**POR_ID[escenario_id]["correo"], **override}
        return svc.procesar_correo(CorreoEntrada(**datos))
    return _enviar
