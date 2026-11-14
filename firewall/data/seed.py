"""Datos 100 % sintéticos para la demo. Ninguna cuenta, NIT o persona es real.

Los PIN son credenciales de DEMO, públicas a propósito (se muestran en la UI): simulan el
segundo factor (MFA) de la Matriz 2. No reutilizar en ningún sistema real.
"""
from __future__ import annotations

from ..config import Rol

DOMINIO_INTERNO = "nuestraempresa.com.co"
TOKEN_CANAL_INTERNO = "INT-7f3a9c21"  # emitido por el ERP interno (simulado)

PROVEEDORES = [
    {
        "proveedor_id": "PROV-001", "razon_social": "Logística Andina S.A.S.", "nit": "900.123.456-7",
        "dominio": "logisticaandina.com.co", "banco": "Bancolombia", "cuenta": "123-456789-01",
        "telefono": "+57 601 555 0101", "cambio_cuenta_hace_dias": 400, "cambio_aprobado_por": "u-tomas",
    },
    {
        "proveedor_id": "PROV-002", "razon_social": "Suministros del Caribe Ltda.", "nit": "800.765.432-1",
        "dominio": "suministroscaribe.co", "banco": "Davivienda", "cuenta": "0045-7781-2290",
        "telefono": "+57 605 555 0202", "cambio_cuenta_hace_dias": 12, "cambio_aprobado_por": "u-teresa",
    },
    {
        "proveedor_id": "PROV-003", "razon_social": "Nube Andina Cloud S.A.S.", "nit": "901.222.333-4",
        "dominio": "nubeandina.co", "banco": "BBVA", "cuenta": "778-112233-4",
        "telefono": "+57 601 555 0303", "cambio_cuenta_hace_dias": 500, "cambio_aprobado_por": "u-tomas",
    },
    {
        "proveedor_id": "PROV-004", "razon_social": "Papelería Central S.A.S.", "nit": "830.444.555-6",
        "dominio": "papeleriacentral.com.co", "banco": "Banco de Bogotá", "cuenta": "310-000777-5",
        "telefono": "+57 601 555 0404", "cambio_cuenta_hace_dias": 220, "cambio_aprobado_por": "u-tomas",
    },
]

ORDENES_COMPRA = [
    {"numero_oc": "OC-2026-0141", "proveedor_id": "PROV-001", "monto_cop": 1_250_000, "factura": "FV-8812"},
    {"numero_oc": "OC-2026-0150", "proveedor_id": "PROV-002", "monto_cop": 6_800_000, "factura": "SC-2291"},
    {"numero_oc": "OC-2026-0133", "proveedor_id": "PROV-003", "monto_cop": 1_800_000, "factura": None},
    {"numero_oc": "OC-2026-0160", "proveedor_id": "PROV-003", "monto_cop": 32_000_000, "factura": "NA-7781"},
    {"numero_oc": "OC-2026-0099", "proveedor_id": "PROV-004", "monto_cop": 850_000, "factura": "PC-319"},
    {"numero_oc": "OC-2026-0120", "proveedor_id": "PROV-001", "monto_cop": 1_250_000, "factura": "FV-8790"},
    {"numero_oc": "OC-2026-0171", "proveedor_id": "PROV-001", "monto_cop": 3_400_000, "factura": "FV-8840"},
]

HISTORIAL_PAGOS = [
    {"pago_id": "PAG-0007", "proveedor_id": "PROV-001", "factura": "FV-8790", "monto_cop": 1_250_000,
     "cuenta": "123-456789-01", "hace_dias": 9},
    {"pago_id": "PAG-0006", "proveedor_id": "PROV-004", "factura": "PC-301", "monto_cop": 640_000,
     "cuenta": "310-000777-5", "hace_dias": 40},
]

# Matriz 2 — personas. `llave_firma` simula la llave de firma personal (Tesorero / Director).
USUARIOS = [
    {"usuario_id": "u-ana", "nombre": "Ana Rojas", "rol": Rol.ANALISTA_CXP, "pin": "1111"},
    {"usuario_id": "u-andres", "nombre": "Andrés Peña", "rol": Rol.ANALISTA_CXP, "pin": "2222"},
    {"usuario_id": "u-tomas", "nombre": "Tomás Herrera", "rol": Rol.TESORERO, "pin": "3333"},
    {"usuario_id": "u-teresa", "nombre": "Teresa Gómez", "rol": Rol.TESORERO, "pin": "4444"},
    {"usuario_id": "u-diana", "nombre": "Diana Castro", "rol": Rol.DIRECTOR_FINANCIERO, "pin": "5555"},
    {"usuario_id": "u-sofia", "nombre": "Sofía Méndez", "rol": Rol.OFICIAL_SEGURIDAD, "pin": "6666"},
    {"usuario_id": "u-pablo", "nombre": "Pablo Ruiz", "rol": Rol.ADMIN_PLATAFORMA, "pin": "7777"},
    {"usuario_id": "u-victor", "nombre": "Víctor Lara", "rol": Rol.ADMIN_PROVEEDORES, "pin": "8888"},
    {"usuario_id": "u-aura", "nombre": "Aura Medina", "rol": Rol.AUDITOR, "pin": "9999"},
]
