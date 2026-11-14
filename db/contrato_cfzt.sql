-- =====================================================================================
-- Contrato de datos del Context Firewall (solo estructura, SIN datos).
--
-- El firewall LEE estas cuatro relaciones con estos nombres y columnas. Pueden ser tablas o,
-- mejor, VISTAS sobre las tablas que ya tenga la base de pruebas (ver ejemplo al final): así no
-- hay que cambiar ni la base ni el código, solo escribir el mapeo.
--
-- El firewall NUNCA escribe en la base (Matriz 1: solo lectura). Los pagos que ejecuta durante una
-- prueba quedan en memoria; cada corrida empieza desde el mismo estado de la base.
--
-- SQL estándar: funciona en SQLite, PostgreSQL, MySQL y SQL Server (ajustar tipos si hace falta).
-- =====================================================================================

-- Maestro de proveedores (Orquestador y PEP lo consultan; el PEP compara la cuenta contra esta).
CREATE TABLE cfzt_proveedores (
    proveedor_id          VARCHAR(20)  PRIMARY KEY,  -- formato PROV-001
    razon_social          VARCHAR(120) NOT NULL,
    nit                   VARCHAR(20),
    dominio               VARCHAR(120) NOT NULL,     -- dominio de correo legítimo, p. ej. proveedor.com.co
    banco                 VARCHAR(60),
    cuenta                VARCHAR(30)  NOT NULL,     -- cuenta registrada; solo dígitos y guiones
    telefono              VARCHAR(30),               -- número para la verificación telefónica (R7/R9)
    fecha_cambio_cuenta   TIMESTAMP,                 -- última modificación de la cuenta (R9: < 30 días)
    dias_desde_cambio_cuenta INTEGER,                -- ALTERNATIVA a la fecha: días fijos (pruebas reproducibles)
    cambio_aprobado_por   VARCHAR(40)                -- usuario_id que aprobó el cambio (SoD 30 días)
);

-- Órdenes de compra (R5: el pago debe estar respaldado por OC o factura que coincida).
CREATE TABLE cfzt_ordenes_compra (
    numero_oc     VARCHAR(20) PRIMARY KEY,           -- formato OC-2026-0141
    proveedor_id  VARCHAR(20) NOT NULL,
    monto_cop     BIGINT      NOT NULL,              -- pesos enteros
    factura       VARCHAR(20)                        -- formato FV-8812 (opcional)
);

-- Historial de pagos ya hechos (R4: duplicados).
CREATE TABLE cfzt_historial_pagos (
    pago_id       VARCHAR(20) PRIMARY KEY,
    proveedor_id  VARCHAR(20) NOT NULL,
    factura       VARCHAR(20),
    monto_cop     BIGINT      NOT NULL,
    cuenta        VARCHAR(30),
    fecha         TIMESTAMP,                         -- o la alternativa:
    hace_dias     INTEGER
);

-- OPCIONAL. Personas de la Matriz 2 que firman en la consola. Si la relación no existe, se usan las
-- personas de demostración del aplicativo. Roles válidos: ANALISTA_CXP, TESORERO, DIRECTOR_FINANCIERO,
-- ADMIN_PROVEEDORES, OFICIAL_SEGURIDAD, ADMIN_PLATAFORMA, AUDITOR.
CREATE TABLE cfzt_usuarios (
    usuario_id    VARCHAR(40) PRIMARY KEY,
    nombre        VARCHAR(120) NOT NULL,
    rol           VARCHAR(30)  NOT NULL,
    pin           VARCHAR(12)  NOT NULL              -- PIN de PRUEBA (MFA simulado); nunca credenciales reales
);

-- -------------------------------------------------------------------------------------
-- Ejemplo de mapeo con VISTAS si la base ya tiene sus propias tablas (nombres inventados):
--
-- CREATE VIEW cfzt_proveedores AS
--   SELECT codigo AS proveedor_id, nombre AS razon_social, nit, email_dominio AS dominio,
--          banco, numero_cuenta AS cuenta, telefono, actualizado_en AS fecha_cambio_cuenta,
--          NULL AS dias_desde_cambio_cuenta, aprobado_por AS cambio_aprobado_por
--   FROM vendors;
-- -------------------------------------------------------------------------------------
