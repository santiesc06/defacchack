# Base de datos de pruebas — instrucciones para generarla

## Para qué es

El Context Firewall procesa correos que piden pagos. Antes de pagar, el PEP (código determinista) compara cada
solicitud contra el **maestro de proveedores**, las **órdenes de compra** y el **historial de pagos**. Esta base
contiene esos datos de prueba. El sistema **solo la lee**: nunca escribe en ella.

**Todo debe ser sintético:** ninguna cuenta, NIT, teléfono, persona ni PIN real.

## Entregable

Un único archivo `.sql` en UTF-8, con solo `CREATE TABLE` e `INSERT`, **compatible con SQLite**:

- sin `AUTO_INCREMENT`, `SERIAL`, `ENGINE=…`, `SET …`, `USE …`, `GO`, comillas invertidas (`` ` ``) ni corchetes;
- texto entre comillas simples; montos como enteros, sin comillas ni separadores;
- fechas como texto ISO: `'2026-11-02 10:30:00'`.

La estructura exacta está en `db/contrato_cfzt.sql`: lo más fácil es copiar sus `CREATE TABLE` al inicio del
archivo y luego escribir los `INSERT`. Si prefieren entregar una base PostgreSQL o MySQL en vez de un archivo, sirve
igual, siempre que tenga estas cuatro tablas o vistas con estos nombres y columnas.

## Tablas y formatos (los formatos son obligatorios)

### `cfzt_proveedores`
| Columna | Formato | Ejemplo |
|---|---|---|
| `proveedor_id` | `PROV-` + 3 dígitos | `PROV-001` |
| `razon_social` | Texto, terminado en S.A.S., Ltda. o S.A. | `Logística Andina S.A.S.` |
| `nit` | Dígitos, puntos y guion | `900.123.456-7` |
| `dominio` | Solo el dominio de correo, en minúsculas, sin `@` | `logisticaandina.com.co` |
| `banco` | Texto | `Bancolombia` |
| `cuenta` | Solo dígitos y guiones, de 6 a 24 caracteres | `123-456789-01` |
| `telefono` | Texto | `+57 601 555 0101` |
| `dias_desde_cambio_cuenta` | Entero: hace cuántos días cambió la cuenta. **Preferido** | `12` |
| `fecha_cambio_cuenta` | Alternativa a la anterior (`NULL` si se usa la otra) | `'2026-11-02 10:30:00'` |
| `cambio_aprobado_por` | `usuario_id` de quien aprobó el cambio (un Tesorero) | `u-teresa` |

### `cfzt_ordenes_compra`
| Columna | Formato | Ejemplo |
|---|---|---|
| `numero_oc` | `OC-` + año + `-` + 4 dígitos | `OC-2026-0141` |
| `proveedor_id` | Debe existir en `cfzt_proveedores` | `PROV-001` |
| `monto_cop` | Entero en pesos, sin decimales | `1250000` |
| `factura` | 1 a 5 letras, guion opcional, 2 a 8 dígitos (o `NULL`) | `FV-8812` |

### `cfzt_historial_pagos`
| Columna | Formato | Ejemplo |
|---|---|---|
| `pago_id` | Texto único | `PAG-0007` |
| `proveedor_id` | Debe existir en `cfzt_proveedores` | `PROV-001` |
| `factura` | Mismo formato que arriba | `FV-8790` |
| `monto_cop` | Entero en pesos | `1250000` |
| `cuenta` | Cuenta a la que se pagó | `123-456789-01` |
| `hace_dias` | Entero. **Preferido** (o `fecha` como texto ISO) | `9` |

### `cfzt_usuarios` (opcional)
| Columna | Formato | Ejemplo |
|---|---|---|
| `usuario_id` | Texto único | `u-ana` |
| `nombre` | Texto | `Ana Rojas` |
| `rol` | Uno de: `ANALISTA_CXP`, `TESORERO`, `DIRECTOR_FINANCIERO`, `ADMIN_PROVEEDORES`, `OFICIAL_SEGURIDAD`, `ADMIN_PLATAFORMA`, `AUDITOR` | `ANALISTA_CXP` |
| `pin` | 4 a 12 dígitos, **solo de prueba** | `1111` |

Si no incluyen esta tabla, se usan las personas de demostración del aplicativo.

## Qué datos debe tener (para poder probar todas las reglas)

- [ ] **Al menos 4 proveedores**, cada uno con dominio y cuenta distintos.
- [ ] **Al menos 1 proveedor con la cuenta cambiada hace menos de 30 días** (`dias_desde_cambio_cuenta` < 30), con
      `cambio_aprobado_por` = un Tesorero. Sirve para la regla R9 y para probar que ese Tesorero no puede firmar.
- [ ] **Órdenes de compra en los tres rangos de monto**: al menos una de hasta $2.000.000 (R6), una entre
      $2.000.000 y $20.000.000 (R7) y una de más de $20.000.000 (R8). La mayoría con factura.
- [ ] **Al menos 1 pago en el historial con factura** que también exista en una OC (R4, duplicados).
- [ ] Si incluyen usuarios: **2 Analistas, 2 Tesoreros, 1 Director financiero, 1 Oficial de seguridad y 1
      Administrador de plataforma** (para probar la segregación de funciones).
- [ ] Usar `dias_desde_cambio_cuenta` y `hace_dias` en vez de fechas, para que las pruebas den lo mismo cualquier día.

## Además del `.sql`, envíen esta tabla

Los correos de prueba se escriben contra estos datos. Indiquen qué registro usar para cada caso:

| Caso | Proveedor | OC | Factura | Monto |
|---|---|---|---|---|
| Pago legítimo de hasta $2M | | | | |
| Pago legítimo entre $2M y $20M | | | | |
| Pago legítimo de más de $20M | | | | |
| Proveedor con cuenta cambiada hace < 30 días | | | | |
| Factura ya pagada (duplicado) | | | | |

## Cómo comprobar que quedó bien (desde la raíz del proyecto)

```bash
.venv/Scripts/python db/validar_base.py ruta/al/archivo.sql
```

Debe terminar en `✅ Base válida`. Los `ERROR` hay que corregirlos; los `AVISO` indican reglas que no se podrán
probar con esos datos.

---

# Guía para probarlo

## 1. Validar la base
```bash
.venv/Scripts/python db/validar_base.py ruta/al/archivo.sql
```

## 2. Pruebas automáticas (no necesitan la base del equipo)
```bash
.venv/Scripts/python -m pytest -q
```
Incluyen la prueba de equivalencia: los datos de demostración volcados a SQL dan exactamente los mismos resultados
que en memoria.

## 3. Consola con la base
En PowerShell:
```bash
$env:CFZT_DB_SQL="C:/ruta/al/archivo.sql"; python start.py
```
La píldora **Datos** de arriba debe decir `SQL · archivo.sql`. Si falta una tabla o columna, el arranque muestra
cuál. Para volver a los datos de demostración, cierra la terminal o ejecuta `Remove-Item Env:CFZT_DB_SQL`.

## 4. Benchmark con la base
```bash
$env:CFZT_DB_SQL="C:/ruta/al/archivo.sql"; .venv/Scripts/python evaluacion_empirica.py
```
La cabecera de `reports/resultados.md` debe decir `datos: SQL · …`. **Importante:** mientras los correos de
`firewall/escenarios.py` no se reescriban con los proveedores, cuentas y OC de esta base, el «estado esperado» de
cada escenario no aplica: revisa la tabla «Detalle por escenario» antes de leer los porcentajes.

## 5. Con el modelo real
```bash
$env:CFZT_DB_SQL="C:/ruta/al/archivo.sql"; .venv/Scripts/python evaluacion_empirica.py --llm ollama --modelo qwen2.5:7b
```
