# Decisiones de diseño — Context Firewall Zero-Trust (núcleo universal + Policy Packs)

> Documento para revisión y autorización del equipo. Fuente de verdad: `Modelo_gobernanza_matriz_permisos.docx`
> (Matrices 1–4) y `Paquete_documentacion_ISO.docx` (política, procedimiento de 9 pasos, SoA, evaluación de
> impacto, informe por corte). Criterio de evaluación: las 4 preguntas del jurado (vector de riesgo, mecanismo
> defensivo, validación empírica, límites y doble uso).

**Principio rector (no negociable):** un mensaje externo (correo, issue, ticket) nunca autoriza nada: solo abre una
solicitud. Los agentes preparan y verifican; una persona firma; la acción solo ocurre cuando el PEP determinista
comprueba la firma y las políticas.

Estado de cada decisión: ✅ autorizada por el equipo · 🟡 propuesta, pendiente de autorización (lo implementado
es la opción recomendada; cambiarla es configuración, no reescritura).

---

## 1. Decisiones ya autorizadas

### D1 ✅ Orquestación multiagente con LangChain + LangGraph
- `langgraph.StateGraph` con estado tipado (`TypedDict` cuyos campos son modelos Pydantic congelados).
- Nodos genéricos, iguales en todos los dominios: `ingesta_estructurada → sanitizer → orquestador → ejecutor →
  herramientas_pep` (en `herramientas_pep` el ToolGateway somete la llamada al PEP y luego al Explicador).
- Arista condicional en el Orquestador: si el mensaje no pide ninguna acción, el grafo termina **sin instanciar**
  al agente ejecutor (mínimo privilegio, ISO 27001 5.15 / 8.2; ahorro de tokens).
- Los prompts, esquemas y herramientas de cada nodo los aporta el Policy Pack activo (D4).
- Herramientas como `langchain_core.tools.StructuredTool` con `args_schema` Pydantic v2 y
  `ConfigDict(extra="forbid", frozen=True)`: un campo extra (p. ej. `"nota": "ignora las reglas"`) hace fallar la
  validación antes de ejecutar nada.

### D2 ✅ PEP híbrido: motor determinista + Human-in-the-Loop
- **Capa 1 — motor de reglas en código puro (sin LLM)**. Intercepta *toda* invocación de herramienta del agente
  ejecutor (`ToolGateway`). Primero corre el núcleo universal U0–U4 (D4) y después las reglas del pack. Para el pack
  de pagos (`firewall/packs/pagos_iso42001.py`), la Matriz 3 en orden fijo:

  | Orden | Regla (Matriz 3) | Decisión |
  |---|---|---|
  | R0 | Integridad: herramienta permitida para el agente (Matriz 1), argumentos válidos, sello de etiquetas intacto | BLOQUEADA |
  | R1 | Proveedor no registrado o cuenta distinta a la del maestro | BLOQUEADA + alerta |
  | R2 | Sanitizer marca riesgo ALTO | BLOQUEADA + alerta |
  | R3 | Falla SPF/DKIM/DMARC, dominio parecido o dominio distinto al registrado del proveedor | BLOQUEADA + alerta |
  | R4 | Pago duplicado (misma factura, o mismo beneficiario + monto) | RECHAZADA |
  | R5 | Sin factura u orden de compra que lo respalde | RECHAZADA (devuelta a CxP) |
  | R9 | Cuenta del proveedor modificada < 30 días | Firma el **Director financiero** + verificación telefónica |
  | R8 | Válido, > $20.000.000 | Firma el **Director financiero** |
  | R7 | Válido, riesgo MEDIO o entre $2.000.000 y $20.000.000 | Firma un **Tesorero** + verificación telefónica |
  | R6 | Válido, riesgo BAJO, ≤ $2.000.000 | Firma un **Tesorero** |

  En el pack `devops_cloud`, las reglas D1–D5 cumplen el mismo papel:
  - **D1**: acción destructiva o exposición pública pedida desde una fuente externa → BLOQUEADA + alerta.
  - **D2**: instrucción inyectada en logs o adjuntos → BLOQUEADA + alerta.
  - **D3**: cambio válido en staging → firma un **DevOps senior**.
  - **D4**: cambio válido en producción → firma el **Líder SRE**.
  - **D5**: recurso fuera del catálogo o sin ticket aprobado por el CAB → RECHAZADA.

  El PEP **no confía en el Orquestador**: vuelve a consultar por sí mismo (solo lectura) el maestro de
  proveedores, las OC y el historial. La validación del Orquestador se muestra al humano, pero no decide.
- **Capa 2 — escalada humana con una sola firma.** Si la solicitud supera las reglas de bloqueo y rechazo, el PEP
  **no ejecuta**: la deja en `PENDIENTE_FIRMA_1` (`pending_approval = true`). Firma **una sola persona**: la del rol
  que exige la regla (Tesorero o Director; DevOps senior o Líder SRE). Decisión del equipo: varias firmas en
  cadena multiplicaban la fatiga de aprobación sin agregar una verificación distinta; el umbral sube el rol en vez
  de sumar firmantes. La firma exige PIN (MFA simulado), el rol correcto y segregación de funciones (U4 / Matriz 2):
  - quien inició la solicitud no la firma;
  - quien aprobó el cambio de cuenta de ese proveedor no firma pagos a él durante 30 días;
  - administradores de plataforma no firman; ningún agente de IA firma (no existe herramienta de aprobación).
  - La firma es `HMAC-SHA256(llave_firmante, id | sha256(beneficiario|cuenta|monto) | timestamp)`. Si cualquiera
    de esos campos cambia, la firma deja de valer. Las firmas vencen a las 48 h (`EXPIRADA`).
  - Con la firma, el PEP **re-verifica** firma, SoD y hash sobre los datos actuales y solo entonces emite una orden
    firmada al servicio del pack (`ServicioPagosMock` o el plano de control simulado), que rechaza cualquier orden
    sin la firma del PEP.
  - Botón **No aprobar** (con PIN, queda en el registro) para Analista, Tesorero, Director, Oficial de Seguridad,
    DevOps senior y Líder SRE. Si la decisión es BLOQUEADA, Firmar se deshabilita; solo el Oficial de Seguridad
    puede registrar la revisión del incidente.

### D3 ✅ Explicador LLM en cada llamada a herramienta del Agente Financiero (solicitado por el equipo)
Cada vez que el Agente Financiero invoca una herramienta, el `ToolGateway` (1) la somete al PEP y (2) pide a un
**Agente Explicador** un resumen en lenguaje natural de *qué se intenta ejecutar, qué riesgos hay y qué decidió el
PEP*, que termina con una **pregunta de confirmación** al trabajador (o, si está bloqueada, con la indicación de
que solo el Oficial de Seguridad puede escalar). Salvaguardas:
- El Explicador **solo recibe datos estructurados** (propuesta, etiquetas, veredicto), nunca el texto del correo:
  no puede ser inyectado por el remitente.
- Su texto es **solo informativo**: la firma cubre el hash de los datos verificados, no la explicación.
- Control de coherencia determinista: si la explicación no menciona el monto y la cuenta exactos, la UI la marca
  como «no coherente» y el humano debe guiarse por el bloque «Datos verificados por el PEP».

### D4 ✅ Núcleo Zero-Trust universal + Policy Packs (escalabilidad)
- **Núcleo (`cfzt/`)**, sin conocimiento de ningún dominio:
  - `ContextEnvelope`: todo mensaje externo con su canal y su autenticación de origen.
  - `ToolManifest`: cada herramienta con su `NivelImpacto`.
  - `UniversalPEP`: reglas U0–U4.
  - `hash_accion`: hash canónico de cualquier acción.
  - `AuditLogSHA256`: registro encadenado.
- **Policy Pack (`firewall/packs/base.py`)**: interfaz con manifiestos, fuentes de verdad de solo lectura, reglas de
  negocio, quién firma (`firmas_requeridas`, `verificar_firmante`), el servicio que ejecuta órdenes firmadas,
  prompts, escenarios y KPI de daño.
- Packs implementados: `pagos_iso42001` (por defecto) y `devops_cloud`. La API (`POST /api/pack`) y la interfaz
  (pestañas Pagos / Cloud) cambian el dominio en vivo.
- Compatibilidad: en pagos, U0/U1/U2 se reportan como R0/R2/R3 para no romper la Matriz 3 ni las pruebas existentes.

### D5 ✅ Interfaz: prototipo de diseño conectado a la API
`frontend/index.html` conserva estilos, íconos y estructura de `diseno/entregable3_prototipo.html`; `frontend/app.js`
reemplaza los datos ilustrativos por la API real. Todo lo que muestra sale del backend:
- solicitudes y trazas del grafo;
- veredictos del PEP y explicación del Explicador;
- firmas con PIN contra el PEP;
- registro SHA-256 y su verificación;
- último reporte del benchmark.

Se agregaron el selector de dominio y un «Panel de pruebas» (enviar escenarios, cambiar de modo, simular intruso,
reiniciar). La UI decide qué botones mostrar, pero el PEP vuelve a verificar todo en el servidor.

---

## 2. Puntos abiertos — opciones propuestas para autorizar

### P1 🟡 Proveedor / modelo de LLM
| Opción | Pros | Contras |
|---|---|---|
| **A (elegida por el equipo, en `.env.example`): Ollama local** (`CFZT_LLM=ollama`, `CFZT_LLM_MODEL=qwen2.5:7b`) | Modelo real sin red ni API key; los correos no salen de la máquina; mide la susceptibilidad real a inyección | Lento en CPU (cerca de un minuto por correo); modelos pequeños fallan más en salida estructurada |
| Simulador local determinista (`CFZT_LLM=local`, valor sin `.env`) | Benchmark 100 % reproducible, pruebas automáticas, costo 0 | No mide la susceptibilidad de un modelo real |
| B: Groq + Llama 3.x (`CFZT_LLM=groq`, `GROQ_API_KEY`, `CFZT_LLM_MODEL`) | Latencia muy baja, tool-calling y salida estructurada | Requiere red y llave; cuotas |
| C: Gemini Flash (`CFZT_LLM=gemini`, `GOOGLE_API_KEY`, `CFZT_LLM_MODEL`) | Salida estructurada nativa, cuota gratuita | Requiere red y llave |

**Modo estricto** (`CFZT_LLM_ESTRICTO=1`, por defecto): si el modelo falla (red, formato, validación), la solicitud
queda en `FALLO_MODELO`, no se ejecuta nada y **nunca** se usa el simulador. En el benchmark, ese escenario se
excluye de todas las configuraciones y se reporta aparte. Con `CFZT_LLM_ESTRICTO=0` (o `--permitir-respaldo`) los
fallos caen al simulador y se cuentan por separado. El PEP nunca usa LLM, así que la seguridad no depende de la
opción elegida.
Dependencias opcionales en `requirements-llm.txt`.

### P2 🟡 Persistencia del registro de auditoría
| Opción | Pros | Contras |
|---|---|---|
| **A (recomendada, implementada): JSON Lines append-only + cadena SHA-256** (`runtime/audit_log.jsonl`) | Legible por un auditor, `verificar()` recalcula la cadena, exportable | No hay control de acceso del SO (límite declarado) |
| B: SQLite con trigger que prohíbe UPDATE/DELETE + misma cadena | Consultas SQL, transacciones | Un admin con acceso al archivo puede quitar el trigger |
| C: A + anclaje periódico del último hash en un sistema externo (WORM/S3 Object Lock) | Detecta truncamiento, no solo alteración | Fuera del alcance de la hackatón |

`hash_actual = sha256(hash_anterior + json_canónico(evento))`. El endpoint `/api/auditoria/verificar` y el botón
de la UI recalculan toda la cadena; el botón «Simular manipulación» altera una entrada para demostrar detección.

### P3 ✅ Frontend y sistema visual
HTML + CSS + JS vanilla servido por FastAPI (cero build, funciona offline). El sistema visual es el del prototipo
del equipo (`diseno/entregable3_prototipo.html`, tema claro y oscuro); ver D5.

### P4 🟡 Línea base «Sin defensa» (confianza implícita)
Propuesta: en el modo `SIN_DEFENSA`, la herramienta crítica del pack va directo al servicio (sin reglas, sin firmas,
sin explicador). Los agentes siguen siendo los mismos. Es una **cota superior de
vulnerabilidad**: modela el agente que ejecuta lo que extrajo, no la conducta exacta de un modelo comercial. Se
declara así en el README. Además se mide una **ablación** «PEP sin Sanitizer» para cuantificar cuánto depende la
defensa del Sanitizer semántico.

### P4b ✅ Configuraciones de comparación (pedido del equipo)
Para comprobar que cada componente funciona por sí solo, el modo (`firewall/config.Modo`) selecciona el control:
`SIN_DEFENSA`, `SOLO_LLM` (un único modelo decide con correo + propuesta + maestro), `SOLO_SANITIZER`,
`SOLO_PEP` y `COMPLETO`. Se implementó como modo dentro de la misma base de código (no como rama de git) para
que las cinco configuraciones corran con los mismos escenarios en una sola tabla. `SOLO_LLM` falla cerrado y
requiere un modelo real.

### P5b ✅ Fuente de datos: base SQL del equipo
El maestro, las OC, el historial y (opcional) las personas se leen de una base SQL que cumpla `db/contrato_cfzt.sql` (tablas o vistas `cfzt_*`), vía `CFZT_DB_URL` (SQLAlchemy) o `CFZT_DB_SQL` (script cargado en SQLite en memoria). Solo lectura; los pagos de prueba quedan en memoria. Los datos de `seed.py` quedan únicamente como respaldo cuando no hay base configurada.

### P5 🟡 Datos y credenciales de demo
Todo es sintético. Pagos: `firewall/data/seed.py` (4 proveedores, 5 OC, historial, 9 personas con los roles de la
Matriz 2) cuando no hay base SQL. DevOps: catálogo de 3 recursos, 5 tickets del CAB y 4 personas propias en
`firewall/packs/devops_cloud.py`. Los PIN de demo son públicos en la UI a propósito (no son credenciales reales).
Umbrales de la Matriz 3 en `firewall/config.py`.

---

## 3. Estructura de carpetas

```
defaihack/
├── DECISIONES_DISENO.md        ← este documento
├── README.md                   ← resumen ejecutivo + 4 preguntas del jurado + trazabilidad ISO
├── start.py                    ← un solo comando: crea .venv, instala y arranca
├── .env.example                ← modelo (Ollama) y base de datos; copiar como .env (no se sube a git)
├── requirements.txt            ← dependencias núcleo (LangGraph, LangChain Core, Pydantic, FastAPI, SQLAlchemy)
├── requirements-llm.txt        ← opcionales: Ollama / Groq / Gemini
├── evaluacion_empirica.py      ← benchmark multi-dominio, 5 configuraciones → reports/
├── cfzt/                       ← NÚCLEO universal
│   ├── contracts.py            ← ContextEnvelope, ToolManifest, NivelImpacto
│   ├── pep.py                  ← UniversalPEP (U0–U4), hash_accion
│   └── ledger.py               ← AuditLogSHA256
├── firewall/
│   ├── packs/
│   │   ├── base.py             ← interfaz PolicyPack
│   │   ├── pagos_iso42001.py   ← R1–R9, maestro, firmante único
│   │   └── devops_cloud.py     ← D1–D5, catálogo, CAB, plano de control simulado, 13 escenarios
│   ├── config.py               ← umbrales, roles, modos, carga del .env
│   ├── schemas.py              ← contratos Pydantic (extra="forbid", frozen)
│   ├── fuente_datos.py         ← lectura de la base SQL (solo lectura)
│   ├── repositorio.py          ← vistas de solo lectura del maestro/OC/historial
│   ├── pagos.py                ← ServicioPagosMock (solo órdenes firmadas por el PEP)
│   ├── llm.py, llm_local.py    ← proveedor LLM (Ollama / Groq / Gemini / simulador), modo estricto
│   ├── prompts_gobernanza.py   ← system prompts por dominio derivados de ISO 27001/42001
│   ├── sanitizer.py            ← ContextSanitizer (reglas + clasificador semántico)
│   ├── agentes.py              ← Recepcionista, Orquestador, Ejecutor, Explicador, Verificador (SOLO_LLM)
│   ├── herramientas.py         ← tools desde los manifiestos + ToolGateway
│   ├── pep.py                  ← PEP del pack sobre el núcleo + flujo de firma
│   ├── grafo.py                ← StateGraph de 5 nodos
│   ├── escenarios.py           ← escenarios de pagos (construidos desde la base si hay SQL)
│   ├── servicio.py             ← fachada: dominio activo, modo, estado, firmas
│   ├── benchmark_resumen.py    ← resumen del último reporte para la UI
│   └── api.py                  ← FastAPI
├── frontend/                   ← index.html (diseño del prototipo) + app.js (conectado a la API)
├── diseno/                     ← prototipo de diseño del equipo
├── db/                         ← contrato SQL y validador de la base de pruebas
├── tests/                      ← pytest (núcleo, packs, firmas, auditoría, API, benchmark, base SQL)
└── reports/                    ← salida de evaluacion_empirica.py
```

## 4. Qué NO hace el MVP (alcance)
Sin bancos ni nube reales (servicio de pagos y plano de control simulados), sin SSO real (PIN = MFA simulado), sin
verificación telefónica real (casilla de constancia), sin análisis antimalware de adjuntos (adjunto = texto
simulado), un solo proceso en memoria.
