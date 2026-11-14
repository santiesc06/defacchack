# Decisiones de diseño — Context Firewall Zero-Trust para pagos desde correo

> Documento para revisión y autorización del equipo. Fuente de verdad: `Modelo_gobernanza_matriz_permisos.docx`
> (Matrices 1–4) y `Paquete_documentacion_ISO.docx` (política, procedimiento de 9 pasos, SoA, evaluación de
> impacto, informe por corte). Criterio de evaluación: las 4 preguntas del jurado (vector de riesgo, mecanismo
> defensivo, validación empírica, límites y doble uso).

**Principio rector (no negociable):** un correo nunca autoriza nada: solo abre una solicitud. Los agentes preparan
y verifican; las personas firman; el pago solo ocurre cuando el PEP determinista comprueba firmas y políticas.

Estado de cada decisión: ✅ autorizada por el equipo · 🟡 propuesta, pendiente de autorización (lo implementado
es la opción recomendada; cambiarla es configuración, no reescritura).

---

## 1. Decisiones ya autorizadas

### D1 ✅ Orquestación multiagente con LangChain + LangGraph
- `langgraph.StateGraph` con estado tipado (`TypedDict` cuyos campos son modelos Pydantic congelados).
- Nodos: `recepcionista → sanitizer → orquestador → (financiero → gateway_pep → explicador) | cierre`.
- Arista condicional en el Orquestador: si la tarea no es financiera, el grafo termina **sin instanciar** al
  Agente Financiero (mínimo privilegio, ISO 27001 5.15 / 8.2; ahorro de tokens).
- Herramientas como `langchain_core.tools.StructuredTool` con `args_schema` Pydantic v2 y
  `ConfigDict(extra="forbid", frozen=True)`: un campo extra (p. ej. `"nota": "ignora las reglas"`) hace fallar la
  validación antes de ejecutar nada.

### D2 ✅ PEP híbrido: motor determinista + Human-in-the-Loop
- **Capa 1 — motor de reglas en código puro (sin LLM)** (`firewall/pep.py`). Intercepta *toda* invocación de
  herramienta del Agente Financiero (`ToolGateway`). Evalúa la Matriz 3 en orden fijo:

  | Orden | Regla (Matriz 3) | Decisión |
  |---|---|---|
  | R0 | Integridad: herramienta permitida para el agente (Matriz 1), argumentos válidos, sello de etiquetas intacto | BLOQUEADA |
  | R1 | Proveedor no registrado o cuenta distinta a la del maestro | BLOQUEADA + alerta |
  | R2 | Sanitizer marca riesgo ALTO | BLOQUEADA + alerta |
  | R3 | Falla SPF/DKIM/DMARC, dominio parecido o dominio distinto al registrado del proveedor | BLOQUEADA + alerta |
  | R4 | Pago duplicado (misma factura, o mismo beneficiario + monto) | RECHAZADA |
  | R5 | Sin factura u orden de compra que lo respalde | RECHAZADA (devuelta a CxP) |
  | R9 | Cuenta del proveedor modificada < 30 días | Analista + Tesorero + Director + verificación telefónica |
  | R8 | Válido, > $20.000.000 | Analista + Tesorero + Director |
  | R7 | Válido, riesgo MEDIO o entre $2.000.000 y $20.000.000 | Analista + Tesorero + verificación telefónica |
  | R6 | Válido, riesgo BAJO, ≤ $2.000.000 | Analista + Tesorero |

  El PEP **no confía en el Orquestador**: vuelve a consultar por sí mismo (solo lectura) el maestro de
  proveedores, las OC y el historial. La validación del Orquestador se muestra al humano, pero no decide.
- **Capa 2 — escalada humana.** Si la solicitud supera R0–R5, el PEP **no ejecuta**: la deja en
  `PENDIENTE_FIRMA_1` (`pending_approval = true`). Cada firma exige PIN (MFA simulado), rol correcto en el orden
  del procedimiento (Analista → Tesorero → Director) y segregación de funciones (Matriz 2):
  - firmantes distintos; ninguno es quien inició la solicitud;
  - quien aprobó el cambio de cuenta de ese proveedor no firma pagos a él durante 30 días;
  - administradores de plataforma no firman; ningún agente de IA firma (no existe herramienta de aprobación).
  - La firma es `HMAC-SHA256(llave_firmante, id | sha256(beneficiario|cuenta|monto) | timestamp)`. Si cualquiera
    de esos campos cambia, la firma deja de valer. Las firmas vencen a las 48 h (`EXPIRADA`).
  - Con todas las firmas, el PEP **re-verifica** firmas y SoD y solo entonces emite una orden firmada al
    `ServicioPagosMock`, que rechaza cualquier orden sin la firma del PEP.
  - Botón **No aprobar / Rechazar** disponible para Analista, Tesorero y Director. Si la decisión es BLOQUEADA, el
    botón Aprobar se deshabilita; solo el Oficial de Seguridad puede registrar la revisión del incidente.

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

---

## 2. Puntos abiertos — opciones propuestas para autorizar

### P1 🟡 Proveedor / modelo de LLM
| Opción | Pros | Contras |
|---|---|---|
| **A (recomendada, implementada por defecto): simulador local determinista** (`CFZT_LLM=local`) | Demo offline sin fallos de red, benchmark 100 % reproducible, costo 0 | No mide la susceptibilidad de un modelo real |
| B: Groq + Llama 3.x (`CFZT_LLM=groq`, `GROQ_API_KEY`, `CFZT_LLM_MODEL`) | Latencia muy baja, tool-calling y salida estructurada | Requiere red y llave; cuotas |
| C: Gemini Flash (`CFZT_LLM=gemini`, `GOOGLE_API_KEY`, `CFZT_LLM_MODEL`) | Salida estructurada nativa, cuota gratuita | Requiere red y llave |

Con B o C, **cualquier error de red o de validación cae automáticamente al simulador local** y queda registrado
en la traza (`fallback_local`). El PEP nunca usa LLM, así que la seguridad no depende de la opción elegida.
Dependencias opcionales en `requirements-llm.txt`.

### P2 🟡 Persistencia del registro de auditoría
| Opción | Pros | Contras |
|---|---|---|
| **A (recomendada, implementada): JSON Lines append-only + cadena SHA-256** (`runtime/audit_log.jsonl`) | Legible por un auditor, `verificar()` recalcula la cadena, exportable | No hay control de acceso del SO (límite declarado) |
| B: SQLite con trigger que prohíbe UPDATE/DELETE + misma cadena | Consultas SQL, transacciones | Un admin con acceso al archivo puede quitar el trigger |
| C: A + anclaje periódico del último hash en un sistema externo (WORM/S3 Object Lock) | Detecta truncamiento, no solo alteración | Fuera del alcance de la hackatón |

`hash_actual = sha256(hash_anterior + json_canónico(evento))`. El endpoint `/api/auditoria/verificar` y el botón
de la UI recalculan toda la cadena; el botón «Simular manipulación» altera una entrada para demostrar detección.

### P3 🟡 Frontend y sistema visual
| Opción | Pros | Contras |
|---|---|---|
| **A (recomendada, implementada): HTML + CSS + JS vanilla servido por FastAPI** | Cero build, funciona offline, un solo comando | Menos componentes reutilizables |
| B: React + Vite + Tailwind | Ecosistema, componentes | Paso de build, CDN o node_modules en la demo |

Sistema visual «cliente de correo fintech»: fondo papel (`#F3F5F8`), tinta azul marino (`#0F1B2D`), acento
institucional (`#1D4ED8`); semántica de estado fija: verde = ejecutada/segura, ámbar = pendiente de firma,
rojo = bloqueada, gris = aislado/en reposo. Tipografía Inter (con fallback de sistema) y monoespaciada para
hashes, montos y JSON.

### P4 🟡 Línea base «PEP DESACTIVADO» (confianza implícita)
Propuesta: con el interruptor apagado, la herramienta `solicitar_ejecucion_pago` va directo al servicio de pagos
(sin reglas, sin firmas, sin explicador). Los agentes siguen siendo los mismos. Es una **cota superior de
vulnerabilidad**: modela el agente que ejecuta lo que extrajo, no la conducta exacta de un modelo comercial. Se
declara así en el README. Además se mide una **ablación** «PEP sin Sanitizer» para cuantificar cuánto depende la
defensa del Sanitizer semántico.

### P5 🟡 Datos y credenciales de demo
Todo es sintético (`firewall/data/seed.py`): 4 proveedores, 5 OC, historial de pagos, 9 personas con los roles de
la Matriz 2. Los PIN de demo son públicos en la UI a propósito (no son credenciales reales). Saldo inicial
$250.000.000 COP. Umbrales de la Matriz 3 en `firewall/config.py`.

---

## 3. Estructura de carpetas

```
defaihack/
├── DECISIONES_DISENO.md        ← este documento
├── README.md                   ← resumen ejecutivo + 4 preguntas del jurado + trazabilidad ISO
├── start.py                    ← un solo comando: crea .venv, instala y arranca
├── requirements.txt            ← dependencias núcleo (LangGraph, LangChain Core, Pydantic, FastAPI)
├── requirements-llm.txt        ← opcionales: Groq / Gemini
├── evaluacion_empirica.py      ← benchmark ON / OFF / ablación → reports/
├── firewall/
│   ├── config.py               ← umbrales Matriz 3, roles, constantes
│   ├── schemas.py              ← contratos Pydantic (extra="forbid", frozen)
│   ├── data/seed.py            ← maestro, OC, historial, personas (sintético)
│   ├── repositorio.py          ← vistas de solo lectura del maestro/OC/historial
│   ├── audit.py                ← AuditLogSHA256
│   ├── pagos.py                ← ServicioPagosMock (solo órdenes firmadas por el PEP)
│   ├── llm.py                  ← proveedor LLM (local / Groq / Gemini con fallback)
│   ├── prompts_gobernanza.py   ← system prompts derivados de ISO 27001/42001 y Matriz 1
│   ├── sanitizer.py            ← ContextSanitizer (reglas + clasificador semántico)
│   ├── agentes.py              ← Recepcionista, Orquestador, Financiero, Explicador
│   ├── herramientas.py         ← tools Pydantic + ToolGateway
│   ├── pep.py                  ← PolicyEnforcementPoint (Matriz 3 + Matriz 2)
│   ├── grafo.py                ← StateGraph de LangGraph
│   ├── escenarios.py           ← 17 escenarios con verdad de terreno
│   ├── servicio.py             ← fachada: estado, KPIs, firmas
│   └── api.py                  ← FastAPI
├── frontend/                   ← index.html, styles.css, app.js
├── tests/                      ← pytest (reglas PEP, SoD, auditoría, API, benchmark)
├── reports/                    ← salida de evaluacion_empirica.py
└── cfzt/                       ← incremento 1 previo (PEP por autorización de tarea), se conserva con sus pruebas
```

## 4. Qué NO hace el MVP (alcance)
Sin bancos reales, sin SSO real (PIN = MFA simulado), sin verificación telefónica real (casilla de constancia),
sin análisis antimalware de adjuntos (adjunto = texto simulado), un solo proceso en memoria.
