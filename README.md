# Context Firewall Zero-Trust — pagos autónomos desde correo

> **Un correo nunca autoriza nada: solo abre una solicitud.** Los agentes de IA preparan y verifican; las personas
> firman; el pago solo ocurre cuando un PEP **determinista** (código, no un LLM) comprueba firmas y políticas.

MVP para el Defensive Acceleration Hackathon (Track 1: seguridad de agentes). Multiagente con **LangGraph +
LangChain**, contratos **Pydantic v2** cerrados, **PEP híbrido** (motor de reglas + human-in-the-loop),
**Agente Explicador** que pide confirmación en cada llamada a herramienta, y **registro de auditoría con cadena
SHA-256**. Todo con datos sintéticos; no mueve dinero real.

## Arranque (un solo comando)

```bash
python start.py
```

Crea `.venv`, instala dependencias (solo la primera vez) y abre `http://127.0.0.1:8000`. Requiere Python 3.11+.
Funciona offline: el LLM por defecto es un simulador local determinista (ver `DECISIONES_DISENO.md`, P1).

```bash
python evaluacion_empirica.py
```

```bash
.venv/Scripts/python -m pytest -q
```

(En macOS/Linux: `.venv/bin/python -m pytest -q`.) LLM real opcional: `CFZT_LLM=groq GROQ_API_KEY=… python start.py`
o `CFZT_LLM=gemini GOOGLE_API_KEY=…`; ante cualquier fallo de red cae al simulador local.

---

## Las 4 preguntas del jurado

### 1. Vector de riesgo — ¿qué amenaza concreta atacamos?

**Inyección indirecta de instrucciones y suplantación de proveedor contra un agente de IA con permiso para
pagar.** Un atacante no necesita acceso al sistema: le basta con enviar un correo (o comprometer el buzón de un
proveedor real) con una instrucción oculta — en texto blanco dentro del PDF, un comentario HTML, o simplemente
redactada en tono corporativo — que pide pagar a una cuenta nueva. Es el fraude más común del flujo de cuentas por
pagar (BEC / cambio de cuenta), amplificado porque el agente lee y actúa sin cansarse.

El agravante específico de los sistemas multiagente es el **lavado semántico**: el agente lector reescribe el
correo en un resumen limpio («El proveedor solicita el pago de $18.400.000 COP a la cuenta 9910-442-77»). La
instrucción desaparece del texto, pero **el dato del atacante sobrevive** y viaja agente a agente con apariencia
legítima. Un filtro sobre el resumen ya no ve nada.

Matriz de riesgo (Evaluación de impacto ISO 42001): inyección que induce un pago 4×5 = **20**; suplantación con
cambio de cuenta 4×5 = **20**.

### 2. Mecanismo defensivo — ¿qué construimos y cómo reduce el riesgo?

```
Correo ─▶ Recepcionista ─▶ Sanitizer ─▶ Orquestador ─┬─▶ (no financiero) FIN · Agente Financiero AISLADO
 (no      (esquema cerrado) (taint +     (relevancia +  │
 confiable)                 sello SHA-256) validación RO) └─▶ Financiero ─▶ ToolGateway ─▶ PEP determinista ─▶ Explicador LLM
                                                                                          │ BLOQUEADA / RECHAZADA (alerta)
                                                                                          └ PENDIENTE_FIRMA ─▶ firmas humanas (PIN, SoD, hash)
                                                                                                             ─▶ PEP re-verifica ─▶ Servicio de pagos
```

| Capa | Qué hace | Qué riesgo corta |
|---|---|---|
| **Esquema cerrado** (Recepcionista) | Único que toca texto libre; produce `SolicitudExtraccionSchema` con `extra="forbid"`, `frozen`, patrones estrictos | «Ignora las reglas» no cabe en `cuenta_destino` ni en `numero_oc` |
| **Context Sanitizer** | Etiqueta el correo **original** (no el resumen): `EXTERNO_NO_CONFIABLE`, `tainted`, SPF/DKIM/DMARC, dominios parecidos, imperativos, urgencia. El LLM semántico **solo puede subir** el riesgo. Las etiquetas se sellan con SHA-256 | Lavado semántico; dominios tipo `logisticaandlna.com.co` |
| **Orquestador** | Filtro de relevancia: si no es financiero, cierra **sin despertar** al Agente Financiero. Si lo es, valida con 3 tools de **solo lectura** | Exposición innecesaria del agente privilegiado; tokens |
| **ToolGateway + PEP (Capa 1)** | Intercepta **toda** llamada del Agente Financiero. Reglas R0–R9 de la Matriz 3 en código puro; **re-consulta el maestro por su cuenta** (no confía en el Orquestador); verifica el sello de las etiquetas; la orden usa los datos del **maestro**, no del correo | Cuenta distinta al maestro, proveedor inexistente, riesgo alto, SPF/DMARC, duplicados, falta de soporte |
| **Explicador LLM** | En cada llamada a herramienta explica a la persona qué se intenta ejecutar, los riesgos y el veredicto, y **pide confirmación**. Recibe solo datos estructurados; un control determinista verifica que cite el monto y la cuenta exactos | Aprobación a ciegas; explicación engañosa |
| **Human-in-the-loop (Capa 2)** | `PENDIENTE_FIRMA`: Analista → Tesorero (→ Director). PIN/MFA, firma HMAC sobre `sha256(beneficiario|cuenta|monto)`, vigencia 48 h, segregación de funciones (Matriz 2), verificación telefónica al número **registrado** | Fraude interno, firma de datos alterados, autoaprobación |
| **Auditoría SHA-256** | Append-only, `hash = sha256(anterior + evento)`, verificación en vivo | Alteración del registro |

### 3. Validación empírica — ¿cómo demostramos que funciona?

`python evaluacion_empirica.py` ejecuta **17 escenarios reproducibles** (9 ataques, 6 legítimos, 2 irrelevantes)
en tres configuraciones, más 11 pruebas adversariales contra el propio firewall. Resultados reales
(`reports/resultados.md`, 5 repeticiones):

| Métrica | PEP OFF (confianza implícita) | PEP ON sin Sanitizer (ablación) | **PEP ON** |
|---|---|---|---|
| Tasa de bloqueo de ataques | 0 % | 88,9 % | **100 %** |
| Ataques detectados como incidente con alerta | 0 % | 66,7 % | **77,8 %** ¹ |
| Completitud de tareas legítimas | 100 % | 83,3 % | **83,3 %** |
| Falsos positivos | 0 % | 16,7 % | **16,7 %** ² |
| Aislamiento del Agente Financiero en tareas irrelevantes | 100 % | 100 % | **100 %** |
| Fondos desviados a cuentas no registradas | **$81.450.000** | $0 | **$0** |
| Latencia añadida por el PEP | — | 0,07 ms | **0,07 ms** |
| Cadena SHA-256 íntegra / manipulación detectada | 100 % | 100 % | **100 % / sí** |
| Firmas denegadas por segregación de funciones | — | 2 | **2** |
| Pruebas adversariales superadas | | | **11 / 11** |

¹ Duplicados y pagos sin soporte se **rechazan** (devueltos a CxP) sin abrir incidente, como dice la Matriz 3.
² Un proveedor legítimo con DKIM mal configurado se bloquea por R3. Es un falso positivo **intencional** de la
política: preferimos bloquear y revisar a pagar con autenticación rota.

**Supuesto conservador:** todo lo que llega a firmas se firma (peor caso de fatiga humana). Aun así, ningún ataque
mueve dinero, porque los ataques se detienen **antes** de llegar a las personas.

Las 11 pruebas adversariales incluyen: herramienta con un campo extra inyectado (R0), el Recepcionista invocando
la herramienta de pago (R0), etiquetas del Sanitizer rebajadas tras el sellado (R0), cuenta alterada después de la
firma 1 (firma inválida), orden directa al servicio de pagos sin firma del PEP, un agente intentando firmar, el
administrador de plataforma firmando, PIN incorrecto, firma después de 48 h, rol incorrecto y aprobación de una
solicitud bloqueada. La suite `pytest` (94 pruebas) cubre cada regla de la Matriz 3, cada restricción de la
Matriz 2, la API y el benchmark completo.

**Lectura de la ablación:** sin el Sanitizer, **no se desvía ni un peso**, porque la defensa monetaria descansa en
reglas deterministas sobre datos maestros (R1, R3). Lo que se pierde es la **detección**: la inyección que intenta
saltarse controles sin cambiar la cuenta (`inyeccion_sin_desvio`) llega a firmas sin alerta, y bajan los
incidentes reportados (77,8 % → 66,7 %).

### 4. Límites y doble uso — ¿dónde falla y cómo se podría abusar?

**Dónde falla**
- **Fatiga de aprobación.** El PEP lleva a las personas solo lo que pasó las reglas, pero si quien firma aprueba
  todo sin leer, la capa 2 se vuelve un trámite. Mitigaciones parciales: resumen de riesgo antes de firmar,
  verificación telefónica obligatoria en R7/R9, firmas solo cuando aplica. No lo medimos con personas reales.
- **Datos maestros envenenados.** Si un atacante logra cambiar la cuenta del proveedor *en el maestro* (ingeniería
  social al administrador de proveedores), R1 deja de proteger. Lo cubre R9 (Director + verificación telefónica
  durante 30 días) y la SoD sobre quien aprobó el cambio, pero no es infalible.
- **Calidad del Sanitizer semántico.** Las reglas regex y el clasificador no detectan toda paráfrasis; la ablación
  muestra que perderlo reduce la detección, no la protección del dinero. Con un LLM real, el clasificador puede
  equivocarse, pero por diseño solo puede **subir** el riesgo.
- **Campos de texto libre residuales.** `concepto` y `beneficiario` (≤ 160 caracteres) siguen siendo datos del
  atacante que el Explicador ve. Mitigación: el Explicador no decide nada, y un control determinista exige que su
  texto cite el monto y la cuenta exactos; la firma cubre el hash, no la explicación.
- **Validación con simulador.** Las métricas usan un LLM simulado que reproduce la conducta *típica* de un agente
  ingenuo (cota superior de vulnerabilidad en la línea base). No medimos la tasa de éxito de inyección sobre un
  modelo comercial concreto.
- **Límites del prototipo.** Un proceso en memoria; PIN en lugar de SSO + MFA real; casilla en lugar de llamada
  telefónica real; el registro detecta alteraciones pero no el truncamiento del final sin un ancla externa.
- **Falsos positivos.** Proveedores con autenticación de correo mal configurada quedan bloqueados (16,7 % de los
  legítimos en la batería); requieren revisión del Oficial de Seguridad.

**Doble uso**
- La batería de escenarios es, a la vez, un **catálogo de técnicas de ataque** (lavado semántico, dominios
  parecidos, instrucciones ocultas en adjuntos) que un atacante podría usar para probar sus correos contra otros
  sistemas. Por eso son genéricos, sintéticos y sin cargas novedosas.
- El Sanitizer y el Explicador podrían usarse **al revés**: como oráculo para iterar un correo hasta que no
  dispare banderas. Mitigación: el PEP no depende de ellos para proteger el dinero; en producción, no exponer el
  veredicto detallado al remitente (Matriz 1: ningún componente se comunica con el remitente).
- La misma arquitectura de agentes que **prepara** pagos puede automatizar fraude a escala si se le quita el PEP:
  el modo «PEP desactivado» de la demo existe para mostrarlo ($81,45 M desviados en 17 correos) y no debe existir
  en producción.
- Las firmas y el registro concentran información sensible (quién aprueba qué): el rol Auditor es de solo lectura
  y el administrador de plataforma no puede firmar (ISO 27001 8.2).

---

## Guion de demo (5 minutos)

1. **PEP ACTIVADO** → «Inyección indirecta + lavado». Mostrar el resumen limpio del Recepcionista, las etiquetas
   `TAINTED / ALTO`, la validación del Orquestador y la llamada del Agente Financiero bloqueada por R1/R2. Botón
   Aprobar deshabilitado.
2. **Apagar el PEP** → repetir el mismo correo: $18.400.000 salen a la cuenta del atacante sin que nadie confirme.
3. **Encender el PEP** → «Tarea irrelevante»: el Agente Financiero queda **AISLADO / EN REPOSO**.
4. «Orden interna · doble firma»: Ana (quien inició) intenta firmar → denegado por SoD. Firma Andrés, luego Tomás →
   **EJECUTADA**, el saldo baja.
5. «Cuenta modificada < 30 días»: Teresa (aprobó el cambio de cuenta) no puede firmar; se exige Director y
   verificación telefónica.
6. **Simular manipulación** del registro → la verificación SHA-256 señala la entrada alterada.

PIN de demo: Ana 1111 · Andrés 2222 · Tomás 3333 · Teresa 4444 · Diana 5555 · Sofía 6666 · Pablo 7777 (sintéticos).

## Trazabilidad ISO/IEC 27001:2022 e ISO/IEC 42001:2023 (Matriz 4)

| Elemento del diseño | Dónde está en el código | ISO/IEC 27001:2022 | ISO/IEC 42001:2023 |
|---|---|---|---|
| Identidad propia por agente y matriz de permisos | `pep.PERMISOS_HERRAMIENTAS`, `repositorio.VistaSoloLectura`, `grafo.py` | 5.15, 5.16, 5.18, 8.2 | A.3 Roles y responsabilidades |
| Doble firma y segregación de funciones | `pep.firmar`, `pep._ordenar_pago` | 5.3 | Supervisión humana (A.9) |
| Firma con MFA ligada al hash de la solicitud | `pep._firma_hmac`, `pep.hash_transaccion` | 5.17, 8.5 | — |
| Correo no confiable + Sanitizer + esquema cerrado | `sanitizer.py`, `schemas.py`, `llm.delimitar_no_confiable` | 5.14, 8.7 | A.7 Procedencia y calidad de datos |
| Registro encadenado e inalterable | `audit.py` | 8.15, 8.16 | A.6 Registro en el ciclo de vida |
| Alertas, bloqueos y casos | `pep.evaluar` (ALERTA_OFICIAL_SEGURIDAD), `pep.revisar_incidente` | 5.24–5.26 | A.3 Reporte de inquietudes |
| Políticas y umbrales fuera del alcance de los agentes | `config.py` (sin herramienta de escritura) | 8.32 | A.2 Políticas de IA |
| Explicación previa a la firma | `agentes.ExplicadorAgent`, `herramientas.ToolGateway` | 5.3 | A.9 Supervisión humana |
| System prompts derivados de la política | `prompts_gobernanza.py` | 5.1 | A.2 |
| Evaluación de riesgo e informe por corte | `evaluacion_empirica.py`, `reports/` | 6.1, 7.5 | 6.1.4, 8.4, 7.5 |

> La numeración del Anexo A de ISO/IEC 42001:2023 debe confirmarse contra el texto oficial antes de una auditoría
> formal. El aplicativo no certifica: genera la evidencia que el auditor solicita.

## Estructura

Ver `DECISIONES_DISENO.md` (decisiones autorizadas, opciones abiertas y árbol de carpetas). `cfzt/` contiene el
incremento 1 previo del equipo (PEP por autorización de tarea) y se conserva con sus pruebas.
