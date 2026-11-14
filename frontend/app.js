"use strict";
/* Consola de demo del Context Firewall. Todo texto proveniente del correo se inserta con
   textContent (nunca innerHTML): el contenido externo no puede inyectar HTML en esta UI. */

const $ = (sel) => document.querySelector(sel);
const S = { escenarios: [], usuarios: [], actual: null, estado: null, animando: false };
const SIGNING_ROLES = ["ANALISTA_CXP", "TESORERO", "DIRECTOR_FINANCIERO"];

function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "html") throw new Error("no innerHTML");
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of kids.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
const fill = (el, ...kids) => el.replaceChildren(...kids.flat().filter((k) => k !== null && k !== undefined && k !== false));
const cop = (n) => (typeof n === "number" ? "$" + n.toLocaleString("es-CO") + " COP" : "—");
const short = (hash, n = 12) => (hash ? hash.slice(0, n) + "…" : "—");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" }, ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const d = data.detail;
    throw new Error(typeof d === "string" ? d : Array.isArray(d) ? d.map((x) => `${x.loc?.slice(-1)}: ${x.msg}`).join("; ") : `HTTP ${res.status}`);
  }
  return data;
}

let toastTimer;
function toast(msg, err = false) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast" + (err ? " err" : "");
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), 4200);
}

/* ------------------------------------------------------------------ estado y KPIs */
function setText(id, txt, animate = false) {
  const el = $(id);
  if (el.textContent !== String(txt)) {
    el.textContent = txt;
    if (animate) { el.classList.remove("pop"); void el.offsetWidth; el.classList.add("pop"); }
  }
}

async function refrescarEstado() {
  const e = await api("/api/estado");
  S.estado = e;
  const k = e.kpis;
  setText("#kpiSaldo", cop(e.saldo_cop), true);
  const delta = e.saldo_cop - e.saldo_inicial_cop;
  setText("#kpiSaldoSub", delta ? `${cop(delta)} desde el inicio` : "COP · sin movimientos");
  setText("#kpiBloq", k.ataques_bloqueados, true);
  setText("#kpiBloqSub", `${k.bloqueadas} bloqueadas · ${k.rechazadas} rechazadas`);
  setText("#kpiEvit", k.accesos_evitados, true);
  setText("#kpiAprob", k.operaciones_aprobadas, true);
  setText("#kpiAprobSub", `${k.pendientes_firma} pendientes de firma` + (k.pagos_sin_control ? ` · ${k.pagos_sin_control} sin control` : ""));
  setText("#llmPill", "LLM: " + e.llm);
  setText("#bankSaldo", cop(e.saldo_cop), true);
  setText("#bankDesv", cop(k.fondos_desviados_cop));
  const bp = $("#bankPill");
  bp.textContent = e.pep_activo ? "PROTEGIDO" : "EXPUESTO";
  bp.className = "pill " + (e.pep_activo ? "pill-ok" : "pill-danger");
  pintarModo(e.pep_activo);

  const pagos = $("#pagos");
  fill(pagos, ...(e.pagos.length ? e.pagos.map((p) => h("li", {},
    h("span", {}, h("b", {}, p.pago_id), " · ", p.beneficiario, " · ", h("span", { class: "mono" }, p.cuenta_destino)),
    h("span", { class: "mono", style: p.con_firma_pep ? "" : "color:var(--danger)" }, "-" + cop(p.monto_cop)))) :
    [h("li", { class: "empty" }, "Sin pagos ejecutados.")]));

  const sel = $("#selSolicitud");
  const prev = S.actual?.id;
  fill(sel, ...e.solicitudes.map((s) => h("option", { value: s.id, selected: s.id === prev }, `${s.id} · ${s.estado}`)));
  sel.hidden = e.solicitudes.length < 2;
  pintarIntegridad(e.integridad);
}

function pintarModo(activo) {
  $("#pepToggle").checked = activo;
  $("#pepSwitch").classList.toggle("off", !activo);
  $("#pepState").textContent = activo ? "ACTIVADO" : "DESACTIVADO";
  $("#bannerOff").hidden = activo;
}

function pintarIntegridad(r) {
  const p = $("#integrityPill");
  p.textContent = r.integro ? `ÍNTEGRO · ${r.entradas}` : `ALTERADO · #${r.primera_alterada}`;
  p.className = "pill " + (r.integro ? "pill-ok" : "pill-danger");
}

async function refrescarAuditoria() {
  const a = await api("/api/auditoria?limite=120");
  const malo = a.integridad.integro ? Infinity : a.integridad.primera_alterada;
  const items = a.entradas.slice().reverse().map((e) => h("li", { class: e.seq >= malo ? "bad" : "", title: JSON.stringify(e.payload) },
    h("span", {}, "#" + e.seq),
    h("span", { class: "actor" }, e.ts.slice(11, 19)),
    h("span", {}, h("span", { class: "ev" }, e.evento), " ", h("span", { class: "actor" }, e.actor), e.estado ? ` → ${e.estado}` : ""),
    h("span", { class: "h" }, "sha256 " + short(e.hash_actual, 20) + (e.solicitud_id ? "  ·  " + e.solicitud_id : ""))));
  $("#auditList").replaceChildren(...(items.length ? items : [h("li", {}, "Sin eventos.")]));
  pintarIntegridad(a.integridad);
}

/* ------------------------------------------------------------------ bandeja */
const COLORES = ["#1d4ed8", "#0e7c5a", "#7c3aed", "#b45309", "#be123c", "#0369a1", "#4d7c0f"];
function renderInbox() {
  const ul = $("#inbox");
  fill(ul, ...S.escenarios.map((e, i) => {
    const tipo = { ATAQUE: ["pill-danger", "Ataque"], LEGITIMO: ["pill-ok", "Legítimo"], IRRELEVANTE: ["pill-idle", "Irrelevante"] }[e.tipo];
    const nombre = e.correo.nombre_remitente || e.correo.remitente;
    const li = h("li", { tabindex: "0", role: "button", "aria-label": `Escenario ${e.etiqueta}` },
      h("div", { class: "avatar", style: `background:${COLORES[i % COLORES.length]}` }, nombre.slice(0, 1).toUpperCase()),
      h("div", { style: "min-width:0" },
        h("div", { class: "from" }, nombre),
        h("div", { class: "subj" }, e.correo.asunto),
        h("div", { class: "desc" }, `${i + 1}. ${e.etiqueta}`)),
      h("div", { class: "meta" }, h("span", { class: "pill " + tipo[0] }, tipo[1])));
    const go = () => { document.querySelectorAll(".inbox li").forEach((x) => x.classList.remove("active")); li.classList.add("active"); cargarEscenario(e, true); };
    li.addEventListener("click", go);
    li.addEventListener("keydown", (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); go(); } });
    li.title = e.descripcion;
    return li;
  }));
}

function cargarEscenario(e, enviar) {
  const f = $("#compose");
  const c = { canal: "EMAIL_EXTERNO", nombre_remitente: "", adjunto_nombre: "", adjunto_texto: "", spf: "pass", dkim: "pass", dmarc: "pass", iniciado_por: "", token_interno: "", ...e.correo };
  for (const [k, v] of Object.entries(c)) if (f.elements[k]) f.elements[k].value = v ?? "";
  f.querySelector("details").open = !!c.adjunto_texto;
  $("#internoFields").hidden = c.canal !== "CANAL_INTERNO";
  if (enviar) enviarCorreo();
}

function leerFormulario() {
  const f = $("#compose");
  const d = Object.fromEntries(new FormData(f).entries());
  for (const k of ["adjunto_nombre", "adjunto_texto", "iniciado_por", "token_interno"]) if (!d[k]) d[k] = null;
  if (d.canal !== "CANAL_INTERNO") { d.iniciado_por = null; d.token_interno = null; }
  return d;
}

async function enviarCorreo() {
  if (S.animando) return;
  const btn = $("#btnEnviar");
  btn.disabled = true;
  try {
    const sol = await api("/api/correos", { method: "POST", body: leerFormulario() });
    S.actual = sol;
    await animar(sol);
    await Promise.all([refrescarEstado(), refrescarAuditoria()]);
  } catch (err) {
    toast("No se pudo procesar el correo: " + err.message, true);
  } finally {
    btn.disabled = false;
  }
}

/* ------------------------------------------------------------------ pipeline */
function paso(sol, nombre) { return sol.traza.find((t) => t.paso === nombre); }
const riesgoPill = { ALTO: "pill-danger", MEDIO: "pill-warn", BAJO: "pill-ok" };

function stage(n, titulo, sub, pill, pillCls, cls, body, origen) {
  return h("div", { class: `stage ${cls}` },
    h("div", { class: "stage-head" },
      h("div", { class: "step" }, n),
      h("div", {}, h("div", { class: "stage-title" }, titulo), h("div", { class: "stage-sub" }, sub)),
      h("span", { class: "pill " + pillCls }, pill)),
    h("div", { class: "stage-body" }, body),
    origen ? h("div", { class: "origin" }, "origen LLM: " + origen) : null);
}

function kv(pares) {
  return h("dl", { class: "kv" }, ...pares.flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v ?? "—")]));
}

function construirEtapas(sol) {
  const r = paso(sol, "recepcionista"), s = paso(sol, "sanitizer"), o = paso(sol, "orquestador"), f = paso(sol, "financiero");
  const md = s.datos, ext = r.datos;
  const etapas = [];

  const lavado = ext.es_solicitud_pago && (md.banderas_anomalia || []).some((b) => ["INSTRUCCION_OCULTA", "INSTRUCCION_EN_ADJUNTO", "CAMBIO_CUENTA"].includes(b));
  etapas.push(stage(1, "Agente Recepcionista", "Único que lee el texto libre · salida = esquema cerrado Pydantic",
    "ESQUEMA CERRADO", "pill-info", "s-ok", [
      h("div", { class: "quote" }, ext.resumen_neutro),
      kv([["beneficiario", ext.beneficiario], ["cuenta_destino", ext.cuenta_destino], ["monto_cop", cop(ext.monto_cop)],
          ["factura / OC", [ext.numero_factura, ext.numero_oc].filter(Boolean).join(" · ") || "—"], ["es_solicitud_pago", String(ext.es_solicitud_pago)]]),
      lavado ? h("div", { class: "note note-warn" }, h("b", {}, "Lavado semántico: "),
        "el resumen suena corporativo y no contiene la instrucción del atacante, pero los datos (cuenta/monto) sí vienen de ella. Por eso el Sanitizer etiqueta el correo ORIGINAL y el PEP verifica contra el maestro.") : null,
    ], r.origen_llm));

  const activo = md.sanitizer_activo !== false;
  etapas.push(stage(2, "Context Sanitizer", "Taint tracking · etiquetas inmutables selladas con SHA-256",
    activo ? `RIESGO ${md.nivel_riesgo}` : "DESACTIVADO", activo ? riesgoPill[md.nivel_riesgo] : "pill-idle",
    !activo ? "s-idle" : md.nivel_riesgo === "ALTO" ? "s-danger" : md.nivel_riesgo === "MEDIO" ? "s-warn" : "s-ok", [
      h("div", { class: "chips" },
        h("span", { class: "pill " + (md.tainted ? "pill-danger" : "pill-ok") }, "ORIGEN: " + md.origen),
        h("span", { class: "pill " + (md.tainted ? "pill-danger" : "pill-ok") }, "TAINTED: " + String(md.tainted).toUpperCase()),
        h("span", { class: "pill " + (md.spf_dkim_valido ? "pill-ok" : "pill-danger") }, "SPF/DKIM/DMARC: " + (md.spf_dkim_valido ? "OK" : "FALLA"))),
      kv([["dominio", md.dominio_remitente + (md.dominio_parecido_a ? `  ≈ ${md.dominio_parecido_a}` : "")],
          ["riesgo reglas / LLM", `${md.nivel_riesgo_reglas} / ${md.nivel_riesgo_semantico} → ${md.nivel_riesgo}`],
          ["sello", short(md.sello_sha256, 24)]]),
      (md.banderas_anomalia || []).length ? h("div", { class: "chips" }, ...md.banderas_anomalia.map((b) => h("span", { class: "pill pill-warn" }, b))) : null,
      (md.evidencias || []).length ? h("ul", { class: "risks" }, ...md.evidencias.map((x) => h("li", {}, x))) : null,
    ], s.origen_llm));

  const od = o.datos;
  if (o.estado === "CERRADA_NO_FINANCIERA") {
    etapas.push(stage(3, "Agente Orquestador", "Filtro de relevancia + validación de negocio (solo lectura)",
      "FILTRADA", "pill-idle", "s-ok", [
        h("div", { class: "note note-info" }, h("b", {}, od.relevancia.categoria + ": "), od.relevancia.justificacion,
          " El flujo se cierra aquí: el Agente Financiero no se despierta (mínimo privilegio, cero tokens financieros)."),
      ], o.origen_llm));
  } else {
    const v = od.validacion;
    const chk = (ok, txt, warn = false) => h("li", {}, h("span", { class: "ic " + (ok ? "y" : warn ? "w" : "n") }, ok ? "✓" : warn ? "!" : "✗"), txt);
    etapas.push(stage(3, "Agente Orquestador", "Filtro de relevancia + validación de negocio (solo lectura)",
      v.recomendacion.replace("_", " "), v.recomendacion === "PROPONER_PAGO" ? "pill-ok" : v.recomendacion === "RECHAZAR" ? "pill-warn" : "pill-danger",
      v.recomendacion === "PROPONER_PAGO" ? "s-ok" : "s-warn", [
        h("ul", { class: "checks" },
          chk(v.proveedor_registrado, "Proveedor registrado" + (v.razon_social ? ` (${v.razon_social})` : "")),
          chk(v.cuenta_coincide_maestro, "Cuenta coincide con el maestro"),
          chk(v.dominio_coincide, "Dominio del remitente = dominio registrado"),
          chk(v.soporte_valido, "Factura u OC que respalda el pago"),
          chk(!v.duplicado, "No es un pago duplicado"),
          chk(!(v.dias_desde_cambio_cuenta !== null && v.dias_desde_cambio_cuenta < 30),
            v.dias_desde_cambio_cuenta !== null ? `Cuenta modificada hace ${v.dias_desde_cambio_cuenta} días` : "Antigüedad de la cuenta", true)),
        h("div", { class: "origin" }, "tools: " + od.herramientas_usadas.map((x) => x.herramienta).join(" · ")),
        h("div", { class: "note note-info" }, "Recomendación consultiva: el PEP no confía en ella y repite sus propias consultas."),
      ], o.origen_llm));
  }

  if (f) {
    etapas.push(stage(4, "Agente Financiero", "Privilegios altos · solo propone; no puede firmar",
      "INVOCA HERRAMIENTA", "pill-warn", "s-warn", [
        h("pre", { class: "code" }, `${f.datos.herramienta}(${JSON.stringify(f.datos.argumentos, null, 2)})`),
        h("div", { class: "note note-info" }, sol.pep_activo
          ? "La llamada es interceptada por el ToolGateway → PEP determinista → Agente Explicador → confirmación humana."
          : "PEP DESACTIVADO: la llamada va directo al servicio de pagos."),
      ], f.origen_llm));
  } else {
    etapas.push(stage(4, "Agente Financiero", "Privilegios altos · acceso al servicio de pagos",
      "AISLADO / EN REPOSO", "pill-idle", "s-idle", [
        h("div", { class: "isolated" },
          h("span", {}, "🔒"), "No invocado por el Orquestador: sin contexto, sin herramientas, sin tokens."),
      ]));
  }
  return etapas;
}

async function animar(sol) {
  S.animando = true;
  const pipe = $("#pipeline");
  fill(pipe, );
  $("#verdict").replaceChildren(h("div", { class: "card-title" }, "Veredicto del PEP ", h("span", { class: "hint" }, "código determinista, sin LLM")),
    h("div", { class: "empty" }, "Procesando…"));
  for (const el of construirEtapas(sol)) {
    pipe.append(el);
    await sleep(30);
    el.classList.add("show");
    await sleep(380);
  }
  renderVeredicto(sol);
  renderHitl(sol);
  S.animando = false;
}

/* ------------------------------------------------------------------ veredicto */
function renderVeredicto(sol) {
  const box = $("#verdict");
  const titulo = h("div", { class: "card-title" }, "Veredicto del PEP ", h("span", { class: "hint" }, "código determinista, sin LLM"));
  const v = sol.veredicto;
  if (!v) {
    fill(box, titulo, h("div", { class: "verdict-badge vb-idle" }, "SIN INVOCACIÓN",
      h("small", {}, "El Orquestador cerró la tarea: no hubo llamada a herramientas financieras.")));
    return;
  }
  const estado = sol.estado;
  const cls = { BLOQUEADA: "vb-danger", RECHAZADA: "vb-warn", EXPIRADA: "vb-idle", EJECUTADA: v.pep_activo ? "vb-ok" : "vb-fire" }[estado] || "vb-warn";
  const icono = { BLOQUEADA: "⛔", RECHAZADA: "↩", EJECUTADA: v.pep_activo ? "✓" : "⚠", EXPIRADA: "⌛" }[estado] || "✍";
  const etiqueta = sol.pending_approval ? "PENDING_APPROVAL" : estado;
  fill(box, titulo,
    h("div", { class: "verdict-badge " + cls }, h("span", {}, icono),
      h("div", {}, etiqueta, h("small", {}, v.regla_principal))),
    v.reglas.length ? h("ul", { class: "rules" }, ...v.reglas.map((r) =>
      h("li", {}, h("span", { class: "rule-code rc-" + r.decision }, r.codigo), h("span", {}, r.descripcion)))) : null,
    v.alerta_seguridad ? h("div", { class: "note note-danger" }, "Alerta enviada al Oficial de Seguridad · caso abierto · no se movió dinero.") : null,
    h("div", { class: "meta-line" },
      h("span", {}, "latencia PEP: ", h("b", { class: "mono" }, `${v.latencia_ms} ms`)),
      h("span", {}, "pipeline: ", h("b", { class: "mono" }, `${sol.latencia_total_ms} ms`)),
      v.hash_transaccion ? h("span", { class: "mono", title: v.hash_transaccion }, "hash tx " + short(v.hash_transaccion)) : null));
}

/* ------------------------------------------------------------------ supervisión humana */
function candidatoPorDefecto(sol) {
  if (sol.bloqueada) return "u-sofia";
  const firmados = new Set((sol.firmas || []).map((f) => f.usuario_id));
  const c = S.usuarios.find((u) => u.rol === sol.siguiente_rol && u.usuario_id !== sol.iniciado_por && !firmados.has(u.usuario_id));
  return c ? c.usuario_id : S.usuarios[0].usuario_id;
}

function renderHitl(sol) {
  const box = $("#hitl");
  const sel = $("#selSolicitud");
  const titulo = h("div", { class: "card-title" }, "Resumen ejecutivo para el trabajador", sel);
  if (!sol.veredicto) {
    fill(box, titulo, h("div", { class: "note note-info" },
      "No requiere decisión humana: el Orquestador filtró la tarea sin despertar al Agente Financiero."));
    return;
  }
  const ex = sol.explicacion, dv = sol.datos_verificados;
  const partes = [titulo];

  partes.push(h("div", { class: "explain" },
    h("div", { class: "by" }, h("span", {}, "Generado por el Agente Explicador · " + ex.origen),
      h("span", { class: "pill " + (ex.coherente ? "pill-ok" : "pill-danger"), title: "Control determinista: la explicación cita el monto y la cuenta exactos" },
        ex.coherente ? "coherente con los datos" : "NO coherente: use los datos verificados")),
    h("h3", {}, ex.titulo),
    h("p", {}, ex.resumen),
    ex.riesgos.length ? h("ul", { class: "risks" }, ...ex.riesgos.map((r) => h("li", {}, r))) : null,
    h("p", { class: "q" }, ex.pregunta_confirmacion)));

  partes.push(h("div", { class: "verified" },
    h("div", { class: "kpi-label" }, "Datos verificados — " + dv.fuente),
    kv([["beneficiario", dv.beneficiario], ["cuenta", dv.cuenta], ["monto", dv.monto_formateado],
        ["hash firmado", dv.hash_transaccion ? short(dv.hash_transaccion, 28) : "—"]])));

  if (sol.firmas_requeridas) {
    const hechas = sol.firmas.length;
    partes.push(h("div", { class: "sigs" }, ...sol.firmas_requeridas.map((r, i) => {
      const f = sol.firmas[i];
      return h("div", { class: "sig" + (f ? " done" : i === hechas && sol.pending_approval ? " next" : "") },
        h("b", {}, `Firma ${i + 1}`), r.etiqueta, h("br"), f ? `✓ ${f.nombre}` : "pendiente");
    })));
  }

  const msg = h("div", { class: "msg" });
  const estado = sol.estado;
  if (sol.pending_approval) {
    partes.push(...controlesFirma(sol, msg));
  } else if (sol.bloqueada) {
    partes.push(h("div", { class: "actions" },
      h("button", { class: "btn btn-ok", disabled: true, title: "Bloqueo duro por la Matriz 3" }, "✅ Aprobar transacción"),
      h("button", { class: "btn btn-danger", disabled: true }, "❌ No aprobar")));
    partes.push(h("div", { class: "note note-danger" }, "Aprobación deshabilitada: bloqueo duro del PEP. Solo el Oficial de Seguridad puede revisar el incidente (la solicitud sigue bloqueada; reabrirla exige un caso nuevo)."));
    partes.push(...controlesOficial(sol, msg));
  } else if (estado === "EJECUTADA") {
    partes.push(h("div", { class: "note " + (sol.pep_activo ? "note-ok" : "note-danger") },
      sol.pep_activo ? `Pago ${sol.pago?.pago_id || ""} ejecutado tras verificar ${sol.firmas?.length || 0} firmas y la segregación de funciones.`
        : "El pago se ejecutó sin aduana: nadie confirmó, nadie firmó. Active el PEP y repita el escenario."));
  } else {
    partes.push(h("div", { class: "note note-warn" }, estado === "RECHAZADA"
      ? "Solicitud rechazada: no se movió dinero. Cuentas por pagar puede corregirla y reenviarla con soporte."
      : "Solicitud vencida (48 h): debe iniciarse de nuevo."));
  }
  partes.push(msg);
  fill(box, ...partes);
}

function selectorUsuario(sol, roles) {
  const porDefecto = candidatoPorDefecto(sol);
  const select = h("select", { id: "fUsuario" }, ...S.usuarios.filter((u) => roles.includes(u.rol)).map((u) =>
    h("option", { value: u.usuario_id, selected: u.usuario_id === porDefecto },
      `${u.nombre} — ${u.rol_etiqueta}${u.rol === sol.siguiente_rol ? " ★" : ""}${u.usuario_id === sol.iniciado_por ? " (inició)" : ""}`)));
  const pin = h("input", { type: "password", id: "fPin", inputmode: "numeric", maxlength: "12", placeholder: "PIN / MFA" });
  const hint = h("a", { href: "#", class: "hint" });
  const pintarHint = () => { const u = S.usuarios.find((x) => x.usuario_id === select.value); hint.textContent = `usar PIN demo (${u.pin_demo})`; };
  hint.addEventListener("click", (ev) => { ev.preventDefault(); pin.value = S.usuarios.find((x) => x.usuario_id === select.value).pin_demo; });
  select.addEventListener("change", () => { pin.value = ""; pintarHint(); });
  pintarHint();
  return [h("div", { class: "signer" },
    h("label", {}, "Firmante (rol · Matriz 2)", select),
    h("label", {}, "PIN (MFA simulado)", pin, hint)), select, pin];
}

function controlesFirma(sol, msg) {
  const [fila, select, pin] = selectorUsuario(sol, SIGNING_ROLES.concat(["ADMIN_PLATAFORMA"]));
  const vt = sol.verificacion_telefonica;
  const tel = vt?.requerida && !vt.hecha ? h("input", { type: "checkbox", id: "fTel" }) : null;
  const n = sol.firmas.length + 1, N = sol.firmas_requeridas.length;
  const aprobar = h("button", { class: "btn btn-ok" }, `✅ Aprobar transacción (firma ${n} de ${N})`);
  const rechazar = h("button", { class: "btn btn-danger" }, "❌ No aprobar (rechazar)");
  const accion = async (tipo) => {
    if (!pin.value) { pin.focus(); return mostrar(msg, "Ingrese el PIN del firmante.", "warn"); }
    aprobar.disabled = rechazar.disabled = true;
    try {
      const body = tipo === "firmar"
        ? { usuario_id: select.value, pin: pin.value, verificacion_telefonica: !!(tel && tel.checked) }
        : { usuario_id: select.value, pin: pin.value, motivo: "No aprobada desde la consola de supervisión" };
      const r = await api(`/api/solicitudes/${sol.id}/${tipo}`, { method: "POST", body });
      S.actual = r.solicitud;
      renderVeredicto(r.solicitud);
      renderHitl(r.solicitud);
      toast(r.mensaje, !r.ok);
      await Promise.all([refrescarEstado(), refrescarAuditoria()]);
    } catch (err) {
      mostrar(msg, err.message, "danger");
      aprobar.disabled = rechazar.disabled = false;
      refrescarAuditoria();
    }
  };
  aprobar.addEventListener("click", () => accion("firmar"));
  rechazar.addEventListener("click", () => accion("rechazar"));
  return [fila,
    tel ? h("label", { class: "phone" }, tel, h("span", {}, h("b", {}, "Verificación telefónica realizada "),
      `al número registrado del proveedor ${vt.telefono} (no al del correo). La registra el Analista o el Tesorero.`)) : null,
    vt?.requerida && vt.hecha ? h("div", { class: "note note-ok" }, `Verificación telefónica registrada (${vt.telefono}).`) : null,
    h("div", { class: "actions" }, aprobar, rechazar)];
}

function controlesOficial(sol, msg) {
  const [fila, select, pin] = selectorUsuario(sol, ["OFICIAL_SEGURIDAD", ...SIGNING_ROLES]);
  const btn = h("button", { class: "btn btn-ghost btn-block", style: "margin-top:8px" }, "🛡 Revisar incidente (Oficial de Seguridad)");
  btn.addEventListener("click", async () => {
    if (!pin.value) return mostrar(msg, "Ingrese el PIN.", "warn");
    try {
      const r = await api(`/api/solicitudes/${sol.id}/revisar-incidente`, { method: "POST",
        body: { usuario_id: select.value, pin: pin.value, motivo: "Revisión del incidente desde la consola" } });
      mostrar(msg, r.mensaje, "ok");
      refrescarAuditoria();
    } catch (err) { mostrar(msg, err.message, "danger"); refrescarAuditoria(); }
  });
  return [fila, btn];
}

function mostrar(el, texto, tipo) {
  fill(el, h("div", { class: `note note-${tipo}` }, texto));
}

/* ------------------------------------------------------------------ init */
async function abrirSolicitud(id) {
  const sol = await api(`/api/solicitudes/${id}`);
  S.actual = sol;
  $("#pipeline").replaceChildren(...construirEtapas(sol));
  document.querySelectorAll(".stage").forEach((x) => x.classList.add("show"));
  renderVeredicto(sol);
  renderHitl(sol);
}

async function init() {
  [S.escenarios, S.usuarios] = await Promise.all([api("/api/escenarios"), api("/api/usuarios")]);
  renderInbox();
  cargarEscenario(S.escenarios[1], false);
  await Promise.all([refrescarEstado(), refrescarAuditoria()]);

  $("#compose").addEventListener("submit", (ev) => { ev.preventDefault(); enviarCorreo(); });
  $("#fCanal").addEventListener("change", (ev) => ($("#internoFields").hidden = ev.target.value !== "CANAL_INTERNO"));
  $("#pepToggle").addEventListener("change", async (ev) => {
    try {
      await api("/api/modo", { method: "POST", body: { pep_activo: ev.target.checked } });
      toast(ev.target.checked ? "PEP Zero-Trust ACTIVADO: toda herramienta financiera pasa por la aduana."
        : "PEP DESACTIVADO: confianza implícita. Pruebe ahora el escenario de inyección.", !ev.target.checked);
      await Promise.all([refrescarEstado(), refrescarAuditoria()]);
    } catch (err) { toast(err.message, true); }
  });
  $("#btnReset").addEventListener("click", async () => {
    await api("/api/reiniciar", { method: "POST" });
    S.actual = null;
    $("#pipeline").replaceChildren(h("div", { class: "empty" }, "Demo reiniciada. Elige un escenario."));
    $("#verdict").replaceChildren(h("div", { class: "card-title" }, "Veredicto del PEP"), h("div", { class: "empty" }, "En espera."));
    $("#hitl").replaceChildren(h("div", { class: "card-title" }, "Resumen ejecutivo para el trabajador", $("#selSolicitud")), h("div", { class: "empty" }, "Sin pendientes."));
    await Promise.all([refrescarEstado(), refrescarAuditoria()]);
    toast("Demo reiniciada: saldo, solicitudes y registro nuevos.");
  });
  $("#btnVerify").addEventListener("click", async () => {
    const r = await api("/api/auditoria/verificar");
    pintarIntegridad(r);
    toast(r.detalle, !r.integro);
    refrescarAuditoria();
  });
  $("#btnTamper").addEventListener("click", async () => {
    const r = await api("/api/demo/manipular-auditoria", { method: "POST" });
    if (!r.ok) return toast(r.detalle, true);
    toast(`Se alteró la entrada #${r.seq} sin recalcular hashes → ${r.verificacion.detalle}`, true);
    refrescarAuditoria();
  });
  $("#selSolicitud").addEventListener("change", (ev) => abrirSolicitud(ev.target.value));
}

init().catch((err) => toast("No se pudo conectar con la API: " + err.message, true));
