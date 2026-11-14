/* Context Firewall · interfaz (diseño del prototipo de main, conectada a la API real).
   Todo lo que se muestra sale del backend: solicitudes, veredictos del PEP, firmas con PIN,
   registro SHA-256 y resultados del benchmark. Una sola persona firma cada solicitud. */
(function(){
"use strict";

/* ============ Estado de datos (viene de la API) ============ */
let EST=null, USERS=[], PERSONAS={}, S={}, ORDER=[], BENCH=null, BENCH_ERR=null, ESCEN=[], INTEG=null;
let ui={persona:null,estadoFiltro:"todas",riesgo:new Set(),q:"",sign:null,verify:null,pane:null,paneOpen:true,busy:null,cargando:true,error:null};

/* ============ Utilidades ============ */
const $=s=>document.querySelector(s);
const esc=t=>String(t??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const cop=n=>"$ "+Number(n||0).toLocaleString("es-CO");
const ic=(id,cls="")=>`<svg class="${cls}" aria-hidden="true"><use href="#${id}"/></svg>`;
const P=()=>PERSONAS[ui.persona]||Object.values(PERSONAS)[0]||{id:"",nombre:"—",rol:"auditor",rolTxt:"",ini:"?",home:"bandeja",backendRol:""};
const PACK=()=>EST?EST.pack.id:"pagos_iso42001";
const isDev=()=>PACK()==="devops_cloud";
async function api(path,opt={}){
  const r=await fetch(path,{headers:{"Content-Type":"application/json"},...opt,body:opt.body?JSON.stringify(opt.body):undefined});
  let d=null;try{d=await r.json();}catch(_){}
  if(!r.ok){const det=d&&d.detail;throw new Error(typeof det==="string"?det:Array.isArray(det)?det.map(x=>x.msg).join("; "):`Error ${r.status}`);}
  return d;
}
function toast(msg,icon="i-check",ms=3600){const t=document.createElement("div");t.className="toast";t.innerHTML=ic(icon)+`<span>${msg}</span>`;$("#toasts").appendChild(t);setTimeout(()=>t.remove(),ms);}

/* Textos que cambian según el dominio (Policy Pack) */
const DOM={
  pagos_iso42001:{corto:"Pagos",sub:"Pagos desde correo · Zero-Trust",ent:"Beneficiario",col:"Monto (COP)",ok:"Pagada",okVerbo:"Pago enviado",
    autoriza:"Vas a autorizar este pago",maestro:"maestro de proveedores",buzon:"pagos@empresa-demo.co",adr:"PAY-ADR",accion:"pago",
    bandeja:"Bandeja de entrada",cliente:"cliente de correo simulado",fuente:"correo",dano:"Pagos fraudulentos ejecutados",legit:"Pagos legítimos completados"},
  devops_cloud:{corto:"Cloud",sub:"Cambios de infraestructura · Zero-Trust",ent:"Recurso",col:"Acción",ok:"Aplicada",okVerbo:"Cambio aplicado",
    autoriza:"Vas a aprobar este cambio de infraestructura",maestro:"catálogo de recursos y CAB",buzon:"infra@empresa-demo.co",adr:"CHG-ADR",accion:"cambio",
    bandeja:"Issues y tickets",cliente:"webhooks y portal de soporte simulados",fuente:"issue",dano:"Acciones destructivas ejecutadas",legit:"Cambios legítimos aplicados"}
};
const D=()=>DOM[PACK()]||DOM.pagos_iso42001;

const ISO={sod:"27001 5.3 Segregación de funciones",acc:"27001 5.15 Control de acceso",ent:"27001 8.7 Protección de entradas",log:"27001 8.15 Registro de eventos",ver:"27001 5.14 Transferencia de información",sup:"42001 A.9 Supervisión humana",trz:"42001 A.6 Trazabilidad del sistema IA"};
const ISO_REGLA={R0:["acc","trz"],U0:["acc","trz"],R1:["ver"],R2:["ent"],U1:["ent"],R3:["ent","ver"],U2:["ent","ver"],R4:["acc"],R5:["acc"],R6:["sup"],R7:["ver"],R8:["sod","sup"],R9:["sod","ver","sup"],U3:["sup"],U4:["sod"],D1:["ent"],D2:["ent"],D3:["sod","sup"],D4:["sod","sup"],D5:["acc"]};
const TAG_REGLA={R1:"Cuenta distinta",R2:"Inyección",R3:"Suplantación",U1:"Inyección",U2:"Origen no autenticado",R4:"Duplicado",R5:"Sin soporte",D1:"Destructiva",D2:"Inyección",D5:"Sin ticket"};
const RISK={bajo:["i-low","Riesgo bajo"],medio:["i-med","Riesgo medio"],alto:["i-high","Riesgo alto"]};
const risk=(r,short)=>{const k=RISK[r]?r:"medio";return `<span class="risk ${k}">${ic(RISK[k][0])}${short?RISK[k][1].replace("Riesgo ",""):RISK[k][1]}</span>`;};
const isoTag=k=>ISO[k]?`<span class="iso">${ic("i-shield")}${ISO[k]}</span>`:"";
function chip(s){
  const m={PENDIENTE_FIRMA_1:["c-hum","i-pen","Pendiente de firma"],PENDIENTE_FIRMA_2:["c-hum","i-pen","Pendiente de firma"],PENDIENTE_FIRMA_3:["c-hum","i-pen","Pendiente de firma"],
    EJECUTADA:["c-ok","i-check",D().ok],BLOQUEADA:["c-crit","i-lock","Bloqueada"],RECHAZADA:["c-crit","i-x","Rechazada"],EXPIRADA:["c-neu","i-clock","Vencida"],
    RECIBIDA:["c-neu","i-dot","Recibida"],ETIQUETADA:["c-neu","i-tag","Etiquetada"],VALIDADA:["c-acc","i-check","Validada"],
    CERRADA_NO_FINANCIERA:["c-neu","i-dot","Sin acción"],FALLO_MODELO:["c-crit","i-alert","Fallo del modelo"]}[s]||["c-neu","i-dot",s];
  return `<span class="chip ${m[0]}">${ic(m[1])}${esc(m[2])}</span>`;
}
const pending=s=>!!s.pendiente;
const hhmm=iso=>{try{return new Date(iso).toLocaleTimeString("es-CO",{hour:"2-digit",minute:"2-digit"});}catch(_){return "";}};
const hhmmss=iso=>{try{return new Date(iso).toLocaleTimeString("es-CO",{hour:"2-digit",minute:"2-digit",second:"2-digit"});}catch(_){return "";}};
const fechaTxt=iso=>{try{const d=new Date(iso);return d.toLocaleDateString("es-CO",{weekday:"short",day:"2-digit",month:"2-digit"})+" · "+hhmm(iso);}catch(_){return iso||"";}};
const llmTxt=l=>!l?"—":typeof l==="string"?l:(l.modelo||l.proveedor||l.nombre||JSON.stringify(l));
const corto=h=>h?`sha256:${h.slice(0,8)}…${h.slice(-6)}`:"—";

/* ============ Personas (usuarios reales del pack) ============ */
const ROL_UI={ANALISTA_CXP:"analista",INGENIERO_SOPORTE:"analista",TESORERO:"firmante",DIRECTOR_FINANCIERO:"firmante",DEVOPS_SENIOR:"firmante",LIDER_SRE:"firmante",
  AUDITOR:"auditor",OFICIAL_SEGURIDAD:"oficial",ADMIN_PLATAFORMA:"admin",ADMIN_PROVEEDORES:"admin"};
const PUEDEN_RECHAZAR=new Set(["ANALISTA_CXP","TESORERO","DIRECTOR_FINANCIERO","OFICIAL_SEGURIDAD","DEVOPS_SENIOR","LIDER_SRE"]);
const POR_DEFECTO={pagos_iso42001:"TESORERO",devops_cloud:"LIDER_SRE"};
function armarPersonas(){
  PERSONAS={};
  for(const u of USERS){
    const ini=u.nombre.split(" ").map(w=>w[0]).slice(0,2).join("").toUpperCase();
    PERSONAS[u.usuario_id]={id:u.usuario_id,nombre:u.nombre,backendRol:u.rol,rol:ROL_UI[u.rol]||"analista",rolTxt:u.rol_etiqueta,ini,pin:u.pin_demo,home:u.rol==="AUDITOR"?"corte":"bandeja"};
  }
  if(!PERSONAS[ui.persona]){const d=USERS.find(u=>u.rol===POR_DEFECTO[PACK()])||USERS[0];ui.persona=d?d.usuario_id:null;}
}
const nombreDe=uid=>PERSONAS[uid]?PERSONAS[uid].nombre:uid;

/* ============ Adaptador: vista del backend → modelo del prototipo ============ */
const paso=(v,k)=>(v.traza||[]).find(p=>p.paso===k);
function cuerpoConSenales(texto,evid){
  let h=esc(texto);
  for(const e of evid){
    const m=/«(.+?)»/.exec(e);if(!m) continue;
    const frase=esc(m[1]);const crit=/INSTRUCCION|CAMBIO_CUENTA|EXFIL|DESTRUCT|PRIVILEG/.test(e);
    if(frase&&h.includes(frase)) h=h.replace(frase,`<span class='flag${crit?" crit":""}'>${frase}</span>`);
  }
  return h.split(/\n+/).filter(Boolean);
}
function filasComparacion(v,ext,val,meta){
  const r=[];if(!val) return r;
  const add=(campo,sol,ref,ok,nota)=>r.push([campo,sol==null||sol===""?"—":String(sol),ref,ok?1:0,nota]);
  if(isDev()){
    if("recurso_registrado" in val) add("Recurso",ext.recurso,val.recurso_registrado?"Registrado en el catálogo":"No existe en el catálogo",val.recurso_registrado,"No registrado");
    if("entorno_catalogo" in val) add("Entorno",ext.entorno,val.entorno_catalogo||"—",!val.entorno_catalogo||val.entorno_catalogo===ext.entorno,"No coincide");
    if("recurso_operativo" in val) add("Estado del recurso","",val.recurso_operativo?"Operativo":"No operativo",val.recurso_operativo,"No operativo");
    if("ticket_aprobado" in val) add("Ticket de cambio",ext.ticket_cambio,val.ticket_aprobado?"Aprobado por el CAB":"Sin aprobación del CAB",val.ticket_aprobado,"Sin ticket válido");
    if("accion_destructiva" in val) add("Acción",[ext.accion,ext.replicas!=null?`réplicas=${ext.replicas}`:"",ext.version?`versión=${ext.version}`:""].filter(Boolean).join(" · "),val.accion_destructiva?"Destructiva":"No destructiva",!val.accion_destructiva,"Destructiva");
  }else{
    if("proveedor_registrado" in val) add("Proveedor",ext.beneficiario,val.proveedor_registrado?`${val.razon_social||""} · ${val.proveedor_id||""}`:"No está en el maestro",val.proveedor_registrado,"No registrado");
    if("dominio_coincide" in val) add("Remitente",meta.dominio_remitente,val.dominio_coincide?"Dominio registrado":(meta.dominio_parecido_a?`Parecido a ${meta.dominio_parecido_a}`:"No coincide"),val.dominio_coincide,meta.dominio_parecido_a?"Dominio parecido":"Distinto");
    if("cuenta_coincide_maestro" in val) add("Cuenta",ext.cuenta_destino,val.cuenta_coincide_maestro?"Coincide con el maestro":"Distinta a la registrada",val.cuenta_coincide_maestro,"Distinta");
    if(typeof val.dias_desde_cambio_cuenta==="number") add("Último cambio de cuenta","",`hace ${val.dias_desde_cambio_cuenta} días`,val.dias_desde_cambio_cuenta>=30,"Reciente (<30 días)");
    if("soporte_valido" in val) add("Factura / OC",[ext.numero_factura,ext.numero_oc].filter(Boolean).join(" · "),val.soporte_valido?"OC abierta y monto coincide":"Sin soporte válido",val.soporte_valido,"Sin respaldo");
    if("duplicado" in val) add("Duplicados","",val.duplicado?"Ya existe una solicitud igual":"Ninguno",!val.duplicado,"Duplicada");
  }
  if(meta&&"spf_dkim_valido" in meta) add("Autenticación del origen","",meta.spf_dkim_valido?(isDev()?"Firma/autenticación válida":"SPF · DKIM · DMARC válidos"):"Falló",meta.spf_dkim_valido,"No autenticado");
  return r;
}
function adaptar(v){
  const ext=(paso(v,"recepcionista")||{}).datos||{};
  const orq=(paso(v,"orquestador")||{}).datos||{};
  const val=orq.validacion||null;
  const san=(paso(v,"sanitizer")||{}).datos||{};
  const meta=v.metadata||san||{};
  const dv=v.datos_verificados||{};
  const ver=v.veredicto||{};
  const reglas=(ver.reglas||[]).map(r=>r.codigo);
  const c=v.correo||{};
  const dev=isDev();
  const monto=dv.monto_cop??ext.monto_cop??0;
  const montoTxt=dev?[ext.accion||dv.accion,ext.replicas!=null?`× ${ext.replicas}`:"",ext.version||""].filter(Boolean).join(" ")||"—":(monto?cop(monto):"—");
  const creada=v.creada||(v.eventos[0]||{}).ts;
  const venceH=Math.max(0,Math.round(48-(Date.now()-new Date(creada).getTime())/3.6e6));
  const firma=(v.firmas||[])[0];
  const rech=(v.eventos||[]).find(e=>e.evento==="RECHAZADA_POR_HUMANO");
  const evid=meta.evidencias||[];
  const interno=c.canal==="CANAL_INTERNO";
  const principal=(ver.regla_principal||"").split(" ")[0];
  const iso=[...new Set(reglas.flatMap(k=>ISO_REGLA[k]||[]).concat(["log"]))];
  const req=(v.firmas_requeridas||[])[0];
  const rolSig=v.siguiente_rol;
  const exp=v.explicacion||{};
  const rel=(orq.relevancia||{});
  return {
    id:v.id,raw:v,prov:dev?(ext.recurso||dv.recurso||c.asunto||"—"):(dv.beneficiario||ext.beneficiario||c.nombre_remitente||"—"),
    nit:dev?(ext.entorno||dv.entorno||"—"):(ext.nit_beneficiario||(val&&val.proveedor_id)||"—"),
    monto,montoTxt,riesgo:String(meta.nivel_riesgo||"medio").toLowerCase(),estado:v.estado,pendiente:v.pending_approval,
    recibida:hhmm(creada),fecha:fechaTxt(creada),vence:venceH,
    llamada:!!(v.verificacion_telefonica&&v.verificacion_telefonica.requerida&&!v.verificacion_telefonica.hecha),
    telefono:v.verificacion_telefonica&&v.verificacion_telefonica.telefono,
    rolSig,rolSigTxt:req?req.etiqueta:"",ini:v.iniciado_por,canal:interno?"Canal interno":(c.canal==="WEBHOOK_GITHUB"?"Webhook GitHub":c.canal==="TICKET_SOPORTE"?"Ticket de soporte":c.canal==="API_A2A"?"API A2A":"Correo"),
    regla:reglas.join(" · ")||principal||"—",reglas:ver.reglas||[],tag:TAG_REGLA[principal]||(reglas.map(k=>TAG_REGLA[k]).find(Boolean)||null),
    tipo:ver.regla_principal||"",iso,
    porque:exp.resumen||ver.regla_principal||rel.justificacion||"El orquestador determinó que este mensaje no pide ninguna acción.",
    explicacion:exp,
    correo:interno?null:{de:c.remitente,para:D().buzon,asunto:c.asunto||"(sin asunto)",cuerpo:cuerpoConSenales(c.cuerpo||"",evid),adj:c.adjunto_nombre||null,oculto:c.adjunto_texto||null,evid},
    asunto:c.asunto||"",cmp:filasComparacion(v,ext,val,meta),ext,val,meta,dv,
    firmo:firma?firma.usuario_id:null,firmoNombre:firma?firma.nombre:null,firmoRol:firma?firma.rol:null,firmaHora:firma?fechaTxt(firma.timestamp):null,firma,
    rechazoPor:rech?rech.actor.replace("humano:",""):null,motivo:rech?(rech.payload||{}).motivo:null,
    eventos:v.eventos||[],modo:v.modo,financiero:v.financiero_invocado,sello:san.sello_sha256,hash:dv.hash_transaccion,alerta:!!ver.alerta_seguridad
  };
}

/* ============ Carga ============ */
async function cargar(){
  try{
    const [est,users,sol]=await Promise.all([api("/api/estado"),api("/api/usuarios"),api("/api/solicitudes")]);
    EST=est;USERS=users;INTEG=sol.integridad;armarPersonas();
    S={};ORDER=[];
    for(const v of sol.solicitudes){const s=adaptar(v);S[s.id]=s;ORDER.push(s.id);}
    ORDER.reverse();
    ui.error=null;
  }catch(e){ui.error=e.message;}
  ui.cargando=false;
  try{ESCEN=await api("/api/escenarios?todos=true");}catch(_){ESCEN=[];}
  try{BENCH=await api("/api/benchmark");BENCH_ERR=null;}catch(e){BENCH=null;BENCH_ERR=e.message;}
}

/* Reglas de interfaz (espejo de lo que el PEP vuelve a verificar en el servidor) */
function canSign(id){
  const s=S[id],p=P();
  if(!pending(s)){
    const r={BLOQUEADA:["El PEP bloqueó esta solicitud y avisó al Oficial de Seguridad. No admite firma.","ent"],EJECUTADA:[`Esta solicitud ya se ejecutó (${D().ok.toLowerCase()}).`,"log"],RECHAZADA:["Esta solicitud fue rechazada; no admite firma.","log"],EXPIRADA:["Pasaron 48 h sin firma. Debe iniciarse una solicitud nueva.","log"],CERRADA_NO_FINANCIERA:["El orquestador la cerró: el mensaje no pide ninguna acción.","acc"],FALLO_MODELO:["El modelo falló (modo estricto): no se ejecuta nada.","trz"]}[s.estado]||["No está pendiente de firma.","log"];
    return {ok:false,show:p.rol!=="auditor",why:r[0],iso:r[1]};
  }
  if(p.rol==="auditor") return {ok:false,show:false,why:"Vista de solo lectura · Auditor.",iso:"acc"};
  if(p.rol==="admin") return {ok:false,show:true,why:"La administración de la plataforma no puede firmar operaciones (ISO 27001 8.2).",iso:"sod"};
  if(s.ini===p.id) return {ok:false,show:true,why:"Tú iniciaste esta solicitud. Por segregación de funciones debe firmarla otra persona.",iso:"sod"};
  if(s.rolSig!==p.backendRol) return {ok:false,show:true,why:`Esta solicitud la firma: ${s.rolSigTxt}. ${s.tipo?"Regla "+esc(s.tipo)+".":""}`,iso:"sod"};
  return {ok:true,show:true};
}
function whoSigns(id){
  const s=S[id];
  if(s.estado==="EJECUTADA") return [s.firmoNombre?`Firmó ${esc(s.firmoNombre)}`:"Sin firma (modo sin PEP)",""];
  if(s.estado==="BLOQUEADA") return ["No se puede firmar",""];
  if(s.estado==="RECHAZADA") return [s.rechazoPor?`No aprobó ${esc(nombreDe(s.rechazoPor))}`:"Rechazada por el PEP",""];
  if(s.estado==="EXPIRADA") return ["Sin firma en 48 h",""];
  if(!pending(s)) return ["—",""];
  if(canSign(id).ok) return ["Te corresponde","me"];
  if(s.ini===P().id) return ["La iniciaste tú · firma otra persona",""];
  return [`Le corresponde a: ${esc(s.rolSigTxt)}`,""];
}
const canReject=id=>pending(S[id])&&PUEDEN_RECHAZAR.has(P().backendRol)&&S[id].ini!==P().id;
const canExport=()=>["DIRECTOR_FINANCIERO","AUDITOR","LIDER_SRE","OFICIAL_SEGURIDAD"].includes(P().backendRol);

/* ============ Shell ============ */
function renderShell(route){
  const p=P();
  $("#brandSub").textContent=D().sub;
  $("#packtabs").innerHTML=(EST?EST.packs:[]).map(x=>`<button role="tab" aria-selected="${x.id===PACK()}" data-pack="${x.id}" title="${esc(x.nombre)}">${esc((DOM[x.id]||{}).corto||x.nombre)}</button>`).join("");
  $("#persona").innerHTML=`<button type="button" id="pbtn" aria-haspopup="menu" aria-expanded="false"><span class="avatar">${esc(p.ini)}</span><span class="who"><b>${esc(p.nombre)}</b><span>${esc(p.rolTxt)}</span></span>${ic("i-chev")}</button>
   <div class="menu" id="pmenu" role="menu"><div class="lbl">Ver la interfaz como</div>${Object.values(PERSONAS).map(x=>`<button class="mi" role="menuitemradio" aria-checked="${x.id===p.id}" data-p="${esc(x.id)}"><span class="avatar">${esc(x.ini)}</span><span><b>${esc(x.nombre)}</b><small>${esc(x.rolTxt)} · PIN demo ${esc(x.pin)}</small></span></button>`).join("")}
   <p class="muted" style="font-size:12px;margin:6px 8px">Usuarios de demostración del dominio activo. El servidor (PEP) vuelve a verificar rol, PIN y segregación en cada firma.</p></div>`;
  $("#pbtn").querySelector("svg").style.cssText="width:14px;height:14px;transform:rotate(90deg);color:var(--muted)";
  const pendMine=ORDER.filter(id=>canSign(id).ok).length;
  const cur=r=>route===r?'aria-current="page"':"";
  const primerReg=ORDER.find(id=>!pending(S[id]));
  $("#side").innerHTML=`
    <a class="nav" href="#correo" ${cur("correo")}>${ic("i-mail")}Vista en el ${isDev()?"canal":"correo"}</a>
    <a class="nav" href="#bandeja" ${cur("bandeja")}>${ic("i-inbox")}Bandeja${pendMine?`<span class="count" title="Esperan tu firma">${pendMine}</span>`:""}</a>
    <div class="navlbl">Registros</div>
    <a class="nav sub" href="#registro-${primerReg||""}" ${cur("registro")}>Registro de decisión</a>
    <a class="nav sub" href="#corte" ${cur("corte")}>Informe por corte</a>
    <a class="nav" href="#benchmark" ${cur("benchmark")} style="margin-top:8px">${ic("i-chart")}Benchmark</a>
    <div class="side-foot"><b>Un ${D().fuente} nunca autoriza nada</b>Solo abre una solicitud. Los agentes preparan, el PEP decide y una persona firma.</div>`;
  const mb=$("#modobar");
  if(EST&&EST.modo!=="COMPLETO"){
    const m=(EST.modos||[]).find(x=>x.id===EST.modo)||{};const k=EST.kpis||{};
    const dano=k.danio_formato==="cop"?cop(k.fondos_desviados_cop):k.fondos_desviados_cop;
    mb.innerHTML=`<div class="modo-off ${EST.modo==="SIN_DEFENSA"?"":"warn"}">Modo de comparación <b>${esc(EST.modo)}</b>: ${esc(m.descripcion||"")} · ${esc(k.danio_etiqueta||"Daño")}: <b>${esc(dano)}</b></div>`;
  }else mb.innerHTML="";
}
function crumbs(parts){$("#crumbs").innerHTML=parts.map((x,i)=>i===parts.length-1?`<b>${esc(x[0])}</b>`:`<a href="${x[1]}">${esc(x[0])}</a><span>›</span>`).join(" ");}

/* ============ Bandeja ============ */
const FILTROS=[["todas","Todas",()=>true],["pend","Pendientes de firma",s=>pending(s)],["BLOQUEADA","Bloqueadas",s=>s.estado==="BLOQUEADA"],["RECHAZADA","Rechazadas",s=>s.estado==="RECHAZADA"],["EJECUTADA",()=>D().ok+"s",s=>s.estado==="EJECUTADA"],["CERRADA_NO_FINANCIERA","Sin acción",s=>s.estado==="CERRADA_NO_FINANCIERA"],["EXPIRADA","Vencidas",s=>s.estado==="EXPIRADA"]];
const fTxt=f=>typeof f[1]==="function"?f[1]():f[1];
function vBandeja(){
  const p=P();
  crumbs([["Bandeja","#bandeja"]]);
  const firmante=p.rol==="firmante";
  const title=firmante?"Pendientes de mi firma":p.rol==="auditor"?"Bandeja · solo lectura":"Solicitudes";
  const sub=firmante?"Lo que espera tu firma, ordenado por llegada. Solo una persona firma cada solicitud.":p.rol==="auditor"?"Ves todo, sin acciones de firma.":"Prepara, revisa y devuelve. La firma la hace el rol que exige el PEP.";
  const mine=ORDER.filter(id=>canSign(id).ok);
  const soon=ORDER.filter(id=>pending(S[id])&&S[id].vence<12);
  const blk=ORDER.filter(id=>S[id].estado==="BLOQUEADA");
  const paid=ORDER.filter(id=>S[id].estado==="EJECUTADA");
  let rows=ORDER.filter(id=>FILTROS.find(f=>f[0]===ui.estadoFiltro)[2](S[id]));
  if(ui.riesgo.size) rows=rows.filter(id=>ui.riesgo.has(S[id].riesgo));
  if(ui.q) rows=rows.filter(id=>(id+S[id].prov+S[id].asunto).toLowerCase().includes(ui.q.toLowerCase()));
  const kpi=(lbl,n,sub,act,cls="")=>`<button class="kpi ${cls}" data-kf="${act}"><span class="lbl">${lbl}</span><span class="v">${ui.cargando?'<span class="sk" style="width:40px;height:26px;display:block"></span>':n}</span><span class="s">${sub}</span></button>`;
  let table;
  if(ui.cargando) table=`<div style="padding:18px;display:grid;gap:16px">${[80,70,90,60,75].map(w=>`<div style="display:grid;grid-template-columns:90px 1fr 120px 140px 160px;gap:20px"><div class="sk"></div><div class="sk" style="width:${w}%"></div><div class="sk"></div><div class="sk"></div><div class="sk"></div></div>`).join("")}</div>`;
  else if(ui.error) table=`<div class="state err">${ic("i-alert","big")}<h3>No pudimos cargar la bandeja</h3><p>${esc(ui.error)}. Nada se aprobó ni se ejecutó.</p><button class="btn" data-act="retry">${ic("i-refresh")}Reintentar</button></div>`;
  else if(!ORDER.length) table=`<div class="state">${ic("i-inbox","big")}<h3>La bandeja está vacía</h3><p>Envía ${isDev()?"issues o tickets":"correos"} de prueba desde el <b>Panel de pruebas</b> (arriba a la derecha) o carga los escenarios de la demo. Cada uno pasa por el pipeline real (agentes + Sanitizer + PEP)${EST&&EST.llm_real?"; con el modelo real cada uno puede tardar cerca de un minuto":""}.</p><button class="btn pri" data-act="seed-ui" ${ui.busy?"disabled":""}>${ui.busy?'<span class="spin"></span>'+esc(ui.busy):ic("i-play")+"Cargar escenarios de la demo"}</button></div>`;
  else if(!rows.length) table=`<div class="state">${ic("i-inbox","big")}<h3>Ninguna solicitud con estos filtros</h3><p>Prueba con otro estado o quita el filtro de riesgo.</p><button class="btn" data-act="clearf">Quitar filtros</button></div>`;
  else table=`<table class="t"><thead><tr><th>Riesgo</th><th>${D().ent}</th><th class="r">${D().col}</th><th>Estado</th><th>Firma</th><th>Vence en</th><th></th></tr></thead><tbody>${rows.map(id=>{const s=S[id];const w=whoSigns(id);return `<tr data-go="#solicitud-${id}"><td>${risk(s.riesgo,true)}</td><td class="ben"><b>${esc(s.prov)}</b><span class="mono">${id}</span> · <span>${esc(s.canal)} · ${esc(s.recibida)}</span> ${s.tag?`<span class="tag">${esc(s.tag)}</span>`:""}</td><td class="r num">${esc(s.montoTxt)}</td><td>${chip(s.estado)}</td><td class="who-signs ${w[1]}">${w[0]}</td><td>${pending(s)?`<span class="due ${s.vence<12?"soon":""}">${s.vence<12?"⏱ ":""}${s.vence} h</span>`:'<span class="muted">—</span>'}</td><td><a class="btn sm" href="#solicitud-${id}">Abrir</a></td></tr>`;}).join("")}</tbody></table>`;
  return `<div class="page">
   <div class="ph"><div><h1>${title}</h1><p>${sub}</p></div><span class="sp"></span><label class="search">${ic("i-search")}<input id="q" placeholder="Buscar ${D().ent.toLowerCase()}, asunto o n.º de solicitud" value="${esc(ui.q)}" aria-label="Buscar"></label></div>
   <div class="kpis">
     ${kpi(firmante?"Esperan tu firma":"Pendientes de firma",firmante?mine.length:ORDER.filter(id=>pending(S[id])).length,"Abre la más urgente primero","pend")}
     ${kpi("Vencen en menos de 12 h",soon.length,"Después vencen y hay que reiniciar","pend","warn")}
     ${kpi("Bloqueadas por el PEP",blk.length,"Alerta enviada al Oficial de Seguridad","BLOQUEADA")}
     ${kpi(D().ok+"s",paid.length,EST&&EST.modo==="COMPLETO"?"Tras firma y re-verificación del PEP":"En este modo de comparación","EJECUTADA")}
   </div>
   <div class="filters"><div class="seg" role="group" aria-label="Filtrar por estado">${FILTROS.map(f=>`<button aria-pressed="${ui.estadoFiltro===f[0]}" data-f="${f[0]}">${fTxt(f)} <span class="n">${ORDER.filter(id=>f[2](S[id])).length}</span></button>`).join("")}</div>
     <span class="sp"></span><span class="lbl">Riesgo</span>${["bajo","medio","alto"].map(r=>`<button class="rf" aria-pressed="${ui.riesgo.has(r)}" data-r="${r}"><span class="risk ${r}" style="font-size:13.5px">${ic(RISK[r][0])}${RISK[r][1].replace("Riesgo ","")}</span></button>`).join("")}</div>
   <div class="card flush">${table}</div></div>`;
}

/* ============ Expediente ============ */
const EV_TXT={RECIBIDA:"Mensaje recibido",EXTRACCION_ESQUEMA_CERRADO:"extrajo los datos a un esquema cerrado",ETIQUETADA:"etiquetó procedencia y riesgo",VALIDADA:"validó contra fuentes de verdad (solo lectura)",
  RECHAZADA:"encontró inconsistencias",CERRADA_NO_FINANCIERA:"cerró el mensaje: no pide ninguna acción",INVOCACION_HERRAMIENTA:"propuso una llamada a herramienta",DECISION_PEP:"decidió",
  ALERTA_OFICIAL_SEGURIDAD:"Alerta enviada al Oficial de Seguridad",EXPLICACION_A_HUMANO:"explicó la operación y pidió confirmación",FIRMA_DENEGADA:"Firma denegada",RECHAZADA_POR_HUMANO:"no aprobó",
  EXPIRADA:"Venció a las 48 h sin firma",VERIFICACION_FIRMAS_FALLIDA:"Re-verificación de firmas fallida",EJECUTADA:"Ejecutado",EJECUTADA_SIN_PEP:"Ejecutado sin PEP",DECISION_SANITIZER:"decidió (solo Sanitizer)",
  DECISION_VERIFICADOR_LLM:"decidió (solo modelo verificador)",FALLO_MODELO:"Fallo del modelo (modo estricto)",INCIDENTE_REVISADO:"revisó el incidente"};
const ACTOR_TXT=a=>a.startsWith("agente:")?`<b>${esc(a.slice(7).replace(/_/g," ").replace(/^./,c=>c.toUpperCase()))}</b> <span class='muted'>(agente IA)</span>`:a==="pep"?"<b>PEP</b> <span class='muted'>(código determinista)</span>":a.startsWith("humano:")?`<b>${esc(nombreDe(a.slice(7)))}</b>`:a.startsWith("canal:")?`<b>${esc(a.slice(6))}</b>`:`<b>${esc(a)}</b>`;
function timeline(id){
  const s=S[id];
  return s.eventos.map(e=>{
    const n=e.evento;let cls="",icon="i-dot",iso=null;
    if(e.actor.startsWith("agente:")){cls="agent";icon="i-bot";}
    else if(e.actor==="pep"){cls=(e.estado==="BLOQUEADA"||e.estado==="RECHAZADA"||n==="ALERTA_OFICIAL_SEGURIDAD")?"block":"pep";icon=n==="ALERTA_OFICIAL_SEGURIDAD"?"i-alert":cls==="block"?"i-lock":"i-rules";iso=cls==="block"?"ent":"sod";}
    else if(e.actor.startsWith("humano:")){cls=n.includes("DENEGADA")||n==="RECHAZADA_POR_HUMANO"?"block":"hum";icon=n.startsWith("FIRMA_")&&!n.includes("DENEGADA")?"i-pen":"i-user";iso="sup";}
    else if(e.actor.startsWith("canal:")){icon="i-mail";iso="ent";}
    else {cls=n==="EJECUTADA"||n==="EJECUTADA_SIN_PEP"?"ok":"block";icon=cls==="ok"?"i-bank":"i-x";iso="log";}
    let txt=EV_TXT[n]||n.replace(/_/g," ").toLowerCase();
    if(/^FIRMA_\d$/.test(n)) txt=`firmó con PIN (MFA)${(e.payload||{}).verificacion_telefonica?" · verificación telefónica ✓":""}`;
    if(n==="DECISION_PEP") txt+=` <b>${esc((e.payload||{}).decision||e.estado||"")}</b>${(e.payload||{}).regla_principal?" · "+esc(e.payload.regla_principal):""}`;
    if(n==="RECHAZADA_POR_HUMANO"&&(e.payload||{}).motivo) txt+=`: «${esc(e.payload.motivo)}»`;
    if(n==="FIRMA_DENEGADA"&&(e.payload||{}).motivo) txt+=`: ${esc(e.payload.motivo)}`;
    const quien=["RECIBIDA","ALERTA_OFICIAL_SEGURIDAD","EXPIRADA","FALLO_MODELO","EJECUTADA","EJECUTADA_SIN_PEP"].includes(n)?"":ACTOR_TXT(e.actor)+" ";
    return [cls,icon,quien?quien+txt:`<b>${txt}</b>${e.actor.startsWith("canal:")?" · "+esc(e.actor.slice(6)):""}`,hhmmss(e.ts),iso];
  });
}
function vExpediente(id){
  const s=S[id];if(!s) return vNotFound();
  const p=P();crumbs([["Bandeja","#bandeja"],[id,""]]);
  const c=canSign(id);
  const whyCls=pending(s)?"pend":s.estado==="BLOQUEADA"||s.estado==="RECHAZADA"||s.estado==="FALLO_MODELO"?"block":s.estado==="EJECUTADA"?"ok":"neu";
  const whyIc={pend:"i-pen",block:"i-lock",ok:"i-check",neu:"i-clock"}[whyCls];
  const auditor=p.rol==="auditor";
  const m=s.correo;
  const mail=m?`<div class="mail">
      <div class="untrusted">${ic("i-alert")}Contenido externo, no confiable. El sistema no ejecuta instrucciones que aparezcan aquí.</div>
      <div class="hdr"><div><span>De:</span> <b class="mono" style="font-size:13px">${esc(m.de)}</b></div><div><span>Canal:</span> ${esc(s.canal)}</div><div><span>Asunto:</span> <b>${esc(m.asunto)}</b></div></div>
      <div class="body">${m.cuerpo.map(x=>`<p>${x}</p>`).join("")}${m.oculto?`<span class="hidden-txt">${esc(m.oculto)}</span>`:""}</div>
      ${m.adj?`<span class="attach">${ic("i-file")}${esc(m.adj)}</span>`:""}
      ${(m.evid.length||m.oculto)?"":`<span class="m-ok">${ic("i-check")}Sin frases sospechosas</span>`}
    </div>`:`<div class="state" style="padding:24px">${ic("i-user","big")}<h3>Sin ${D().fuente} de origen</h3><p>Creada por ${esc(nombreDe(s.ini))} en el canal interno. Por eso esa persona no puede firmarla.</p></div>`;
  const signBtn=c.show?(c.ok?`<a class="btn pri lg hum" href="#firmar-${id}">${ic("i-pen")}Firmar</a>`:`<button class="btn lg is-dis" disabled aria-describedby="whydis">${ic("i-lock")}Firmar</button>`):"";
  const nd=s.cmp.filter(r=>!r[3]).length;
  return `<div class="page">
   <div class="exp-head">
     <div class="meta"><span class="lbl">${id} · ${esc(s.canal)} · recibida ${esc(s.fecha)}${s.modo&&s.modo!=="COMPLETO"?` · modo ${esc(s.modo)}`:""}</span>
       <div class="title"><h1>${esc(s.prov)}</h1>${chip(s.estado)}</div>
       <div class="title"><span class="amount">${esc(s.montoTxt)}</span>${risk(s.riesgo)}${pending(s)?`<span class="due ${s.vence<12?"soon":""}">${ic("i-clock").replace("<svg","<svg style='width:14px;height:14px;vertical-align:-2px'")} vence en ${s.vence} h</span>`:""}</div></div>
     <div class="actions"><div class="row">
       ${!pending(s)?`<a class="btn" href="#registro-${id}">${ic("i-doc")}Ver registro</a>`:""}
       ${canReject(id)?`<button class="btn danger lg" data-act="reject" data-id="${id}">${ic("i-x")}No aprobar</button>`:""}
       ${signBtn}</div>
       ${c.show&&!c.ok?`<div class="why-dis" id="whydis">${ic("i-lock")}<span>${c.why} <span class="iso" style="margin-left:4px">${ISO[c.iso].split(" ").slice(0,2).join(" ")}</span></span></div>`:""}
       ${auditor?`<div class="why-dis" style="border-color:var(--accent)">${ic("i-doc")}<span>Vista de solo lectura · Auditor</span></div>`:""}
     </div>
   </div>
   <div class="why ${whyCls}"><span class="ic">${ic(whyIc)}</span><div><span class="lbl">Por qué${s.explicacion.resumen?" · explicación del agente explicador":s.estado==="CERRADA_NO_FINANCIERA"?" · justificación del orquestador":""}${s.explicacion.recomendacion?` · recomienda ${esc(s.explicacion.recomendacion.replace("_"," ").toLowerCase())}`:""}</span><p>${esc(s.porque)}</p>${s.explicacion.pregunta_confirmacion&&pending(s)?`<p style="margin-top:6px"><b>${esc(s.explicacion.pregunta_confirmacion)}</b></p>`:""}<div class="isos">${s.iso.map(isoTag).join("")}</div></div></div>
   <div class="cols3">
     <div class="card"><div class="card-h">${ic("i-mail").replace("<svg","<svg style='width:18px;height:18px;color:var(--muted)'")}<h2>Lo que llegó</h2></div>${mail}</div>
     <div class="card flush"><div class="card-h" style="padding:16px 16px 4px"><h2>Lo que entendió el sistema</h2><span class="sp"></span><span class="muted" style="font-size:13px">vs ${D().maestro}</span></div>
       ${s.cmp.length?`<table class="cmp"><thead><tr><th>Campo</th><th>En la solicitud</th><th>Verificación</th><th></th></tr></thead><tbody>
       ${s.cmp.map(r=>`<tr class="${r[3]?"":"diff"}"><td>${esc(r[0])}</td><td class="v">${esc(r[1])}</td><td class="v" style="${r[3]?"":"color:var(--ink);font-weight:500"}">${esc(r[2])}</td><td>${r[3]?`<span class="m-ok">${ic("i-check")}Coincide</span>`:`<span class="m-no">${ic("i-x")}${esc(r[4])}</span>`}</td></tr>`).join("")}
       </tbody></table>`:`<div class="state" style="padding:20px"><p>${s.estado==="CERRADA_NO_FINANCIERA"?"El orquestador cerró el mensaje antes de validar: no pide ninguna acción, así que el agente ejecutor nunca se invocó.":"En este modo no hubo validación contra fuentes de verdad."}</p></div>`}
       <div style="padding:10px 16px 14px" class="muted"><span style="font-size:13px">${nd?`${nd} diferencia(s) resaltadas en rojo.`:s.cmp.length?`Todo coincide con el ${D().maestro}.`:""} El PEP vuelve a consultar las fuentes por su cuenta; esta tabla informa, no decide.</span></div>
     </div>
     <div class="card tlcard"><h2>Qué pasó</h2><div class="tl">${timeline(id).map(x=>`<div class="tli ${x[0]}"><span class="nd">${ic(x[1])}</span><div class="tx">${x[2]}${x[3]?` · <span class="t">${x[3]}</span>`:""}${x[4]?`<br>${isoTag(x[4])}`:""}</div></div>`).join("")}
       ${pending(s)?`<div class="tli wait"><span class="nd">${ic("i-pen")}</span><div class="tx"><b>Firma pendiente</b> · ${esc(s.rolSigTxt)} · vence en ${s.vence} h</div></div>`:""}</div>
       <div class="muted" style="font-size:12.5px;display:flex;gap:12px;flex-wrap:wrap;border-top:1px solid var(--line-2);padding-top:10px"><span>▢ agente IA · prepara</span><span>■ PEP · decide</span><span>● persona · firma</span></div></div>
   </div>
   <details class="tech" ${auditor?"open":""}><summary>${ic("i-chev")}Detalle técnico${auditor?" · expandido para Auditor":""}</summary>
     <dl class="techgrid"><dt>Etiquetas del Sanitizer</dt><dd>origen=${esc(s.meta.origen||"—")} · tainted=${esc(s.meta.tainted)} · riesgo=${esc(String(s.meta.nivel_riesgo||"—"))}${(s.meta.banderas_anomalia||[]).length?" · banderas="+esc(s.meta.banderas_anomalia.join(", ")):""}</dd>
       <dt>Sello de metadatos</dt><dd>${esc(corto(s.sello))}</dd>
       <dt>Reglas del PEP</dt><dd>${s.reglas.length?s.reglas.map(r=>`<b>${esc(r.codigo)}</b> ${esc(r.descripcion)} <span class="muted">(${esc(r.decision)})</span>`).join("<br>"):"—"}</dd>
       <dt>Hash de la acción</dt><dd>${esc(corto(s.hash))}</dd>
       <dt>Último evento</dt><dd>${s.eventos.length?`${esc(corto(s.eventos[s.eventos.length-1].hash_actual))} ← anterior ${esc(corto(s.eventos[s.eventos.length-1].hash_anterior))}`:"—"}</dd>
       <dt>Latencia del pipeline</dt><dd>${esc(s.raw.latencia_total_ms)} ms · modelo ${esc(llmTxt(EST&&EST.llm))}</dd></dl></details>
  </div>`;
}

/* ============ Firma (una sola persona) ============ */
function resumenFirma(s){
  const dv=s.dv,e=s.ext;
  if(isDev()) return `<dt>Recurso</dt><dd>${esc(dv.recurso||e.recurso)} · ${esc(dv.entorno||e.entorno)}</dd><dt>Acción</dt><dd class="amount" style="font-size:22px">${esc(dv.accion||e.accion)} ${esc(dv.parametros||"")}</dd><dt>Ticket</dt><dd>${esc(dv.ticket_cambio||e.ticket_cambio||"—")}</dd><dt>Fuente</dt><dd>${esc(dv.fuente||"—")}</dd>`;
  return `<dt>Beneficiario</dt><dd>${esc(dv.beneficiario||s.prov)}${s.nit&&s.nit!=="—"?" · "+esc(s.nit):""}</dd><dt>Cuenta</dt><dd>${esc(dv.cuenta||e.cuenta_destino||"—")} <span class="muted">(${esc(dv.fuente||"")})</span></dd>
     <dt>Monto</dt><dd class="amount" style="font-size:24px">${cop(s.monto)} COP</dd><dt>Respaldo</dt><dd>${esc([e.numero_factura,e.numero_oc].filter(Boolean).join(" · ")||"—")}</dd>`;
}
function vFirmar(id){
  const s=S[id];if(!s) return vNotFound();
  crumbs([["Bandeja","#bandeja"],[id,"#solicitud-"+id],["Firmar",""]]);
  const c=canSign(id);
  if(!ui.sign||ui.sign.id!==id) ui.sign={id,step:1,checked:false,err:null,phase:null,res:null};
  const st=ui.sign;
  if(!c.ok&&!st.phase){
    return `<div class="sign-wrap"><div class="sign-card"><div class="result block"><span class="big">${ic("i-lock")}</span><h2>No puedes firmar esta solicitud</h2><p>${c.why}</p>${isoTag(c.iso)}<div class="foot"><a class="btn" href="#solicitud-${id}">Volver al expediente</a></div></div></div></div>`;
  }
  const steps=[["Resumen"],["PIN (MFA)"]];
  const stepper=`<div class="stepper">${steps.map((x,i)=>`${i?'<span class="stp-ln"></span>':""}<span class="stp ${i+1===st.step?"on":i+1<st.step?"done":""}"><i>${i+1<st.step?"✓":i+1}</i>${x[0]}</span>`).join("")}<span class="sp"></span><span class="chip c-hum">${ic("i-pen")}Una firma: ${esc(s.rolSigTxt)} · vence en ${s.vence} h</span></div>`;
  let body="";
  if(st.phase==="enviando") return `<div class="sign-wrap"><div class="sign-card"><div class="result hum"><span class="big">${ic("i-pen")}</span><h2>Firma enviada</h2><p>El PEP está verificando de nuevo PIN, rol, segregación de funciones y el hash de la acción antes de ejecutar.</p><span class="muted" style="font-size:13px"><span class="spin" style="vertical-align:-3px;color:var(--accent)"></span> Re-verificando…</span></div></div></div>`;
  if(st.phase==="hecha"){
    const r=st.res||{};const ok=r.estado==="EJECUTADA";
    return `<div class="sign-wrap"><div class="sign-card"><div class="result ${ok?"ok":"block"}"><span class="big">${ic(ok?"i-check":"i-alert")}</span><h2>${ok?D().okVerbo:"El PEP no ejecutó la acción"}</h2><p>${esc(r.mensaje||"")}</p>${ok?`<p class="muted">Se generó el registro ${D().adr}-${id.slice(4)} con tu firma.</p>`:""}<div class="foot"><a class="btn" href="#solicitud-${id}">Ver expediente</a><a class="btn pri" href="#registro-${id}">${ic("i-doc")}Ver registro</a><a class="btn" href="#bandeja">Volver a la bandeja</a></div></div></div></div>`;
  }
  if(st.step===1){
    body=`<h2 style="font-size:22px">${D().autoriza}</h2>
     ${s.explicacion.resumen?`<div class="why pend" style="margin:0"><span class="ic">${ic("i-bot")}</span><div><span class="lbl">El agente explicador te cuenta qué vas a autorizar</span><p>${esc(s.explicacion.resumen)}</p>${s.explicacion.pregunta_confirmacion?`<p style="margin-top:6px"><b>${esc(s.explicacion.pregunta_confirmacion)}</b></p>`:""}</div></div>`:""}
     <dl class="sum">${resumenFirma(s)}<dt>Hash de la acción</dt><dd class="mono" style="font-size:12.5px">${esc(corto(s.hash))}</dd>
     <dt>Por qué firmas tú</dt><dd>Eres ${esc(P().rolTxt.toLowerCase())} y no iniciaste esta solicitud. ${esc(s.tipo)}.</dd></dl>
     ${s.llamada?`<label class="chk-tel"><input type="checkbox" id="chk" ${st.checked?"checked":""}><span>${ic("i-phone").replace("<svg","<svg style='width:16px;height:16px;vertical-align:-3px'")} Llamé al teléfono registrado en el maestro <b class="mono">${esc(s.telefono||"")}</b> (no al del correo) y el proveedor confirmó la cuenta y el monto. <span class="muted">(Regla R7)</span></span></label>`:""}
     <div style="display:flex;gap:6px;flex-wrap:wrap">${isoTag("sod")}${isoTag("sup")}${s.llamada?isoTag("ver"):""}</div><div class="foot"><span class="sp"></span><a class="btn" href="#solicitud-${id}">Cancelar</a><button class="btn pri lg" data-act="next" ${s.llamada&&!st.checked?"disabled":""}>Continuar</button></div>`;
  } else {
    const n=(P().pin||"0000").length;
    body=`<h2 style="font-size:22px">${ic("i-key").replace("<svg","<svg style='width:20px;height:20px;vertical-align:-3px;color:var(--human)'")} Ingresa tu PIN de ${n} dígitos</h2>
     <p class="muted" style="margin:0">Es el segundo factor (MFA simulado). <span class="mono" style="font-size:12.5px">Demo: el PIN de ${esc(P().nombre)} es ${esc(P().pin)}.</span></p>
     <div class="code ${st.err?"err":""}" id="code">${Array.from({length:n},(_,i)=>`<input inputmode="numeric" maxlength="${n}" aria-label="Dígito ${i+1}" id="d${i}">`).join("")}</div>
     ${st.err?`<div class="err-msg">${ic("i-alert")}${esc(st.err)}</div>`:""}
     <div class="foot"><span class="muted" style="font-size:13px">Al firmar no se ejecuta de inmediato: el PEP verifica de nuevo.</span><span class="sp"></span><button class="btn" data-act="back">Atrás</button><button class="btn hum lg" data-act="sign">${ic("i-pen")}Firmar y autorizar</button></div>`;
  }
  return `<div class="sign-wrap"><div class="sign-card">${stepper}${body}</div><span class="muted" style="font-size:13px">Firmas como <b>${esc(P().nombre)}</b> · ${esc(P().rolTxt)}. Cancelar no registra nada.</span></div>`;
}
const leerPin=()=>[...document.querySelectorAll("#code input,.pcode input")].map(i=>i.value).join("");
async function enviarFirma(id,pin,tel){
  try{const r=await api(`/api/solicitudes/${id}/firmar`,{method:"POST",body:{usuario_id:P().id,pin,verificacion_telefonica:!!tel}});await cargar();return {ok:true,r};}
  catch(e){await cargar();return {ok:false,err:e.message};}
}

/* ============ Registro ADR ============ */
function vRegistro(id){
  const s=S[id];if(!s) return ORDER.length?vNotFound():`<div class="page"><div class="card"><div class="state">${ic("i-doc","big")}<h3>Aún no hay registros</h3><p>Los registros de decisión aparecen cuando una solicitud se cierra.</p><a class="btn" href="#bandeja">Ir a la bandeja</a></div></div></div>`;
  crumbs([["Registros","#corte"],[`${D().adr}-${id.slice(4)}`,""]]);
  if(pending(s)) return `<div class="page"><div class="card"><div class="state">${ic("i-doc","big")}<h3>Este registro todavía no existe</h3><p>El registro de decisión se genera cuando la solicitud se cierra: ejecutada, bloqueada, rechazada o vencida.</p><a class="btn" href="#solicitud-${id}">Volver al expediente</a></div></div></div>`;
  const dec={EJECUTADA:s.firmo?`Ejecutar tras una firma humana con PIN y la re-verificación del PEP.`:`Ejecutado sin firma humana (modo de comparación ${s.modo}).`,BLOQUEADA:"Bloquear y alertar al Oficial de Seguridad. No admite firma.",RECHAZADA:s.rechazoPor?"No aprobar por decisión humana; devolver al área solicitante.":"Rechazar por inconsistencias y devolver al área solicitante.",EXPIRADA:"Cerrar por vencimiento: 48 h sin firma.",CERRADA_NO_FINANCIERA:"Cerrar sin acción: el mensaje no pedía ninguna operación.",FALLO_MODELO:"No ejecutar: el modelo falló y el modo estricto no usa respaldo."}[s.estado]||s.estado;
  const v=ui.verify&&ui.verify.id===id?ui.verify:null;
  const exp=canExport();
  const ult=s.eventos[s.eventos.length-1]||{};
  const nd=s.cmp.filter(r=>!r[3]);
  return `<div class="page"><div class="adr-layout">
   <article class="paper" aria-label="Registro de decisión">
     <div class="doc-top"><span>Registro de decisión · ADR</span><span>Página 1 de 1</span></div>
     <h1>${D().adr}-${id.slice(4)} · ${s.estado==="EJECUTADA"?(isDev()?"Cambio en":"Pago a"):"Solicitud para"} ${esc(s.prov)}</h1>
     <div class="sub"><span>Emitido: ${esc(s.firmaHora||fechaTxt(ult.ts))}</span><span>·</span><span>Versión 1</span><span>·</span><span>Origen: ${id}</span><span>·</span><span>Dominio: ${esc(EST.pack.nombre)}</span></div>
     <section><h3>1 · Identificador</h3><div class="c"><dl class="kv"><dt>Registro</dt><dd class="mono">${D().adr}-${id.slice(4)}</dd><dt>Solicitud</dt><dd class="mono">${id}</dd><dt>Canal</dt><dd>${s.correo?esc(s.canal)+" · "+esc(s.correo.de):"Canal interno"}</dd></dl></div></section>
     <section><h3>2 · Estado</h3><div class="c"><div>${chip(s.estado)}</div></div></section>
     <section><h3>3 · Contexto</h3><div class="c"><p>${isDev()?`Solicitud de ${esc(s.montoTxt)} sobre ${esc(s.prov)} (${esc(s.nit)})`:`Solicitud de pago por ${cop(s.monto)} COP a ${esc(s.prov)}`}, ${s.correo?`originada en «${esc(s.correo.asunto)}»`:"creada por el canal interno"}. Un ${D().fuente} no autoriza nada; solo abre una solicitud.</p></div></section>
     <section><h3>4 · Evaluación</h3><div class="c"><p>Riesgo asignado por el Sanitizer: <b>${esc(s.riesgo)}</b>. Reglas activadas en el PEP:</p>${s.reglas.length?`<ul style="margin:4px 0 0 18px">${s.reglas.map(r=>`<li><b>${esc(r.codigo)}</b> · ${esc(r.descripcion)} <span class="muted">(${esc(r.decision)})</span></li>`).join("")}</ul>`:"<p>Ninguna regla activada.</p>"}${nd.length?`<p>Diferencias con el ${D().maestro}: ${nd.map(r=>esc(r[0])+" ("+esc(String(r[4]).toLowerCase())+")").join(", ")}.</p>`:""}</div></section>
     <section><h3>5 · Decisión</h3><div class="c"><p>${esc(dec)}</p><p class="muted" style="font-family:var(--font-body);font-size:14px">${esc(s.porque)}</p></div></section>
     <section><h3>6 · Firma</h3><div class="c">${s.firma?`<dl class="kv"><dt>Firmante</dt><dd>${esc(s.firma.nombre)} · ${esc(s.firma.rol)}</dd><dt>Factores</dt><dd>PIN (MFA) ✓${s.firma.verificacion_telefonica?" · verificación telefónica ✓":""}</dd><dt>Fecha</dt><dd>${esc(s.firmaHora)}</dd><dt>Firma HMAC</dt><dd class="hash">hmac-sha256:${esc(s.firma.firma_hmac.slice(0,12))}…${esc(s.firma.firma_hmac.slice(-6))}</dd><dt>Hash firmado</dt><dd class="hash">${esc(corto(s.firma.hash_transaccion))}</dd></dl><div class="sigline">${esc(s.firma.nombre)} · ${esc(s.firma.rol)}</div>`:s.rechazoPor?`<p>No aprobó: ${esc(nombreDe(s.rechazoPor))}. Motivo: «${esc(s.motivo)}».</p>`:"<p>Sin firmas. Ningún agente de IA puede firmar.</p>"}</div></section>
     <section><h3>7 · Controles ISO</h3><div class="c"><div style="display:flex;gap:6px;flex-wrap:wrap">${[...new Set([...s.iso,"log","trz"])].map(isoTag).join("")}</div></div></section>
     <section><h3>8 · Integridad</h3><div class="c"><dl class="kv"><dt>Hash del último evento</dt><dd class="hash">${esc(corto(ult.hash_actual))}</dd><dt>Hash anterior</dt><dd class="hash">${esc(corto(ult.hash_anterior))}</dd><dt>Cadena</dt><dd>${s.eventos.length} eventos de esta solicitud (eslabones #${s.eventos.map(e=>e.seq).join(", #")}) en el registro append-only de ${INTEG?INTEG.entradas:"N"} entradas</dd></dl></div></section>
   </article>
   <aside class="side-panel">
     <div class="card"><span class="lbl">Acciones</span>
       <div class="dd">${exp?`<button class="btn" style="width:100%" data-act="exp" aria-haspopup="menu">${ic("i-down")}Exportar ▾</button><div class="dd-menu" id="expmenu"><button data-x="PDF" data-id="${id}">PDF <span class="muted">imprimir / guardar</span></button><button data-x="JSON" data-id="${id}">JSON <span class="muted">para sistemas</span></button></div>`:`<button class="btn is-dis" style="width:100%" disabled>${ic("i-lock")}Exportar</button><div class="why-dis" style="margin-top:8px">${ic("i-lock")}<span>Disponible para Director, Líder SRE, Oficial de Seguridad y Auditor.</span></div>`}</div>
       <button class="btn pri" data-act="verify" data-id="${id}" ${v&&v.state==="run"?"disabled":""}>${v&&v.state==="run"?'<span class="spin"></span>Verificando…':ic("i-shield")+"Verificar integridad"}</button>
       ${v&&v.state==="run"?`<div class="vstate run"><b><span class="spin"></span>Verificando la cadena</b><span class="muted">Recalculando hashes de los eventos del registro…</span></div>`:""}
       ${v&&v.state==="ok"?`<div class="vstate ok"><b>${ic("i-check")}Íntegro</b><span>Las ${v.r.entradas} entradas coinciden con su hash y con el eslabón anterior. ${esc(v.r.detalle)}.</span></div>`:""}
       ${v&&v.state==="bad"?`<div class="vstate bad"><b>${ic("i-alert")}Alteración detectada</b><span>${esc(v.r.detalle)}. Se debe avisar al Oficial de Seguridad.</span></div>`:""}
     </div>
     <div class="card"><span class="lbl">Otros registros</span>${ORDER.filter(x=>!pending(S[x])).map(x=>`<a class="lnk" href="#registro-${x}" style="display:flex;justify-content:space-between;gap:8px;${x===id?"color:var(--ink)":""}"><span>${D().adr}-${x.slice(4)}</span>${chip(S[x].estado)}</a>`).join("")}<a class="btn sm" href="#corte">Ver informe por corte</a></div>
   </aside></div></div>`;
}

/* ============ Informe por corte ============ */
function vCorte(){
  crumbs([["Registros","#corte"],["Informe por corte",""]]);
  const cnt=e=>ORDER.filter(id=>S[id].estado===e).length;
  const resp=id=>{const s=S[id];
    if(s.estado==="EJECUTADA")return s.firma?[esc(s.firma.nombre),esc(s.firma.rol),"Firmó"]:["Sin control",`modo ${esc(s.modo)}`,"Ejecutó sin firma"];
    if(s.estado==="BLOQUEADA")return ["PEP","regla "+esc(s.regla),"Bloqueó"];
    if(s.estado==="RECHAZADA")return s.rechazoPor?[esc(nombreDe(s.rechazoPor)),esc((PERSONAS[s.rechazoPor]||{}).rolTxt||""),"No aprobó"]:["PEP","regla "+esc(s.regla),"Rechazó"];
    if(s.estado==="EXPIRADA")return ["Sistema","vencimiento 48 h","Venció"];
    if(s.estado==="CERRADA_NO_FINANCIERA")return ["Orquestador","sin acción","Cerró"];
    if(s.estado==="FALLO_MODELO")return ["Sistema","modo estricto","No ejecutó"];
    return ["Pendiente",esc(s.rolSigTxt),"Pidió firma"];};
  return `<div class="page">
   <div class="ph"><div><h1>Informe por corte</h1><p>Cronograma de operaciones del dominio <b>${esc(EST?EST.pack.nombre:"")}</b>: fecha, responsable, decisión y estado. Cada fila abre su registro.</p></div><span class="sp"></span>
     <button class="btn" data-act="verify-corte">${ic("i-shield")}Verificar integridad del corte</button>${canExport()?`<button class="btn" data-act="export-corte">${ic("i-down")}Exportar corte (JSON)</button>`:`<button class="btn is-dis" disabled title="Disponible para Director, Líder SRE, Oficial de Seguridad y Auditor">${ic("i-lock")}Exportar corte</button>`}</div>
   <div class="kpis" style="grid-template-columns:repeat(6,minmax(0,1fr))">
     ${[["Solicitudes",ORDER.length],[D().ok+"s",cnt("EJECUTADA")],["Pendientes",ORDER.filter(id=>pending(S[id])).length],["Bloqueadas",cnt("BLOQUEADA")],["Rechazadas",cnt("RECHAZADA")],["Sin acción",cnt("CERRADA_NO_FINANCIERA")]].map(x=>`<div class="kpi" style="cursor:default"><span class="lbl">${x[0]}</span><span class="v">${x[1]}</span></div>`).join("")}
   </div>
   <div class="card flush">${ORDER.length?`<table class="t"><thead><tr><th>Fecha y hora</th><th>Solicitud</th><th>${D().ent}</th><th class="r">${D().col}</th><th>Responsable</th><th>Decisión</th><th>Estado</th><th>Control</th><th></th></tr></thead><tbody>
   ${ORDER.map(id=>{const s=S[id],r=resp(id);return `<tr data-go="${pending(s)?"#solicitud-":"#registro-"}${id}"><td class="num" style="font-size:13px">${esc(s.firmaHora||s.fecha)}</td><td class="mono" style="font-size:13px">${id}</td><td>${esc(s.prov)}</td><td class="r num">${esc(s.montoTxt)}</td><td><b style="font-weight:600">${r[0]}</b><br><span class="muted" style="font-size:12.5px">${r[1]}</span></td><td>${r[2]}</td><td>${chip(s.estado)}</td><td><span class="iso">${ISO[s.iso[0]].split(" ").slice(0,2).join(" ")}</span></td><td>${pending(s)?`<a class="btn sm" href="#solicitud-${id}">Expediente</a>`:`<a class="btn sm" href="#registro-${id}">Registro</a>`}</td></tr>`;}).join("")}
   </tbody></table>`:`<div class="state">${ic("i-doc","big")}<h3>Sin operaciones en el corte</h3><p>Envía escenarios desde el Panel de pruebas.</p></div>`}</div>
   <p class="muted" style="margin:0;font-size:13px">Ningún agente de IA figura como responsable de una decisión: los agentes preparan, el PEP decide y una persona firma.</p></div>`;
}

/* ============ Benchmark (último reporte real de evaluacion_empirica.py) ============ */
function ringSVG({size,stroke,segs,center,badges=true,gap=7}){
  const c=size/2,r=c-stroke-(badges?16:2),pt=(d)=>{const a=(d-90)*Math.PI/180;return [c+r*Math.cos(a),c+r*Math.sin(a)];};
  const arc=(a0,a1)=>{const [x0,y0]=pt(a0),[x1,y1]=pt(a1);return `M${x0.toFixed(1)} ${y0.toFixed(1)}A${r} ${r} 0 ${a1-a0>180?1:0} 1 ${x1.toFixed(1)} ${y1.toFixed(1)}`;};
  segs=segs.filter(s=>s.w>0);
  const tot=segs.reduce((a,b)=>a+b.w,0)||1;let a=0,out=`<circle cx="${c}" cy="${c}" r="${r}" class="track" stroke-width="${stroke}"/>`,bd="";
  segs.forEach(s=>{const sp=360*s.w/tot,g=segs.length>1?gap:0,a0=a+g/2,a1=a+Math.min(sp,359.9)-g/2;out+=`<path d="${arc(a0,a1)}" fill="none" stroke="${s.col}" stroke-width="${stroke}" stroke-linecap="round" ${s.dash?`stroke-dasharray="${s.dash}"`:""}/>`;
    if(badges&&s.label){const [x,y]=pt((a0+a1)/2);const w=Math.max(34,String(s.label).length*9+16);bd+=`<rect x="${x-w/2}" y="${y-13}" width="${w}" height="26" rx="13" fill="${s.col}" class="badge"/><text x="${x}" y="${y+4.5}" text-anchor="middle" class="badge-t" fill="${s.ink||"var(--surface)"}">${s.label}</text>`;}a+=sp;});
  let ct="";if(center.length===3){ct=`<text x="${c}" y="${c-size*.1}" text-anchor="middle" class="c1">${center[0]}</text><text x="${c}" y="${c+size*.07}" text-anchor="middle" class="c2" font-size="${size*.17}">${center[1]}</text><text x="${c}" y="${c+size*.17}" text-anchor="middle" class="c3">${center[2]}</text>`;}
  else ct=`<text x="${c}" y="${c+size*.07}" text-anchor="middle" class="c2" font-size="${size*.2}">${center[0]}</text>`;
  return `<svg viewBox="0 0 ${size} ${size}" width="${size}" height="${size}" role="img" aria-label="${center.join(" ")}">${out}${bd}${ct}</svg>`;
}
const pct=x=>x==null?"—":`${Math.round(x*10)/10} %`;
const nde=(p,n)=>p==null||!n?"":`${Math.round(p*n/100)} de ${n}`;
const MODO_TXT={COMPLETO:"Sanitizer + PEP",SOLO_PEP:"Solo PEP",SOLO_SANITIZER:"Solo Sanitizer",SOLO_LLM:"Solo modelo verificador",SIN_DEFENSA:"Sin defensa"};
function vBenchmark(){
  crumbs([["Benchmark",""]]);
  if(!BENCH) return `<div class="page"><div class="ph"><div><h1>¿Cómo le fue al firewall?</h1></div></div><div class="card"><div class="state err">${ic("i-alert","big")}<h3>No encontramos resultados de la batería</h3><p>${esc(BENCH_ERR||"Todavía no hay una ejecución registrada.")} La batería corre fuera de la app (<span class="mono">python evaluacion_empirica.py</span>); cuando termine, los resultados aparecen aquí.</p><button class="btn" data-act="retry-b">${ic("i-refresh")}Volver a cargar</button></div></div></div>`;
  const B=BENCH,cf=B.configuraciones||{},C=cf.COMPLETO||{},SD=cf.SIN_DEFENSA||{},n=B.n||{};
  const nA=n.ATAQUE||0,nL=n.LEGITIMO||0;
  const blq=Math.round((C.tasa_bloqueo_ataques_pct||0)*nA/100),noDet=nA-blq;
  const legOk=Math.round((C.completitud_legitimas_pct||0)*nL/100),fp=Math.round((C.falsos_positivos_pct||0)*nL/100);
  const segs=[{w:blq,col:"var(--accent)",label:blq},{w:legOk,col:"var(--ok)",label:legOk},{w:fp,col:"var(--warn)",label:fp,dash:"12 6"},{w:noDet,col:"var(--crit)",label:noDet,dash:"2 6"}];
  const bk=(lbl,val,d)=>`<div class="bk"><span class="lbl">${lbl}</span><span class="v">${val}</span><span class="d">${d}</span></div>`;
  const fecha=B.generado?fechaTxt(B.generado):"—";
  const llm=llmTxt(B.llm);
  const ataEjec=m=>m.ataques_ejecutados??Math.round((100-(m.tasa_bloqueo_ataques_pct||0))*nA/100);
  const bar=(lbl,val,tot,col)=>`<div class="cmprow"><span>${lbl}</span><div class="cbar"><span style="width:${tot?Math.round(val/tot*100):0}%;background:${col}"></span></div><span class="mono">${val} de ${tot}</span></div>`;
  const orden=["COMPLETO","SOLO_PEP","SOLO_SANITIZER","SOLO_LLM","SIN_DEFENSA"].filter(k=>cf[k]);
  return `<div class="page">
   <div class="ph"><div><h1>¿Cómo le fue al firewall?</h1><p>Resultados de la batería de escenarios del dominio <b>${esc(B.nombre_dominio||"")}</b>: legítimos y ataques, procesados con cada combinación de defensas.</p></div><span class="sp"></span>
     <span class="stamp">${ic("i-check")}Última ejecución · <b class='mono'>${esc(fecha)}</b> · <b class='mono'>${nA+nL+(n.IRRELEVANTE||0)}</b> escenarios · modelo <b class='mono'>${esc(llm)}</b>${B.repeticiones?` · ${B.repeticiones} rep.`:""}</span>${B.simulador?`<span class="ph-note" title="Aún no hay un reporte con modelo real para este dominio">Simulador, no modelo real</span>`:""}</div>
   <div class="bench-top">
     <div class="card" style="justify-items:center"><span class="lbl" style="justify-self:start">Resultado con Sanitizer + PEP</span>
       <div class="ring">${ringSVG({size:300,stroke:14,segs,center:["Ataques bloqueados",pct(C.tasa_bloqueo_ataques_pct),`${blq} de ${nA}`]})}</div>
       <div class="leg" style="justify-self:stretch">
         <div><span class="sw" style="border-top-color:var(--accent)"></span>Ataques bloqueados<b class="mono">${blq}</b></div>
         <div><span class="sw" style="border-top-color:var(--ok)"></span>${D().legit}<b class="mono">${legOk}</b></div>
         <div><span class="sw" style="border-top-color:var(--warn);border-top-style:dashed"></span>Falsos positivos (legítimos detenidos)<b class="mono">${fp}</b></div>
         <div><span class="sw" style="border-top-color:var(--crit);border-top-style:dotted"></span>Ataques no detectados<b class="mono">${noDet}</b></div>
       </div>
       <span class="muted" style="font-size:12.5px;justify-self:start">Archivo: <span class="mono">${esc(B.archivo)}</span>${(B.excluidos_por_fallo_modelo||[]).length?` · ${B.excluidos_por_fallo_modelo.length} escenario(s) excluidos por fallo del modelo`:""}</span></div>
     <div style="display:grid;gap:16px;align-content:start">
       <div class="kgrid">
         ${bk("Tasa de bloqueo de ataques",`${pct(C.tasa_bloqueo_ataques_pct)} <small>· ${nde(C.tasa_bloqueo_ataques_pct,nA)}</small>`,"Ataques detenidos antes de ejecutar")}
         ${bk(D().legit,`${pct(C.completitud_legitimas_pct)} <small>· ${nde(C.completitud_legitimas_pct,nL)}</small>`,"Legítimos que llegaron a ejecutarse tras la firma")}
         ${bk("Falsos positivos",`${pct(C.falsos_positivos_pct)} <small>· ${nde(C.falsos_positivos_pct,nL)}</small>`,"Legítimos detenidos por error")}
         ${bk("Aislamiento del agente ejecutor",`${pct(C.aislamiento_financiero_pct)} <small>· ${nde(C.aislamiento_financiero_pct,n.IRRELEVANTE)}</small>`,"Mensajes sin acción que nunca llegaron al ejecutor")}
         ${bk("Pruebas adversariales al PEP",`${esc(B.pruebas_adversariales||"—")}`,"Firmas falsas, SoD, hash alterado, registro manipulado")}
         ${bk("Latencia añadida",`${C.latencia_control_promedio_ms??"—"} <small>ms por solicitud</small>`,"Costo del control determinista")}
       </div>
       ${B.n_packs>1&&B.consolidado&&B.consolidado.COMPLETO?`<div class="card" style="grid-template-columns:auto 1fr;align-items:center"><span class="lbl">Todos los dominios (${B.n_packs})</span><span class="mono">Bloqueo de ataques con Sanitizer + PEP: ${pct(B.consolidado.COMPLETO.tasa_bloqueo_ataques_pct)} · sin defensa: ${pct((B.consolidado.SIN_DEFENSA||{}).tasa_bloqueo_ataques_pct)}</span></div>`:""}
     </div>
   </div>
   <div class="bench-bot">
     <div class="card"><h2>Desglose por tipo de ataque</h2><div class="minis">${(B.por_tipo||[]).map(a=>{const p=a.total?Math.round(a.bloqueados/a.total*100):0;return `<div style="display:grid;gap:6px;justify-items:center"><div class="ring">${ringSVG({size:96,stroke:9,badges:false,gap:12,segs:[{w:a.bloqueados,col:"var(--accent)"},{w:a.total-a.bloqueados,col:"var(--crit)",dash:"2 5"}],center:[p+" %"]})}</div><span class="nm">${esc(a.tipo)}<small>${a.bloqueados} de ${a.total}</small></span></div>`;}).join("")||'<span class="muted">Sin ataques en el reporte.</span>'}</div>
       <div class="muted" style="font-size:12.5px;display:flex;gap:16px"><span style="display:inline-flex;gap:6px;align-items:center"><span style="width:18px;border-top:4px solid var(--accent);border-radius:2px"></span>bloqueados</span><span style="display:inline-flex;gap:6px;align-items:center"><span style="width:18px;border-top:4px dotted var(--crit)"></span>no detectados</span></div></div>
     <div class="card"><h2>Sin firewall vs con firewall</h2>
       <div style="display:grid;gap:10px"><b style="font-size:14px">${D().dano}</b>
         ${bar("Sin firewall",ataEjec(SD),nA,"var(--crit)")}
         ${bar("Con firewall",ataEjec(C),nA,"var(--accent)")}
         <b style="font-size:14px;margin-top:6px">${D().legit}</b>
         ${bar("Sin firewall",Math.round((SD.completitud_legitimas_pct||0)*nL/100),nL,"var(--muted)")}
         ${bar("Con firewall",legOk,nL,"var(--ok)")}</div></div>
   </div>
   <div class="card flush"><div class="card-h" style="padding:16px 16px 4px"><h2>Cada defensa por separado</h2><span class="sp"></span><span class="muted" style="font-size:13px">¿Sirve cada pieza de la arquitectura?</span></div>
     <table class="t cfgt"><thead><tr><th>Configuración</th><th class="r">Bloqueo de ataques</th><th class="r">Ataques ejecutados</th><th class="r">Legítimos completados</th><th class="r">Falsos positivos</th><th class="r">Aislamiento</th></tr></thead><tbody>
     ${orden.map(k=>{const m=cf[k];return `<tr><td><b>${MODO_TXT[k]||k}</b> <span class="mono muted" style="font-size:12px">${k}</span></td><td class="r num">${pct(m.tasa_bloqueo_ataques_pct)}</td><td class="r num">${ataEjec(m)}</td><td class="r num">${pct(m.completitud_legitimas_pct)}</td><td class="r num">${pct(m.falsos_positivos_pct)}</td><td class="r num">${pct(m.aislamiento_financiero_pct)}</td></tr>`;}).join("")}
     </tbody></table></div>
  </div>`;
}

/* ============ Vista en el correo / canal (complemento) ============ */
const MAIL_IDS=()=>ORDER.filter(id=>S[id].correo);
const strip=h=>String(h).replace(/<br>/g," ").replace(/<[^>]+>/g,"");
const senderName=s=>(s.raw.correo&&s.raw.correo.nombre_remitente)||s.prov;
const initials=t=>String(t).split(/\s+/).filter(w=>w.length>2).slice(0,2).map(w=>w[0]).join("").toUpperCase()||"?";
function signals(s){
  const out=(s.correo.evid||[]).map(e=>[/INSTRUCCION|CAMBIO_CUENTA|EXFIL|DESTRUCT|PRIVILEG/.test(e)?"c":"w",esc(e)]);
  if(s.meta.dominio_parecido_a) out.unshift(["c",`Dominio parecido a ${esc(s.meta.dominio_parecido_a)}`]);
  if(s.meta.spf_dkim_valido===false) out.unshift(["c","Origen no autenticado"]);
  if(s.correo.oculto) out.push(["c",`Texto adjunto${s.correo.adj?" en "+esc(s.correo.adj):""}: «${esc(String(s.correo.oculto).slice(0,180))}»`]);
  return out;
}
function paneBody(id){
  const s=S[id],c=canSign(id),ps=ui.pane&&ui.pane.id===id?ui.pane:null;
  const whyCls=pending(s)?"pend":(s.estado==="BLOQUEADA"||s.estado==="RECHAZADA")?"block":s.estado==="EJECUTADA"?"ok":"";
  if(ps&&ps.step){
    if(ps.step==="enviando") return [`<div class="psec" style="justify-items:center;text-align:center;padding:24px 14px"><span class="spin" style="color:var(--accent);width:22px;height:22px"></span><h3 style="font-size:15px">Firma enviada</h3><span class="muted" style="font-size:13px">El PEP verifica de nuevo PIN, rol, segregación de funciones y hash antes de ejecutar.</span></div>`,""];
    if(ps.step==="hecha"){const r=ps.res||{};const ok=r.estado==="EJECUTADA";return [`<div class="psec" style="justify-items:center;text-align:center;padding:24px 14px"><span class="avatar" style="background:${ok?"var(--ok-soft);color:var(--ok)":"var(--crit-soft);color:var(--crit)"};width:44px;height:44px">${ic(ok?"i-check":"i-alert").replace("<svg","<svg style='width:22px;height:22px'")}</span><h3 style="font-size:15px">${ok?D().okVerbo:"No se ejecutó"}</h3><span class="muted" style="font-size:13px">${esc(r.mensaje||"")}</span><a class="btn sm" href="#registro-${id}">${ic("i-doc")}Ver registro</a></div>`,`<a class="btn" href="#bandeja">Ir a la bandeja</a>`];}
    if(ps.step===1) return [`<span class="pstep">Paso 1 de 2 · Una firma: ${esc(s.rolSigTxt)} · vence en ${s.vence} h</span>
      <div class="psec"><h3>${D().autoriza}</h3><dl class="dl">${resumenFirma(s).replace(/class="amount" style="font-size:2\dpx"/,'class="pamt" style="font-size:17px"')}</dl></div>
      ${s.explicacion.pregunta_confirmacion?`<div class="sig o">${ic("i-bot")}<span>${esc(s.explicacion.pregunta_confirmacion)}</span></div>`:""}
      ${s.llamada?`<label class="chk-tel"><input type="checkbox" id="pchk" ${ps.checked?"checked":""}><span>Llamé al <b class="mono">${esc(s.telefono||"")}</b> del maestro y el proveedor confirmó.</span></label>`:""}
      <div class="sig o">${ic("i-user")}<span>Firmas como <b>${esc(P().nombre)}</b>. No iniciaste esta solicitud.</span></div>`,
      `<div class="row"><button class="btn" data-act="pane-cancel">Cancelar</button><button class="btn pri" data-act="pane-next" ${s.llamada&&!ps.checked?"disabled":""}>Continuar</button></div>`];
    if(ps.step===2){const n=(P().pin||"0000").length;return [`<span class="pstep">Paso 2 de 2 · PIN (MFA)</span>
      <div class="psec"><h3>Ingresa tu PIN de ${n} dígitos</h3><span class="muted" style="font-size:12.5px">Demo: el PIN de ${esc(P().nombre)} es ${esc(P().pin)}.</span>
      <div class="pcode ${ps.err?"err":""}">${Array.from({length:n},(_,i)=>`<input inputmode="numeric" maxlength="${n}" aria-label="Dígito ${i+1}" id="d${i}">`).join("")}</div>
      ${ps.err?`<div class="err-msg">${ic("i-alert")}${esc(ps.err)}</div>`:""}</div>
      <span class="muted" style="font-size:12.5px">Al firmar no se ejecuta de inmediato: el PEP verifica de nuevo.</span>`,
      `<div class="row"><button class="btn" data-act="pane-back">Atrás</button><button class="btn pri" data-act="pane-sign">${ic("i-pen")}Firmar</button></div>`];}
  }
  const sg=signals(s);const diffs=s.cmp.filter(r=>!r[3]);
  const body=`<div class="pstat">${chip(s.estado)}${risk(s.riesgo)}</div>
    <div><div class="pamt">${esc(s.montoTxt)}</div><div class="muted" style="font-size:13px">${esc(s.prov)} · <span class="mono" style="font-size:12px">${id}</span></div></div>
    <div class="pwhy ${whyCls}">${esc(s.porque)}</div>
    <div class="psec"><h3>Señales en este ${D().fuente}</h3>${sg.length?sg.map(x=>`<div class="sig ${x[0]}">${ic("i-alert")}<span>${x[1]}</span></div>`).join(""):`<div class="sig o">${ic("i-check")}<span>Sin frases sospechosas ni texto oculto.</span></div>`}</div>
    <div class="psec"><h3>Comparado con el ${D().maestro}</h3>${!s.cmp.length?`<span class="muted" style="font-size:13px">Sin validación (no pide acción o modo sin defensa).</span>`:diffs.length?`<dl class="dl">${diffs.map(r=>`<dt>${esc(r[0])}</dt><dd class="bad">${esc(r[4])}</dd>`).join("")}</dl>`:`<div class="sig o">${ic("i-check")}<span>Los ${s.cmp.length} campos verificados coinciden.</span></div>`}</div>
    <div class="psec"><h3>Etapa</h3><div class="sig">${ic(pending(s)?"i-pen":s.estado==="EJECUTADA"?"i-check":"i-lock")}<span>${pending(s)?`PEP pidió una firma · le corresponde a ${esc(s.rolSigTxt)} · vence en ${s.vence} h`:s.estado==="BLOQUEADA"?"PEP bloqueó · alerta al Oficial de Seguridad":s.estado==="EJECUTADA"?(s.firmoNombre?`${D().ok} · firmó ${esc(s.firmoNombre)}`:`${D().ok} sin firma (modo ${esc(s.modo)})`):s.estado==="RECHAZADA"?"Rechazada · devuelta al área solicitante":s.estado==="CERRADA_NO_FINANCIERA"?"Cerrada sin acción por el orquestador":esc(s.estado)}</span></div>
      <div style="display:flex;gap:6px;flex-wrap:wrap">${s.iso.slice(0,2).map(isoTag).join("")}</div></div>`;
  let foot="";
  if(c.ok||canReject(id)) foot+=`<div class="row">${canReject(id)?`<button class="btn danger" data-act="reject" data-id="${id}">${ic("i-x")}No aprobar</button>`:""}${c.ok?`<button class="btn pri" data-act="pane-start" data-id="${id}">${ic("i-pen")}Firmar</button>`:`<button class="btn is-dis" disabled>${ic("i-lock")}Firmar</button>`}</div>`;
  else if(c.show) foot+=`<button class="btn is-dis" disabled>${ic("i-lock")}Firmar</button>`;
  if(!c.ok&&c.show) foot+=`<div class="why-dis">${ic("i-lock")}<span>${c.why}</span></div>`;
  if(P().rol==="auditor") foot+=`<div class="why-dis" style="border-color:var(--accent)">${ic("i-doc")}<span>Vista de solo lectura · Auditor</span></div>`;
  foot+=`<a class="lnk" href="#solicitud-${id}" style="font-size:13px">Abrir expediente completo ›</a>`;
  return [body,foot];
}
function vCorreo(id){
  const ids=MAIL_IDS();
  crumbs([[`Vista en el ${isDev()?"canal":"correo"}`,"#correo"],[id||"",""]]);
  if(!ids.length) return `<div class="page"><div class="card"><div class="state">${ic("i-mail","big")}<h3>No hay mensajes todavía</h3><p>Envía ${isDev()?"issues o tickets":"correos"} de prueba desde el Panel de pruebas.</p><button class="btn pri" data-act="seed-ui" ${ui.busy?"disabled":""}>${ui.busy?'<span class="spin"></span>'+esc(ui.busy):ic("i-play")+"Cargar escenarios de la demo"}</button></div></div></div>`;
  id=id&&S[id]&&S[id].correo?id:ids[0];
  const s=S[id];
  const open=ui.paneOpen!==false;
  const [pb,pf]=open?paneBody(id):["",""];
  return `<div class="mailapp" style="${open?"":"grid-template-columns:320px minmax(0,1fr)"}">
   <div class="mlist"><div class="mlist-h"><b>${D().bandeja}</b><span>${D().buzon} · ${D().cliente}</span></div>
     <div class="mlist-items">${ids.map(x=>{const m=S[x];return `<a class="mi2" href="#correo-${x}" aria-current="${x===id}"><span class="av">${esc(initials(senderName(m)))}</span><span class="fr">${esc(senderName(m))}</span><span class="tm">${esc(m.recibida)}</span><span class="sb">${esc(m.correo.asunto)}</span><span class="pv">${m.correo.adj?ic("i-file","att")+" ":""}${esc(strip(m.correo.cuerpo[0]||""))}</span></a>`;}).join("")}</div></div>
   <div class="read">
     <div class="read-tb"><span class="tbb">${ic("i-mail")}Responder</span><span class="tbb">Reenviar</span><span class="tbb">Archivar</span><span class="sp"></span><button class="tbb addin" data-act="pane-toggle" aria-pressed="${open}">${ic("i-shield")}Context Firewall</button></div>
     <div class="read-body">
       <h2>${esc(s.correo.asunto)}</h2>
       <div class="from"><span class="av">${esc(initials(senderName(s)))}</span><b>${esc(senderName(s))} &lt;${esc(s.correo.de)}&gt;</b><span class="tm" style="grid-row:span 2;font-size:12.5px;color:var(--muted)">${esc(s.fecha)}</span><span>Canal: ${esc(s.canal)}</span></div>
       <div class="mbody">${s.correo.cuerpo.map(x=>`<p>${esc(strip(x)).replace(/&amp;(lt|gt|quot|#39|amp);/g,"&$1;")}</p>`).join("")}</div>
       ${s.correo.adj?`<span class="attach">${ic("i-file")}${esc(s.correo.adj)}</span>`:""}
       <span class="sim-note">${ic("i-alert").replace("<svg","<svg style='width:14px;height:14px'")}Así lo ve quien recibe el mensaje: el texto oculto no se ve aquí. El panel de la derecha es nuestro complemento.</span>
     </div></div>
   ${open?`<aside class="pane" aria-label="Panel Context Firewall"><div class="pane-h">${ic("i-shield")}<b>Context Firewall</b><span class="muted" style="font-size:12px">· ${esc(P().nombre.split(" ")[0])}, ${esc(P().rolTxt.toLowerCase())}</span><button class="x tbb" data-act="pane-toggle" aria-label="Cerrar panel" style="cursor:pointer">${ic("i-x")}</button></div><div class="pane-b">${pb}</div><div class="pane-f">${pf}</div></aside>`:""}
  </div>`;
}
function vNotFound(){crumbs([["No encontrada",""]]);return `<div class="page"><div class="card"><div class="state">${ic("i-search","big")}<h3>No encontramos esa solicitud</h3><p>Puede que pertenezca a otro dominio o que se haya reiniciado la demo.</p><a class="btn" href="#bandeja">Ir a la bandeja</a></div></div></div>`;}

/* ============ Panel de pruebas ============ */
function renderDPanel(){
  if(!EST){$("#dpanel-box").innerHTML="<p>Cargando…</p>";return;}
  const modos=(EST.modos||[]).map(m=>`<button aria-pressed="${EST.modo===m.id}" data-modo="${m.id}" ${m.disponible?"":"disabled"} title="${esc(m.descripcion)}${m.disponible?"":" (requiere un modelo real)"}">${esc(MODO_TXT[m.id]||m.id)}</button>`).join("");
  const llm=llmTxt(EST.llm);
  $("#dpanel-box").innerHTML=`<b style="font-size:14px">Panel de pruebas</b><p>Todo pasa por el pipeline real: agentes (${esc(llm)}), Sanitizer y PEP. Datos: ${esc(String(EST.origen_datos||"—").replace(/:\/\/.*$/,""))}.</p>
   <div class="row"><span class="lbl">Dominio</span><div class="seg">${EST.packs.map(x=>`<button aria-pressed="${x.id===PACK()}" data-pack="${x.id}">${esc((DOM[x.id]||{}).corto||x.nombre)}</button>`).join("")}</div></div>
   <div class="row" style="align-items:start"><span class="lbl">Modo</span><div class="seg" style="flex-wrap:wrap">${modos}</div></div>
   <div class="row" style="display:block"><span class="lbl">Enviar ${isDev()?"issue / ticket":"correo"} de prueba</span>
     <div class="scen" style="margin-top:6px">${ESCEN.map(e=>`<div class="it"><b>${esc(e.etiqueta)}<span class="ttipo ${esc(e.tipo)}">${esc(e.tipo)}</span></b><small>${esc(e.vector&&e.vector!=="—"?e.vector:e.descripcion||"")}</small><button class="btn sm" data-esc="${esc(e.id)}" ${ui.busy?"disabled":""}>Enviar</button></div>`).join("")||'<span class="muted">Sin escenarios.</span>'}</div></div>
   <div style="display:flex;flex-wrap:wrap;gap:6px"><button class="btn sm" data-act="seed-ui" ${ui.busy?"disabled":""}>${ic("i-play")}Cargar escenarios de la demo</button><button class="btn sm" data-act="tamper">${ic("i-alert")}Simular intruso en el registro</button><button class="btn sm" data-act="reset">${ic("i-refresh")}Reiniciar</button></div>
   ${ui.busy?`<p><span class="spin" style="vertical-align:-3px;color:var(--accent)"></span> ${esc(ui.busy)}</p>`:""}
   <p class="muted" style="font-size:12px">Integridad del registro: ${INTEG?(INTEG.integro?`íntegro · ${INTEG.entradas} entradas`:`<b style="color:var(--crit)">${esc(INTEG.detalle)}</b>`):"—"}</p>`;
}
async function enviarEscenarios(lista){
  for(let i=0;i<lista.length;i++){
    const e=lista[i];ui.busy=`Procesando ${i+1} de ${lista.length}: ${e.etiqueta}…`;renderDPanel();rerender();
    try{const r=await api("/api/correos",{method:"POST",body:e.correo});toast(`${esc(e.etiqueta)} → ${esc(r.estado)}`,r.estado==="BLOQUEADA"?"i-lock":"i-check");}
    catch(err){toast(`${esc(e.etiqueta)}: ${esc(err.message)}`,"i-alert",6000);}
    await cargar();
  }
  ui.busy=null;renderDPanel();rerender();
}

/* ============ Router ============ */
function route(){
  const h=(location.hash||"").slice(1)||P().home;
  let r="bandeja",html="";
  if(h==="bandeja"){html=vBandeja();}
  else if(h==="correo"||h.startsWith("correo-")){r="correo";html=vCorreo(h.slice(7));}
  else if(h.startsWith("solicitud-")){r="bandeja";html=vExpediente(h.slice(10));}
  else if(h.startsWith("firmar-")){r="bandeja";html=vFirmar(h.slice(7));}
  else if(h.startsWith("registro-")){r="registro";html=vRegistro(h.slice(9));}
  else if(h==="corte"){r="corte";html=vCorte();}
  else if(h==="benchmark"){r="benchmark";html=vBenchmark();}
  else html=vNotFound();
  renderShell(r);
  $("#main").innerHTML=html;$("#main").classList.toggle("bleed",r==="correo");
  if(!h.startsWith("firmar-")) ui.sign=null;
  const d0=document.getElementById("d0");if(d0) d0.focus();
}
function rerender(){const st=$("#main").scrollTop;route();$("#main").scrollTop=st;}
window.addEventListener("hashchange",()=>{if(ui.pane&&!location.hash.endsWith(ui.pane.id))ui.pane=null;route();$("#main").scrollTop=0;});

function descargar(nombre,obj){const b=new Blob([JSON.stringify(obj,null,2)],{type:"application/json"});const a=document.createElement("a");a.href=URL.createObjectURL(b);a.download=nombre;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),2000);}

/* ============ Eventos ============ */
document.addEventListener("click",async e=>{
  const t=e.target.closest("button,a,tr[data-go]");
  const pm=$("#pmenu");
  if(pm&&!e.target.closest(".persona")) pm.classList.remove("open");
  const em=document.getElementById("expmenu");if(em&&!e.target.closest(".dd")) em.classList.remove("open");
  if(!e.target.closest(".dpanel")) $("#dpanel").classList.remove("open");
  if(!t) return;
  if(t.id==="pbtn"){const o=$("#pmenu").classList.toggle("open");t.setAttribute("aria-expanded",o);return;}
  if(t.dataset.p){ui.persona=t.dataset.p;ui.sign=null;ui.pane=null;toast(`Ahora ves la interfaz como ${esc(P().nombre)} · ${esc(P().rolTxt)}`,"i-user");const h=location.hash.slice(1);if(!h||h==="bandeja"||h==="corte"){location.hash="#"+P().home;}rerender();return;}
  if(t.dataset.pack){if(t.dataset.pack===PACK())return;try{await api("/api/pack",{method:"POST",body:{pack:t.dataset.pack}});ui.persona=null;ui.estadoFiltro="todas";ui.sign=null;ui.pane=null;await cargar();toast(`Dominio activo: ${esc(EST.pack.nombre)} · mismo núcleo Zero-Trust`,"i-shield");renderDPanel();location.hash="#bandeja";rerender();}catch(err){toast(esc(err.message),"i-alert");}return;}
  if(t.dataset.modo){try{await api("/api/modo",{method:"POST",body:{modo:t.dataset.modo}});await cargar();toast(`Modo ${esc(t.dataset.modo)}: los próximos mensajes se procesan así`,"i-shield");renderDPanel();rerender();}catch(err){toast(esc(err.message),"i-alert");}return;}
  if(t.dataset.esc){const ev=ESCEN.find(x=>x.id===t.dataset.esc);if(ev) enviarEscenarios([ev]);return;}
  if(t.matches("tr[data-go]")&&!e.target.closest("a,button")){location.hash=t.dataset.go;return;}
  if(t.dataset.f){ui.estadoFiltro=t.dataset.f;rerender();return;}
  if(t.dataset.kf){ui.estadoFiltro=t.dataset.kf;ui.riesgo.clear();rerender();return;}
  if(t.dataset.r){ui.riesgo.has(t.dataset.r)?ui.riesgo.delete(t.dataset.r):ui.riesgo.add(t.dataset.r);rerender();return;}
  if(t.dataset.x){document.getElementById("expmenu").classList.remove("open");if(t.dataset.x==="PDF"){window.print();}else{const s=S[t.dataset.id];descargar(`${D().adr}-${t.dataset.id.slice(4)}.json`,s.raw);toast("JSON descargado","i-down");}return;}
  const a=t.dataset.act;if(!a) return;
  if(a==="retry"){ui.cargando=true;rerender();await cargar();rerender();}
  if(a==="retry-b"){await cargar();rerender();}
  if(a==="clearf"){ui.estadoFiltro="todas";ui.riesgo.clear();ui.q="";rerender();}
  if(a==="seed-ui"){$("#dpanel").classList.remove("open");try{const ui_esc=await api("/api/escenarios");enviarEscenarios(ui_esc.map(x=>({...x})));}catch(err){toast(esc(err.message),"i-alert");}}
  if(a==="next"){ui.sign.step++;rerender();}
  if(a==="back"){ui.sign.step--;ui.sign.err=null;rerender();}
  if(a==="sign"){
    const pin=leerPin();const n=(P().pin||"0000").length;
    if(pin.length<n){toast(`Completa los ${n} dígitos`,"i-alert");return;}
    const id=ui.sign.id,tel=ui.sign.checked;ui.sign.phase="enviando";rerender();
    const r=await enviarFirma(id,pin,tel);
    if(!ui.sign||ui.sign.id!==id) return;
    if(r.ok){ui.sign.phase="hecha";ui.sign.res=r.r;toast(esc(r.r.mensaje||r.r.estado),r.r.estado==="EJECUTADA"?"i-check":"i-alert");}
    else{ui.sign.phase=null;ui.sign.step=2;ui.sign.err=r.err;}
    rerender();
  }
  if(a==="reject") openReject(t.dataset.id);
  if(a==="pane-toggle"){ui.paneOpen=ui.paneOpen===false;rerender();}
  if(a==="pane-start"){ui.pane={id:t.dataset.id,step:1,err:null,checked:false};rerender();}
  if(a==="pane-cancel"){ui.pane=null;rerender();}
  if(a==="pane-next"){ui.pane.step=2;rerender();setTimeout(()=>document.getElementById("d0")?.focus(),0);}
  if(a==="pane-back"){ui.pane.step=1;ui.pane.err=null;rerender();}
  if(a==="pane-sign"){
    const pin=leerPin();const n=(P().pin||"0000").length;
    if(pin.length<n){toast(`Completa los ${n} dígitos`,"i-alert");return;}
    const id=ui.pane.id,tel=ui.pane.checked;ui.pane.step="enviando";rerender();
    const r=await enviarFirma(id,pin,tel);
    if(!ui.pane||ui.pane.id!==id) return;
    if(r.ok){ui.pane.step="hecha";ui.pane.res=r.r;}else{ui.pane.step=2;ui.pane.err=r.err;}
    rerender();
  }
  if(a==="exp"){document.getElementById("expmenu").classList.toggle("open");}
  if(a==="verify"){const id=t.dataset.id;ui.verify={id,state:"run"};rerender();
    try{const r=await api("/api/auditoria/verificar");INTEG=r;await new Promise(z=>setTimeout(z,500));if(ui.verify&&ui.verify.id===id){ui.verify={id,state:r.integro?"ok":"bad",r};rerender();}}
    catch(err){ui.verify=null;toast(esc(err.message),"i-alert");rerender();}}
  if(a==="verify-corte"){try{const r=await api("/api/auditoria/verificar");INTEG=r;toast(r.integro?`Registro íntegro: ${r.entradas} entradas coinciden con su hash`:esc(r.detalle),r.integro?"i-check":"i-alert",5000);renderDPanel();}catch(err){toast(esc(err.message),"i-alert");}}
  if(a==="export-corte"){try{const r=await api("/api/auditoria?limite=100000");descargar(`corte-${PACK()}.json`,{dominio:EST.pack,solicitudes:ORDER.map(id=>S[id].raw),auditoria:r});toast("Corte exportado (JSON)","i-down");}catch(err){toast(esc(err.message),"i-alert");}}
  if(a==="tamper"){try{const r=await api("/api/demo/manipular-auditoria",{method:"POST"});INTEG=r.verificacion;toast(r.ok?`Intruso editó la entrada #${r.seq}. Verifica la integridad.`:esc(r.detalle),"i-alert",5000);renderDPanel();rerender();}catch(err){toast(esc(err.message),"i-alert");}}
  if(a==="reset"){try{await api("/api/reiniciar",{method:"POST"});ui.sign=null;ui.pane=null;ui.verify=null;await cargar();renderDPanel();toast("Demo reiniciada: bandeja y registro nuevos","i-refresh");location.hash="#bandeja";rerender();}catch(err){toast(esc(err.message),"i-alert");}}
});
document.addEventListener("input",e=>{
  if(e.target.id==="q"){ui.q=e.target.value;const pos=e.target.selectionStart;rerender();const q=$("#q");q.focus();q.setSelectionRange(pos,pos);}
  if(/^d\d$/.test(e.target.id)){
    // Un dígito por casilla; si se pega el PIN completo, se reparte en las siguientes.
    const dig=e.target.value.replace(/\D/g,"");let i=+e.target.id[1];
    e.target.value=dig.slice(0,1);
    for(const ch of dig.slice(1)){const nx=document.getElementById("d"+(++i));if(!nx)break;nx.value=ch;}
    const nx=document.getElementById("d"+(i+1));if(dig&&nx)nx.focus();else if(dig)document.getElementById("d"+i)?.focus();
  }
});
document.addEventListener("change",e=>{
  if(e.target.id==="chk"&&ui.sign){ui.sign.checked=e.target.checked;rerender();}
  if(e.target.id==="pchk"&&ui.pane){ui.pane.checked=e.target.checked;rerender();}
});
document.addEventListener("keydown",e=>{
  if(/^d\d$/.test(e.target.id)&&e.key==="Backspace"&&!e.target.value){const i=+e.target.id[1];if(i>0)document.getElementById("d"+(i-1)).focus();}
  if(/^d\d$/.test(e.target.id)&&e.key==="Enter"){document.querySelector('[data-act="sign"],[data-act="pane-sign"]')?.click();}
  if(e.key==="Escape"){closeModal();$("#pmenu")?.classList.remove("open");$("#dpanel").classList.remove("open");}
  if((e.key==="p"||e.key==="P")&&!e.target.closest("input,textarea")){presenter();}
});
$("#dpanel-btn").addEventListener("click",e=>{e.stopPropagation();renderDPanel();$("#dpanel").classList.toggle("open");});
function presenter(){toast("El modo presentador se arma con el guion del Entregable 5","i-play");}
$("#presenter").addEventListener("click",presenter);
/* Tema */
function applyThemeIcon(){const dark=document.documentElement.dataset.theme==="dark"||(!document.documentElement.dataset.theme&&matchMedia("(prefers-color-scheme: dark)").matches);$("#theme").innerHTML=ic(dark?"i-sun":"i-moon");$("#theme").title=dark?"Cambiar a modo claro":"Cambiar a modo oscuro";}
$("#theme").addEventListener("click",()=>{const dark=document.documentElement.dataset.theme==="dark"||(!document.documentElement.dataset.theme&&matchMedia("(prefers-color-scheme: dark)").matches);document.documentElement.dataset.theme=dark?"light":"dark";applyThemeIcon();});
/* Modal No aprobar (con PIN: el rechazo también queda firmado en el registro) */
function openReject(id){
  const n=(P().pin||"0000").length;
  $("#modal-root").innerHTML=`<div class="scrim" id="scrim"><div class="modal" role="dialog" aria-modal="true" aria-labelledby="mt"><h2 id="mt">No aprobar ${id}</h2><p class="muted" style="margin:0">La solicitud pasará a <b>Rechazada</b>. Escribe el motivo; quedará en el registro SHA-256 con tu identidad.</p><label class="lbl" for="motivo">Motivo (obligatorio)</label><textarea id="motivo" placeholder="Ej.: el monto no coincide con lo acordado en la OC"></textarea><label class="lbl" for="rpin">Tu PIN (${n} dígitos · demo: ${esc(P().pin)})</label><input id="rpin" inputmode="numeric" maxlength="${n}" style="font:inherit;padding:8px 10px;border:1px solid var(--line);border-radius:6px;background:var(--surface);color:var(--ink);width:120px;letter-spacing:4px"><div id="merr"></div><div class="foot"><span class="sp"></span><button class="btn" id="mcancel">Cancelar</button><button class="btn danger" id="mok" style="background:var(--crit);color:var(--surface);border-color:var(--crit)">${ic("i-x")}No aprobar</button></div></div></div>`;
  $("#motivo").focus();
  $("#mcancel").onclick=closeModal;$("#scrim").onclick=e=>{if(e.target.id==="scrim")closeModal();};
  $("#mok").onclick=async()=>{const m=$("#motivo").value.trim();const pin=$("#rpin").value.trim();
    if(m.length<5){$("#motivo").classList.add("err");$("#merr").innerHTML=`<div class="err-msg">${ic("i-alert")}Escribe un motivo de al menos 5 caracteres.</div>`;return;}
    try{await api(`/api/solicitudes/${id}/rechazar`,{method:"POST",body:{usuario_id:P().id,pin,motivo:m}});closeModal();toast(`${id} rechazada · quedó en el registro`,"i-x");await cargar();rerender();}
    catch(err){$("#merr").innerHTML=`<div class="err-msg">${ic("i-alert")}${esc(err.message)}</div>`;}};
}
function closeModal(){$("#modal-root").innerHTML="";}

(async()=>{applyThemeIcon();route();await cargar();renderDPanel();rerender();})();
})();
