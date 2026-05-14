require("dotenv").config();
const express = require("express");
const { ConfidentialClientApplication } = require("@azure/msal-node");
const axios = require("axios");

const app = express();
const REDIRECT_URI = "https://enterprise-applications-monitor.onrender.com/callback";

const cca = new ConfidentialClientApplication({
  auth: {
    clientId: process.env.CLIENT_ID,
    authority: "https://login.microsoftonline.com/common",
    clientSecret: process.env.CLIENT_SECRET,
  },
});

const sessions = {};

// ─── Graph helpers ────────────────────────────────────────────────────────────
async function graphGet(url, token) {
  const res = await axios.get("https://graph.microsoft.com/v1.0" + url, {
    headers: { Authorization: "Bearer " + token },
  });
  return res.data;
}

async function graphPaged(url, token, limit) {
  limit = limit || 10000;
  var results = [];
  var nextUrl = "https://graph.microsoft.com/v1.0" + url;
  while (nextUrl && results.length < limit) {
    var res = await axios.get(nextUrl, { headers: { Authorization: "Bearer " + token } });
    var data = res.data;
    if (data.value) results = results.concat(data.value);
    nextUrl = data["@odata.nextLink"] || null;
    if (results.length >= limit) { results = results.slice(0, limit); break; }
  }
  return { value: results };
}

// Apps com todos os campos necessarios
async function getApps(token) {
  return graphPaged(
    "/applications?$select=displayName,appId,id,requiredResourceAccess,createdDateTime,signInAudience,notes,tags,passwordCredentials&$top=999",
    token, 10000
  );
}

// Owners de um app
async function getAppOwners(appObjectId, token) {
  try {
    var res = await graphGet("/applications/" + appObjectId + "/owners?$select=displayName,userPrincipalName,mail", token);
    return res.value || [];
  } catch (e) { return []; }
}

// Audit logs — quem criou o app e quem fez mudancas
async function getAuditLogs(token) {
  try {
    var since = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    var res = await graphPaged(
      "/auditLogs/directoryAudits?$filter=category eq 'ApplicationManagement' and activityDateTime ge " + since +
      "&$select=activityDateTime,activityDisplayName,initiatedBy,targetResources,result&$top=999",
      token, 5000
    );
    return res.value || [];
  } catch (e) {
    console.error("Erro audit logs:", e.message);
    return [];
  }
}

// Extrai o nome do ator de um log
function resolveActor(log) {
  var ib = log.initiatedBy;
  if (!ib) return null;

  // PRIORIDADE ABSOLUTA: usuario humano (admin normal, admin via PIM, qualquer conta)
  if (ib.user) {
    var u = ib.user;
    var name = u.displayName || u.userPrincipalName || null;
    if (!name && u.id) name = "Usuario (" + u.id.substring(0,8) + "...)";
    return name || "Usuario desconhecido";
  }

  // App/sistema: marca com prefixo para poder filtrar depois
  if (ib.app) {
    return "__SYSTEM__:" + (ib.app.displayName || ib.app.appId || "Sistema");
  }

  return "__SYSTEM__:Azure AD";
}

// Verifica se ator e humano (nao e sistema)
function isHumanActor(actor) {
  return actor && !actor.startsWith("__SYSTEM__:");
}

// Formata ator para exibicao
function formatActor(actor) {
  if (!actor) return null;
  if (actor.startsWith("__SYSTEM__:")) return null; // sistema = ignora
  return actor;
}

// Service Principals para resolver nomes de permissoes
async function getAllSPs(token) {
  return graphPaged("/servicePrincipals?$select=displayName,appId,oauth2PermissionScopes,appRoles&$top=999", token, 10000);
}

async function getSpecificSP(appId, token) {
  try {
    var res = await graphGet("/servicePrincipals?$filter=appId eq '" + appId + "'&$select=displayName,appId,oauth2PermissionScopes,appRoles", token);
    return res.value || [];
  } catch (e) { return []; }
}

function sleep(ms) { return new Promise(function(r) { setTimeout(r, ms); }); }

// ─── Coleta completa ──────────────────────────────────────────────────────────
async function collectApps(token) {
  var [appsData, allSPs, msGraphSPs, exchangeSPs, auditLogs] = await Promise.all([
    getApps(token),
    getAllSPs(token),
    getSpecificSP("00000003-0000-0000-c000-000000000000", token),
    getSpecificSP("00000002-0000-0ff1-ce00-000000000000", token),
    getAuditLogs(token),
  ]);

  // Mapa SP
  var spMap = {};
  for (var sp of allSPs.value) spMap[sp.appId] = sp;
  for (var sp of [...msGraphSPs, ...exchangeSPs]) spMap[sp.appId] = sp;

  // Mapa de audit: indexa por objectId E por appId para nao perder nenhum log
  // O targetResources pode conter o objectId do app OU o appId dependendo da operacao
  var auditMap = {};

  function addToMap(key, entry) {
    if (!key) return;
    if (!auditMap[key]) auditMap[key] = [];
    auditMap[key].push(entry);
  }

  for (var log of auditLogs) {
    var actor = resolveActor(log);
    for (var target of (log.targetResources || [])) {
      var entry = {
        action: log.activityDisplayName,
        timestamp: log.activityDateTime,
        actor: actor,
        isHuman: isHumanActor(actor),
        result: log.result,
        targetName: target.displayName,
        modifiedProps: target.modifiedProperties || [],
      };

      addToMap(target.id, entry);
      if (target.displayName) addToMap(target.displayName, entry);

      if (target.modifiedProperties) {
        for (var prop of target.modifiedProperties) {
          if (prop.displayName === "AppId" && prop.newValue) {
            var extractedAppId = prop.newValue.replace(/"/g, "").trim();
            addToMap(extractedAppId, entry);
          }
        }
      }
    }
  }

  // Owners em chunks
  var apps = appsData.value;
  var chunkSize = 20;
  var appsEnriched = [];
  for (var i = 0; i < apps.length; i += chunkSize) {
    var chunk = apps.slice(i, i + chunkSize);
    var ownersChunk = await Promise.all(chunk.map(function(a) { return getAppOwners(a.id, token); }));
    for (var j = 0; j < chunk.length; j++) {
      chunk[j]._owners = ownersChunk[j];

      // Busca logs pelo objectId (id), pelo appId e pelo displayName
      var appLogs = []
        .concat(auditMap[chunk[j].id] || [])
        .concat(auditMap[chunk[j].appId] || [])
        .concat(auditMap[chunk[j].displayName] || []);

      // Remove duplicatas por timestamp+action
      var seen = {};
      appLogs = appLogs.filter(function(l) {
        var key = l.timestamp + l.action;
        if (seen[key]) return false;
        seen[key] = true;
        return true;
      });

      // Ordena do mais recente para o mais antigo
      appLogs.sort(function(a, b) { return new Date(b.timestamp) - new Date(a.timestamp); });
      chunk[j]._auditLogs = appLogs;

      // Quem criou: estrategia em camadas priorizando usuario humano
      var createActions = ["add application", "add service principal"];

      // Camada 1: log de criacao feito por HUMANO
      var createLog = appLogs.find(function(l) {
        return l.isHuman && l.action && createActions.some(function(a){ return l.action.toLowerCase().includes(a); });
      });

      // Camada 2: qualquer log de criacao (mesmo sistema)
      if (!createLog) {
        createLog = appLogs.find(function(l) {
          return l.action && createActions.some(function(a){ return l.action.toLowerCase().includes(a); });
        });
      }

      // Camada 3: log humano mais antigo de qualquer acao
      if (!createLog) {
        var humanLogs = appLogs.filter(function(l){ return l.isHuman; });
        if (humanLogs.length > 0) {
          createLog = humanLogs.slice().sort(function(a,b){ return new Date(a.timestamp)-new Date(b.timestamp); })[0];
        }
      }

      // Formata o ator — se for sistema, retorna null para exibir como desconhecido
      if (createLog) {
        chunk[j]._createdBy = createLog.isHuman ? createLog.actor : null;
        chunk[j]._createdBySystem = !createLog.isHuman ? formatActor(createLog.actor) : null;
      } else {
        chunk[j]._createdBy = null;
        chunk[j]._createdBySystem = null;
      }
    }
    appsEnriched = appsEnriched.concat(chunk);
  }

  // Resolve permissoes
  var result = appsEnriched.map(function(application) {
    var appRoles = [];
    var delegated = [];
    if (application.requiredResourceAccess) {
      for (var resource of application.requiredResourceAccess) {
        var resourceSp = spMap[resource.resourceAppId];
        for (var access of resource.resourceAccess) {
          if (access.type === "Role") {
            var roleDef = resourceSp && resourceSp.appRoles
              ? resourceSp.appRoles.find(function(r) { return r.id === access.id; }) : null;
            appRoles.push({ id: access.id, name: roleDef ? roleDef.value : null, description: roleDef ? roleDef.displayName : null, resource: resourceSp ? resourceSp.displayName : resource.resourceAppId });
          } else {
            var scopeDef = resourceSp && resourceSp.oauth2PermissionScopes
              ? resourceSp.oauth2PermissionScopes.find(function(s) { return s.id === access.id; }) : null;
            delegated.push({ id: access.id, name: scopeDef ? scopeDef.value : null, description: scopeDef ? scopeDef.adminConsentDisplayName : null, resource: resourceSp ? resourceSp.displayName : resource.resourceAppId });
          }
        }
      }
    }

    // Processa secrets (passwordCredentials)
    var secrets = (application.passwordCredentials || []).map(function(cred) {
      var now = Date.now();
      var expDate = cred.endDateTime ? new Date(cred.endDateTime) : null;
      var daysToExp = expDate ? Math.ceil((expDate.getTime() - now) / 86400000) : null;
      var status = !expDate ? "sem-expiracao"
        : daysToExp < 0 ? "expirada"
        : daysToExp <= 30 ? "expirando"
        : "ativa";
      return {
        hint: cred.hint || "***",
        displayName: cred.displayName || "Secret",
        startDate: cred.startDateTime,
        endDate: cred.endDateTime,
        daysToExp: daysToExp,
        status: status,
      };
    });

    return Object.assign({}, application, { appRoles, delegated, secrets });
  });

  return result;
}

// ─── Detecta mudancas entre snapshots ────────────────────────────────────────
function detectChanges(prevApps, currApps) {
  var changes = [];
  var prevMap = {}, currMap = {};
  for (var a of prevApps) prevMap[a.appId] = a;
  for (var a of currApps)  currMap[a.appId] = a;

  for (var appId in currMap) {
    if (!prevMap[appId]) {
      var a = currMap[appId];
      var createdBy = a._createdBy ? " por " + a._createdBy : "";
      changes.push({ type:"novo", severity:"aviso", appId, appName: a.displayName||appId, message:"Nova aplicacao registrada: "+(a.displayName||appId)+createdBy, permChanges:[] });
    }
  }
  for (var appId in prevMap) {
    if (!currMap[appId]) {
      changes.push({ type:"removido", severity:"info", appId, appName: prevMap[appId].displayName||appId, message:"Aplicacao removida: "+(prevMap[appId].displayName||appId), permChanges:[] });
    }
  }
  for (var appId in currMap) {
    if (!prevMap[appId]) continue;
    var prev = prevMap[appId], curr = currMap[appId];
    var permChanges = [];

    var prevRoles = (prev.appRoles||[]).map(function(r){return r.id;});
    var currRoles = (curr.appRoles||[]).map(function(r){return r.id;});
    for (var id of currRoles.filter(function(id){return !prevRoles.includes(id);})) {
      var p = (curr.appRoles||[]).find(function(r){return r.id===id;});
      permChanges.push({ action:"adicionada", type:"APP", name: p?(p.name||id):id, severity:"critico" });
    }
    for (var id of prevRoles.filter(function(id){return !currRoles.includes(id);})) {
      var p = (prev.appRoles||[]).find(function(r){return r.id===id;});
      permChanges.push({ action:"removida", type:"APP", name: p?(p.name||id):id, severity:"melhora" });
    }

    var prevDel = (prev.delegated||[]).map(function(r){return r.id;});
    var currDel = (curr.delegated||[]).map(function(r){return r.id;});
    for (var id of currDel.filter(function(id){return !prevDel.includes(id);})) {
      var p = (curr.delegated||[]).find(function(r){return r.id===id;});
      permChanges.push({ action:"adicionada", type:"DEL", name: p?(p.name||id):id, severity:"aviso" });
    }
    for (var id of prevDel.filter(function(id){return !currDel.includes(id);})) {
      var p = (prev.delegated||[]).find(function(r){return r.id===id;});
      permChanges.push({ action:"removida", type:"DEL", name: p?(p.name||id):id, severity:"melhora" });
    }

    // Mudancas em secrets
    var prevSecrets = (prev.secrets||[]).length;
    var currSecrets = (curr.secrets||[]).length;
    if (currSecrets > prevSecrets) permChanges.push({ action:"adicionada", type:"SECRET", name: "Nova secret/certificado", severity:"aviso" });
    if (currSecrets < prevSecrets) permChanges.push({ action:"removida", type:"SECRET", name: "Secret/certificado removido", severity:"info" });

    if (permChanges.length > 0) {
      var worst = permChanges.some(function(c){return c.severity==="critico";}) ? "critico"
        : permChanges.some(function(c){return c.severity==="aviso";}) ? "aviso" : "melhora";

      // Tenta achar quem fez a mudanca nos audit logs
      var recentLog = (curr._auditLogs||[])
        .filter(function(l){ return (Date.now()-new Date(l.timestamp).getTime()) < 3600000; })
        .sort(function(a,b){return new Date(b.timestamp)-new Date(a.timestamp);})[0];
      var changedBy = recentLog ? " por " + recentLog.actor : "";

      changes.push({ type:"permissao", severity:worst, appId, appName: curr.displayName||appId, message:(curr.displayName||appId)+": "+permChanges.length+" alteracao(es)"+changedBy, permChanges });
    }
  }
  return changes;
}

function classifyPerm(name) {
  if (!name) return "normal";
  var critical = ["Mail.ReadWrite","Mail.Send","Files.ReadWrite.All","Directory.ReadWrite.All","User.ReadWrite.All","RoleManagement.ReadWrite.Directory","Application.ReadWrite.All","Group.ReadWrite.All","full_access_as_app"];
  var high = ["Mail.Read","Files.Read.All","User.Read.All","Directory.Read.All","AuditLog.Read.All","Policy.Read.All","IdentityRiskyUser.Read.All"];
  if (critical.some(function(c){return name.includes(c);})) return "critico";
  if (high.some(function(h){return name.includes(h);})) return "alto";
  return "normal";
}

function permLabel(p) { return p.name || "["+p.id.substring(0,8)+"...]"; }

function fmtDate(d) { if (!d) return "—"; return new Date(d).toLocaleString("pt-BR"); }
function fmtDateOnly(d) { if (!d) return "—"; return new Date(d).toLocaleDateString("pt-BR"); }

// ─── Rotas ────────────────────────────────────────────────────────────────────
app.get("/", async (req, res) => {
  const authUrl = await cca.getAuthCodeUrl({
    scopes: ["User.Read","Directory.Read.All","Application.Read.All","AuditLog.Read.All"],
    redirectUri: REDIRECT_URI,
    prompt: "select_account",
  });
  res.redirect(authUrl);
});

app.get("/callback", async (req, res) => {
  if (!req.query.code) return res.status(400).send("Codigo nao encontrado.");
  try {
    const tokenResponse = await cca.acquireTokenByCode({
      code: req.query.code,
      scopes: ["User.Read","Directory.Read.All","Application.Read.All","AuditLog.Read.All"],
      redirectUri: REDIRECT_URI,
    });
    const sessionId = Math.random().toString(36).slice(2);
    sessions[sessionId] = {
      token: tokenResponse.accessToken,
      tenantId: tokenResponse.tenantId,
      lastApps: null,
      changesLast24h: [], // acumula mudancas das ultimas 24h
      snapshots: [],
      lastUpdated: null,
    };
    res.send(buildLoadingPage(sessionId, tokenResponse.tenantId));
  } catch (err) {
    console.error(err);
    res.status(500).send("<h2>Erro</h2><pre>"+err.message+"</pre><a href='/'>Tentar novamente</a>");
  }
});

app.get("/progress/:sessionId", function(req, res) {
  const sessionId = req.params.sessionId;
  if (!sessions[sessionId]) return res.status(404).end();
  res.setHeader("Content-Type","text/event-stream");
  res.setHeader("Cache-Control","no-cache");
  res.setHeader("Connection","keep-alive");
  res.flushHeaders();
  function send(d) { res.write("data: "+JSON.stringify(d)+"\n\n"); }
  runCollection(sessionId, send).then(function(){
    send({type:"done"}); res.end();
  }).catch(function(err){
    send({type:"error",message:err.message}); res.end();
  });
});

async function runCollection(sessionId, send) {
  var session = sessions[sessionId];
  send({type:"step",status:"running",label:"Conectando ao tenant..."});
  await sleep(200);
  send({type:"step",status:"done",label:"Conectado: "+session.tenantId});
  send({type:"step",status:"running",label:"Buscando aplicacoes, secrets e audit logs..."});
  var apps = await collectApps(session.token);
  send({type:"step",status:"done",label:apps.length+" aplicacoes encontradas"});
  send({type:"step",status:"running",label:"Resolvendo permissoes e owners..."});
  await sleep(200);
  var totalPerms = apps.reduce(function(acc,a){return acc+(a.appRoles||[]).length+(a.delegated||[]).length;},0);
  var totalSecrets = apps.reduce(function(acc,a){return acc+(a.secrets||[]).length;},0);
  send({type:"step",status:"done",label:totalPerms+" permissoes | "+totalSecrets+" secrets mapeadas"});
  send({type:"step",status:"running",label:"Detectando mudancas..."});
  var newChanges = session.lastApps ? detectChanges(session.lastApps, apps) : [];
  // Acumula mudancas 24h
  var now = Date.now();
  var stamped = newChanges.map(function(c){ return Object.assign({},c,{detectedAt: new Date().toISOString()}); });
  session.changesLast24h = session.changesLast24h
    .filter(function(c){ return (now - new Date(c.detectedAt).getTime()) < 24*60*60*1000; })
    .concat(stamped);
  send({type:"step",status:"done",label:newChanges.length+" mudanca(s) | "+session.changesLast24h.length+" nas ultimas 24h"});
  session.snapshots.push({timestamp: new Date().toISOString(), count: apps.length});
  if (session.snapshots.length > 50) session.snapshots.shift();
  session.lastApps = apps;
  session.lastUpdated = new Date();
  send({type:"step",status:"running",label:"Gerando dashboard..."});
  await sleep(200);
  send({type:"step",status:"done",label:"Pronto!"});
}

app.get("/refresh/:sessionId", async function(req, res) {
  var session = sessions[req.params.sessionId];
  if (!session) return res.status(404).json({error:"Sessao nao encontrada"});
  try {
    var apps = await collectApps(session.token);
    var newChanges = session.lastApps ? detectChanges(session.lastApps, apps) : [];
    var now = Date.now();
    var stamped = newChanges.map(function(c){ return Object.assign({},c,{detectedAt: new Date().toISOString()}); });
    session.changesLast24h = session.changesLast24h
      .filter(function(c){ return (now - new Date(c.detectedAt).getTime()) < 24*60*60*1000; })
      .concat(stamped);
    session.snapshots.push({timestamp: new Date().toISOString(), count: apps.length});
    if (session.snapshots.length > 50) session.snapshots.shift();
    session.lastApps = apps;
    session.lastUpdated = new Date();
    res.json({ apps, changesLast24h: session.changesLast24h, newChanges, snapshots: session.snapshots, updatedAt: session.lastUpdated });
  } catch (err) {
    res.status(500).json({error: err.message});
  }
});

app.get("/dashboard/:sessionId", function(req, res) {
  var session = sessions[req.params.sessionId];
  if (!session || !session.lastApps) return res.status(404).send("Dashboard nao encontrado.");
  res.send(buildDashboard(session, req.params.sessionId));
});

// ─── Loading Page ─────────────────────────────────────────────────────────────
function buildLoadingPage(sessionId, tenantId) {
  return '<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><title>Carregando...</title>'+
'<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:"SF Mono",Monaco,monospace;background:#060a0f;color:#c8d8e8;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}'+
'.card{background:#0d1520;border:1px solid #1a2840;border-radius:16px;padding:48px 40px;max-width:580px;width:100%}'+
'h1{font-size:18px;color:#4fc3f7;margin-bottom:4px;letter-spacing:2px;text-transform:uppercase}'+
'.tid{font-size:11px;color:#3a5068;margin-bottom:32px;font-family:monospace}'+
'.bar-wrap{height:2px;background:#0a1525;border-radius:2px;margin-bottom:32px}'+
'.bar{height:100%;background:linear-gradient(90deg,#0ea5e9,#38bdf8,#7dd3fc);border-radius:2px;width:0%;transition:width .8s cubic-bezier(.4,0,.2,1)}'+
'.steps{display:flex;flex-direction:column;gap:6px}'+
'.step{display:flex;align-items:center;gap:10px;padding:10px 14px;border-radius:8px;background:#060d16;font-size:12px;color:#3a5068;border:1px solid transparent;transition:all .4s}'+
'.step.running{background:#061828;border-color:#0ea5e9;color:#7dd3fc}'+
'.step.done{background:#061a10;border-color:#22c55e40;color:#4ade80}'+
'.step.error{background:#1a0606;border-color:#ef444440;color:#f87171}'+
'.icon{width:16px;height:16px;display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:11px}'+
'.spinner{width:12px;height:12px;border:1.5px solid #1a3050;border-top-color:#0ea5e9;border-radius:50%;animation:spin .7s linear infinite}'+
'@keyframes spin{to{transform:rotate(360deg)}}'+
'.reveal{text-align:center;margin-top:36px;display:none}'+
'.big{font-size:64px;font-weight:700;color:#0ea5e9;font-family:"SF Mono",monospace;letter-spacing:-2px}'+
'.sub{font-size:12px;color:#3a5068;margin-top:4px;letter-spacing:2px;text-transform:uppercase}'+
'.btn{display:inline-block;margin-top:24px;padding:12px 32px;background:linear-gradient(135deg,#0369a1,#0ea5e9);color:#fff;border-radius:8px;text-decoration:none;font-weight:600;font-size:13px;letter-spacing:1px;text-transform:uppercase}'+
'</style></head><body>'+
'<div class="card"><h1>// APP MONITOR</h1><div class="tid">'+tenantId+'</div>'+
'<div class="bar-wrap"><div class="bar" id="bar"></div></div>'+
'<div class="steps" id="steps"></div>'+
'<div class="reveal" id="reveal"><div class="big" id="bigNum">—</div><div class="sub">aplicacoes encontradas</div><a class="btn" id="btn" href="#">ABRIR MONITOR</a></div></div>'+
'<script>'+
'var total=5,done=0,active=null;'+
'var stepsEl=document.getElementById("steps"),bar=document.getElementById("bar");'+
'var es=new EventSource("/progress/'+sessionId+'");'+
'es.onmessage=function(e){'+
'  var d=JSON.parse(e.data);'+
'  if(d.type==="step"){'+
'    if(d.status==="running"){'+
'      if(active){active.className="step done";active.querySelector(".icon").innerHTML="✓";done++;bar.style.width=Math.min(92,Math.round(done/total*100))+"%";}'+
'      var el=document.createElement("div");el.className="step running";'+
'      el.innerHTML="<div class=\\"icon\\"><div class=\\"spinner\\"></div></div><span>"+d.label+"</span>";'+
'      stepsEl.appendChild(el);el.scrollIntoView({behavior:"smooth"});active=el;'+
'    } else if(d.status==="done"&&active){active.querySelector("span").textContent=d.label;}'+
'  }'+
'  if(d.type==="done"){'+
'    if(active){active.className="step done";active.querySelector(".icon").innerHTML="✓";}'+
'    bar.style.width="100%";es.close();'+
'    document.getElementById("btn").href="/dashboard/'+sessionId+'";'+
'    document.getElementById("reveal").style.display="block";'+
'  }'+
'  if(d.type==="error"){'+
'    if(active){active.className="step error";active.querySelector(".icon").innerHTML="✗";}'+
'    var err=document.createElement("div");err.className="step error";'+
'    err.innerHTML="<div class=\\"icon\\">✗</div><span>Erro: "+d.message+"</span>";'+
'    stepsEl.appendChild(err);es.close();'+
'  }'+
'};'+
'</script></body></html>';
}

// ─── Dashboard ────────────────────────────────────────────────────────────────
function buildDashboard(session, sessionId) {
  var apps = session.lastApps;
  var changes24h = session.changesLast24h || [];
  var riskColor = { critico:"#ef4444", alto:"#f59e0b", normal:"#4ade80" };

  // Grupos para abas
  var allApps          = apps;
  var riskyApps        = apps.filter(function(a){ return a.appRoles && a.appRoles.length>0; });
  var recentApps       = apps.filter(function(a){ return a.createdDateTime && (Date.now()-new Date(a.createdDateTime).getTime())/86400000<=30; });
  var noOwnerApps      = apps.filter(function(a){ return !a._owners||a._owners.length===0; });
  var appsWithSecrets  = apps.filter(function(a){ return a.secrets&&a.secrets.length>0; });
  var expSecrets       = apps.filter(function(a){ return (a.secrets||[]).some(function(s){ return s.status==="expirada"||s.status==="expirando"; }); });

  // ── Tooltip de risco por permissão ──────────────────────────────────────────
  var RISK_TOOLTIPS = {
    // Criticos
    "Mail.ReadWrite":                   "CRITICO — Le e modifica todos os e-mails da organizacao. Um atacante pode ler, apagar ou alterar qualquer mensagem.",
    "Mail.Send":                         "CRITICO — Envia e-mails como qualquer usuario da org. Pode ser usado para phishing interno.",
    "Files.ReadWrite.All":               "CRITICO — Le e escreve em todos os arquivos do SharePoint/OneDrive de todos os usuarios.",
    "Directory.ReadWrite.All":           "CRITICO — Le e modifica todo o diretorio Azure AD: usuarios, grupos, roles. Acesso quase total ao tenant.",
    "User.ReadWrite.All":                "CRITICO — Cria, edita e deleta qualquer usuario do tenant. Pode ser usado para escalar privilegios.",
    "RoleManagement.ReadWrite.Directory":"CRITICO — Atribui e remove roles de administrador. Pode elevar qualquer conta para Global Admin.",
    "Application.ReadWrite.All":         "CRITICO — Cria e modifica qualquer aplicacao no tenant, incluindo secrets e permissoes.",
    "Group.ReadWrite.All":               "CRITICO — Cria e modifica todos os grupos, incluindo grupos de seguranca e Teams.",
    "full_access_as_app":                "CRITICO — Acesso total ao Exchange Online como a propria aplicacao, sem restricoes.",
    // Altos
    "Mail.Read":                         "ALTO — Le todos os e-mails de todos os usuarios. Expoe comunicacoes confidenciais da organizacao.",
    "Files.Read.All":                    "ALTO — Le todos os arquivos de todos os usuarios no SharePoint e OneDrive.",
    "User.Read.All":                     "ALTO — Le dados de todos os usuarios: nomes, e-mails, cargos, numeros de telefone.",
    "Directory.Read.All":                "ALTO — Le todo o diretorio AD: usuarios, grupos, roles, dispositivos, configuracoes.",
    "AuditLog.Read.All":                 "ALTO — Acessa os logs de auditoria do tenant. Pode revelar comportamentos e falhas de seguranca.",
    "Policy.Read.All":                   "ALTO — Le todas as politicas de seguranca, acesso condicional e autenticacao.",
    "IdentityRiskyUser.Read.All":        "ALTO — Le dados de usuarios sinalizados como de risco pelo Azure AD Identity Protection.",
    // Normais comuns
    "User.Read":                         "NORMAL — Le apenas o perfil do usuario que autorizou o acesso. Escopo limitado e seguro.",
    "openid":                            "NORMAL — Permite login com conta Microsoft. Nao acessa dados alem da identidade basica.",
    "profile":                           "NORMAL — Le nome, foto e informacoes basicas de perfil do usuario logado.",
    "email":                             "NORMAL — Le o endereco de e-mail do usuario logado. Nao acessa a caixa de entrada.",
    "offline_access":                    "NORMAL — Permite que o app funcione em segundo plano sem o usuario presente (refresh token).",
    "Calendars.Read":                    "NORMAL — Le os eventos de calendario do usuario logado.",
    "Calendars.ReadWrite":               "NORMAL/MEDIO — Le e cria eventos no calendario do usuario logado.",
    "Tasks.ReadWrite":                   "NORMAL — Le e cria tarefas no Planner/To Do do usuario logado.",
  };

  function getPermTooltip(name, description, risk) {
    if (!name) return description || "Permissao nao identificada";
    // Busca correspondencia exata ou parcial no mapa de tooltips
    for (var key in RISK_TOOLTIPS) {
      if (name === key || name.startsWith(key)) return RISK_TOOLTIPS[key];
    }
    // Fallback: usa a descricao do Graph + nivel de risco
    var riskLabel = risk==="critico" ? "🔴 CRITICO" : risk==="alto" ? "🟡 ALTO" : "🟢 NORMAL";
    return riskLabel + " — " + (description || name);
  }

  // ── Sugestoes de permissoes por padrao de nome do app ────────────────────────
  function getSuggestions(a) {
    var name = (a.displayName||"").toLowerCase();
    var currentNames = (a.appRoles||[]).concat(a.delegated||[]).map(function(p){ return p.name||""; });
    var suggestions = { add:[], remove:[] };

    // Permissoes que provavelmente NAO deveriam existir para apps comuns
    var dangerousForMost = ["Directory.ReadWrite.All","User.ReadWrite.All","RoleManagement.ReadWrite.Directory","Application.ReadWrite.All","full_access_as_app"];
    dangerousForMost.forEach(function(perm){
      if (currentNames.some(function(n){return n===perm;})) {
        suggestions.remove.push({ name:perm, reason:"Permissao de escrita critica raramente necessaria. Considere substituir por versao Read-only." });
      }
    });

    // Sugestoes baseadas no nome do app
    if (name.includes("mail") || name.includes("email") || name.includes("outlook")) {
      if (!currentNames.some(function(n){return n==="Mail.Read";})) suggestions.add.push({ name:"Mail.Read", reason:"Apps de e-mail geralmente precisam ler mensagens." });
      if (currentNames.some(function(n){return n==="Mail.ReadWrite";})) suggestions.remove.push({ name:"Mail.ReadWrite", reason:"Se o app so le e-mails, use Mail.Read em vez de ReadWrite." });
    }
    if (name.includes("user") || name.includes("people") || name.includes("directory")) {
      if (!currentNames.some(function(n){return n==="User.Read.All";})) suggestions.add.push({ name:"User.Read.All", reason:"Apps de diretorio de usuarios precisam desta permissao de leitura." });
    }
    if (name.includes("report") || name.includes("audit") || name.includes("monitor") || name.includes("security") || name.includes("scan")) {
      if (!currentNames.some(function(n){return n==="AuditLog.Read.All";})) suggestions.add.push({ name:"AuditLog.Read.All", reason:"Apps de monitoramento precisam ler logs de auditoria." });
      if (!currentNames.some(function(n){return n==="Directory.Read.All";})) suggestions.add.push({ name:"Directory.Read.All", reason:"Apps de seguranca precisam ler o diretorio do tenant." });
    }
    if (name.includes("calendar") || name.includes("agenda") || name.includes("meeting")) {
      if (!currentNames.some(function(n){return n==="Calendars.Read";})) suggestions.add.push({ name:"Calendars.Read", reason:"Apps de calendario precisam desta permissao." });
    }
    if (name.includes("file") || name.includes("sharepoint") || name.includes("document") || name.includes("doc")) {
      if (!currentNames.some(function(n){return n==="Files.Read.All";})) suggestions.add.push({ name:"Files.Read.All", reason:"Apps de documentos precisam ler arquivos do SharePoint/OneDrive." });
      if (currentNames.some(function(n){return n==="Files.ReadWrite.All";})) suggestions.remove.push({ name:"Files.ReadWrite.All", reason:"Se o app so le arquivos, use Files.Read.All em vez de ReadWrite.All." });
    }
    // App sem nenhuma permissao
    if (currentNames.filter(function(n){return n;}).length===0) {
      suggestions.add.push({ name:"User.Read", reason:"A maioria dos apps precisa ao menos desta permissao para identificar o usuario logado." });
    }
    return suggestions;
  }

  // ── buildAppRow com prefixo de aba para IDs unicos ───────────────────────────
  function buildAppRow(a, tabPrefix) {
    tabPrefix = tabPrefix || "all";
    var uid = tabPrefix + "-" + a.appId; // ID unico por aba para evitar conflito de IDs
    var allPerms = (a.appRoles||[]).concat(a.delegated||[]);
    var isRisky = a.appRoles && a.appRoles.length>0;
    var owners = (a._owners||[]).map(function(o){ return o.displayName||o.userPrincipalName||o.mail||"?"; });
    var ownersStr = owners.length>0 ? owners.join(", ") : '<span style="color:#ef4444">Sem owner</span>';
    // Prioriza usuario humano; fallback para sistema ou mensagem de log antigo
    var createdBy = a._createdBy
      ? a._createdBy
      : a._createdBySystem
        ? '<span style="color:#3a5068;font-size:10px">via ' + a._createdBySystem + '</span>'
        : '<span style="color:#2a4060;font-size:10px">Anterior a 30 dias</span>';

    // Notas internas
    var notesHtml = a.notes
      ? '<div class="notes-box"><span class="notes-label">📝 Notas internas:</span> '+a.notes+'</div>'
      : '';

    // Permissoes com tooltip de risco individual
    var permsHtml = allPerms.length===0
      ? '<span style="color:#3a5068;font-size:11px">Nenhuma permissao registrada</span>'
      : allPerms.map(function(p){
          var risk = classifyPerm(p.name);
          var isApp = !!(a.appRoles||[]).find(function(r){return r.id===p.id;});
          var label = permLabel(p);
          var tooltip = getPermTooltip(p.name, p.description, risk);
          // Escapa aspas para nao quebrar o HTML do title
          tooltip = tooltip.replace(/"/g,"&quot;").replace(/'/g,"&#39;");
          return '<div class="pb-wrap">'+
            '<span class="pb" style="border-color:'+riskColor[risk]+';color:'+riskColor[risk]+'" data-tooltip="'+tooltip+'">'+
              '<span class="pt">'+(isApp?"APP":"DEL")+'</span> '+label+
            '</span>'+
            '<div class="pb-tooltip">'+tooltip+'</div>'+
          '</div>';
        }).join("");

    // Sugestoes
    var sugg = getSuggestions(a);
    var suggHtml = "";
    if (sugg.add.length===0 && sugg.remove.length===0) {
      suggHtml = '<div class="sugg-ok">✅ Nenhuma sugestao — permissoes parecem adequadas para este app.</div>';
    } else {
      if (sugg.remove.length>0) {
        suggHtml += '<div class="sugg-section"><div class="sugg-title" style="color:#ef4444">🔴 Considere REMOVER:</div>'+
          sugg.remove.map(function(s){ return '<div class="sugg-item sugg-remove"><code>'+s.name+'</code><span>'+s.reason+'</span></div>'; }).join("")+'</div>';
      }
      if (sugg.add.length>0) {
        suggHtml += '<div class="sugg-section"><div class="sugg-title" style="color:#4ade80">🟢 Considere ADICIONAR:</div>'+
          sugg.add.map(function(s){ return '<div class="sugg-item sugg-add"><code>'+s.name+'</code><span>'+s.reason+'</span></div>'; }).join("")+'</div>';
      }
    }

    // Secrets
    var secretsHtml = (a.secrets&&a.secrets.length>0)
      ? '<div class="secrets-wrap">'+a.secrets.map(function(s){
          var sc = s.status==="expirada"?"#ef4444":s.status==="expirando"?"#f59e0b":s.status==="sem-expiracao"?"#94a3b8":"#4ade80";
          var slabel = s.status==="expirada"?"EXPIRADA":s.status==="expirando"?"EXPIRA EM "+s.daysToExp+"d":s.status==="sem-expiracao"?"SEM EXPIRACAO":"ATIVA";
          return '<div class="secret-item">'+
            '<span class="secret-name">🔑 '+s.displayName+' ('+s.hint+'***)</span>'+
            '<span class="secret-dates">Criada: '+fmtDateOnly(s.startDate)+' → Expira: '+fmtDateOnly(s.endDate)+'</span>'+
            '<span class="secret-status" style="color:'+sc+'">'+slabel+'</span>'+
          '</div>';
        }).join("")+'</div>'
      : '<span style="color:#3a5068;font-size:12px">Nenhuma secret registrada</span>';

    // Atividade recente
    var recentLogs = (a._auditLogs||[]).slice(0,5);
    var auditHtml = recentLogs.length>0
      ? '<div class="audit-wrap"><div class="audit-title">Atividade recente:</div>'+
        recentLogs.map(function(l){
          var actorDisplay = l.isHuman ? l.actor : (formatActor(l.actor) || 'Sistema');
          var actorColor = l.isHuman ? '#38bdf8' : '#3a5068';
          return '<div class="audit-item">'+
            '<span class="audit-action">'+l.action+'</span>'+
            '<span class="audit-actor" style="color:'+actorColor+'">por '+actorDisplay+'</span>'+
            '<span class="audit-time">'+fmtDate(l.timestamp)+'</span>'+
          '</div>';
        }).join("")+'</div>'
      : '<span style="color:#3a5068;font-size:12px">Nenhuma atividade registrada nos ultimos 30 dias</span>';

    return '<tr class="ar'+(isRisky?" risky":"")+'" onclick="toggle(\'rx-'+uid+'\')">' +
      '<td><div class="app-name">'+(a.displayName||"—")+
        (isRisky?'<span class="risk-badge">App Perm</span>':'')+
        ((a.secrets&&a.secrets.length>0)?'<span class="secret-badge">'+a.secrets.length+' secret(s)</span>':'')+
        (a.notes?'<span class="notes-badge">📝 notas</span>':'')+
      '</div></td>'+
      '<td>'+fmtDate(a.createdDateTime)+'</td>'+
      '<td>'+createdBy+'</td>'+
      '<td>'+ownersStr+'</td>'+
      '<td style="text-align:center"><span style="color:#f59e0b">'+(a.appRoles||[]).length+'</span> APP / <span style="color:#60a5fa">'+(a.delegated||[]).length+'</span> DEL</td>'+
    '</tr>'+
    '<tr id="rx-'+uid+'" style="display:none"><td colspan="5" class="expand-cell">'+
      notesHtml+
      '<div class="expand-tabs">'+
        '<div class="etab active" onclick="etab(this,\'epp-'+uid+'\')">🔑 Permissoes</div>'+
        '<div class="etab" onclick="etab(this,\'esg-'+uid+'\')">💡 Sugestoes'+(sugg.add.length+sugg.remove.length>0?' <span class="sugg-count">'+(sugg.add.length+sugg.remove.length)+'</span>':'')+'</div>'+
        '<div class="etab" onclick="etab(this,\'esr-'+uid+'\')">🔐 Secrets</div>'+
        '<div class="etab" onclick="etab(this,\'eat-'+uid+'\')">📋 Atividade</div>'+
      '</div>'+
      '<div id="epp-'+uid+'" class="epanel active"><div class="perm-wrap">'+permsHtml+'</div></div>'+
      '<div id="esg-'+uid+'" class="epanel" style="display:none"><div class="sugg-wrap">'+suggHtml+'</div></div>'+
      '<div id="esr-'+uid+'" class="epanel" style="display:none">'+secretsHtml+'</div>'+
      '<div id="eat-'+uid+'" class="epanel" style="display:none">'+auditHtml+'</div>'+
    '</td></tr>';
  }

  // HTML de cada aba — passa o prefixo para IDs unicos
  function buildTabTable(list, emptyMsg, tabPrefix) {
    if (list.length===0) return '<div class="empty-tab">'+emptyMsg+'</div>';
    return '<table><thead><tr><th>Nome</th><th>Criado em</th><th>Criado por</th><th>Owner(s)</th><th>Permissoes</th></tr></thead><tbody>'+
      list.map(function(a){ return buildAppRow(a, tabPrefix||"all"); }).join("")+'</tbody></table>';
  }

  var changesHtml = changes24h.length===0
    ? '<div class="no-changes">Nenhuma mudanca nas ultimas 24 horas</div>'
    : changes24h.slice().reverse().map(function(c){
        var icon=c.severity==="critico"?"🚨":c.severity==="aviso"?"⚠️":c.type==="removido"?"🗑️":c.type==="novo"?"✨":"✅";
        var color=c.severity==="critico"?"#ef4444":c.severity==="aviso"?"#f59e0b":c.severity==="melhora"?"#4ade80":"#60a5fa";
        var pd="";
        if (c.permChanges&&c.permChanges.length>0) {
          pd='<div class="perm-changes">'+c.permChanges.map(function(pc){
            var pcc=pc.action==="adicionada"?(pc.severity==="critico"?"#ef4444":"#f59e0b"):"#4ade80";
            return '<span class="pc" style="color:'+pcc+'">'+(pc.action==="adicionada"?"+":"-")+' ['+pc.type+'] '+pc.name+'</span>';
          }).join("")+'</div>';
        }
        return '<div class="change-item" style="border-left-color:'+color+'">'+
          '<div class="change-top"><span>'+icon+'</span><span class="change-msg">'+c.message+'</span><span class="change-time">'+fmtDate(c.detectedAt)+'</span></div>'+
          pd+'</div>';
      }).join("");

  var initChangesJson = JSON.stringify(changes24h.filter(function(c){ return (Date.now()-new Date(c.detectedAt).getTime())<300000; }));

  // Secrets expirando/expiradas para painel lateral
  var allSecretIssues = [];
  for (var a of apps) {
    for (var s of (a.secrets||[])) {
      if (s.status==="expirada"||s.status==="expirando") {
        allSecretIssues.push({ appName: a.displayName, secret: s });
      }
    }
  }
  var secretAlertsHtml = allSecretIssues.length===0
    ? '<div class="no-changes">Nenhuma secret expirando</div>'
    : allSecretIssues.map(function(item){
        var color=item.secret.status==="expirada"?"#ef4444":"#f59e0b";
        var label=item.secret.status==="expirada"?"EXPIRADA":"EXPIRA EM "+item.secret.daysToExp+"d";
        return '<div class="change-item" style="border-left-color:'+color+'">'+
          '<div class="change-top">'+
            '<span>'+(item.secret.status==="expirada"?"🚨":"⚠️")+'</span>'+
            '<span class="change-msg"><strong>'+item.appName+'</strong> — '+item.secret.displayName+'</span>'+
            '<span class="change-time" style="color:'+color+'">'+label+'</span>'+
          '</div>'+
          '<div style="font-size:11px;color:#3a5068;margin-top:4px;padding-left:20px">Criada: '+fmtDateOnly(item.secret.startDate)+' → Expira: '+fmtDateOnly(item.secret.endDate)+'</div>'+
        '</div>';
      }).join("");

  return '<!DOCTYPE html><html lang="pt-BR"><head>'+
'<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">'+
'<title>App Monitor</title>'+
'<style>'+
'@import url("https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600&display=swap");'+
'*{box-sizing:border-box;margin:0;padding:0}'+
'body{font-family:"Inter",sans-serif;background:#060a0f;color:#c8d8e8;min-height:100vh}'+
'.hdr{background:#0a1220;border-bottom:1px solid #1a2840;padding:12px 28px;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:200}'+
'.hdr-brand{display:flex;align-items:center;gap:12px}'+
'.hdr-brand h1{font-family:"JetBrains Mono",monospace;font-size:14px;color:#38bdf8;letter-spacing:2px;text-transform:uppercase}'+
'.tid{font-size:10px;color:#2a4060;margin-top:2px;font-family:"JetBrains Mono",monospace}'+
'.hdr-right{display:flex;align-items:center;gap:12px}'+
'.live{display:flex;align-items:center;gap:5px;font-size:11px;color:#4ade80;background:#0a1f10;padding:4px 10px;border-radius:20px;border:1px solid #166534;font-family:"JetBrains Mono",monospace}'+
'.dot{width:6px;height:6px;background:#4ade80;border-radius:50%;animation:pulse 2s infinite}'+
'@keyframes pulse{0%,100%{opacity:1;box-shadow:0 0 0 0 #4ade8060}50%{opacity:.5;box-shadow:0 0 0 4px transparent}}'+
'.cd{font-size:11px;color:#2a4060;font-family:"JetBrains Mono",monospace}'+
'.ri{font-size:16px;cursor:pointer;color:#2a4060;transition:color .2s,transform .3s}.ri:hover{color:#38bdf8}'+
'.refresh-spin{animation:spin .8s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}'+
'.upd{font-size:11px;color:#2a4060}'+

'.wrap{max-width:1400px;margin:0 auto;padding:20px}'+

// Stats
'.stats{display:grid;grid-template-columns:repeat(6,1fr);gap:8px;margin-bottom:16px}'+
'.sc{background:#0d1520;border:1px solid #1a2840;border-radius:10px;padding:14px 12px;text-align:center;cursor:pointer;transition:all .2s}'+
'.sc:hover{border-color:#38bdf8;transform:translateY(-2px)}'+
'.sc.active-tab{border-color:#0ea5e9;background:#061828}'+
'.sn{font-size:28px;font-weight:700;color:#c8d8e8;font-family:"JetBrains Mono",monospace}'+
'.sn.changed{animation:flash .6s}@keyframes flash{0%,100%{opacity:1}50%{opacity:.2}}'+
'.sl{font-size:10px;color:#3a5068;margin-top:3px;text-transform:uppercase;letter-spacing:.5px}'+

// Layout
'.layout{display:grid;grid-template-columns:1fr 320px;gap:14px;align-items:start}'+

// Card
'.card{background:#0d1520;border:1px solid #1a2840;border-radius:12px;padding:18px;margin-bottom:12px}'+
'.card-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}'+
'.card-title{font-family:"JetBrains Mono",monospace;font-size:11px;color:#3a5068;text-transform:uppercase;letter-spacing:2px}'+
'.search-bar{width:100%;background:#060a0f;border:1px solid #1a2840;border-radius:7px;padding:8px 12px;color:#c8d8e8;font-size:12px;margin-bottom:12px;outline:none;font-family:"JetBrains Mono",monospace;transition:border-color .2s}'+
'.search-bar:focus{border-color:#0ea5e9}'+

// Tabs de navegacao
'.nav-tabs{display:flex;gap:4px;margin-bottom:14px;flex-wrap:wrap}'+
'.ntab{padding:6px 14px;border-radius:6px;font-size:11px;cursor:pointer;background:transparent;color:#3a5068;border:1px solid #1a2840;font-family:"JetBrains Mono",monospace;transition:all .2s;white-space:nowrap}'+
'.ntab:hover{border-color:#38bdf8;color:#38bdf8}'+
'.ntab.active{background:#061828;border-color:#0ea5e9;color:#38bdf8}'+
'.tab-panel{display:none}.tab-panel.active{display:block}'+

// Tabela
'table{width:100%;border-collapse:collapse;font-size:12px}'+
'th{text-align:left;padding:8px 10px;color:#2a4060;font-weight:600;font-size:10px;text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid #1a2840;font-family:"JetBrains Mono",monospace;white-space:nowrap}'+
'td{padding:9px 10px;border-bottom:1px solid #0d1a2a;color:#94a3b8;vertical-align:middle}'+
'.ar{cursor:pointer;transition:background .15s}.ar:hover td{background:#0a1525}'+
'.ar.risky td:first-child{border-left:2px solid #f59e0b}'+
'.app-name{display:flex;align-items:center;gap:6px;flex-wrap:wrap;color:#c8d8e8;font-weight:500}'+
'.risk-badge{font-size:9px;font-weight:700;padding:1px 6px;border-radius:10px;background:#f59e0b20;color:#f59e0b;border:1px solid #f59e0b40;font-family:"JetBrains Mono",monospace;white-space:nowrap}'+
'.secret-badge{font-size:9px;font-weight:700;padding:1px 6px;border-radius:10px;background:#60a5fa20;color:#60a5fa;border:1px solid #60a5fa40;font-family:"JetBrains Mono",monospace;white-space:nowrap}'+

// Expand
'.expand-cell{background:#060d16;padding:14px 16px;border-bottom:1px solid #1a2840}'+
'.notes-box{background:#0a1f10;border:1px solid #166534;border-radius:7px;padding:10px 14px;margin-bottom:12px;font-size:12px;color:#86efac;line-height:1.6}'+
'.notes-label{font-weight:700;margin-right:6px;font-family:"JetBrains Mono",monospace;font-size:10px;text-transform:uppercase;letter-spacing:1px}'+
'.notes-badge{font-size:9px;font-weight:700;padding:1px 6px;border-radius:10px;background:#4ade8020;color:#4ade80;border:1px solid #4ade8040;font-family:"JetBrains Mono",monospace}'+
'.sugg-wrap{display:flex;flex-direction:column;gap:10px}'+
'.sugg-ok{font-size:12px;color:#4ade80;padding:8px;background:#061a10;border-radius:6px;font-family:"JetBrains Mono",monospace}'+
'.sugg-section{display:flex;flex-direction:column;gap:4px}'+
'.sugg-title{font-size:10px;font-weight:700;margin-bottom:6px;font-family:"JetBrains Mono",monospace;text-transform:uppercase;letter-spacing:1px}'+
'.sugg-item{display:flex;align-items:flex-start;gap:10px;padding:8px 10px;border-radius:6px;background:#060a0f;font-size:12px}'+
'.sugg-item code{font-family:"JetBrains Mono",monospace;font-size:11px;flex-shrink:0;padding:1px 4px;border-radius:3px;background:#0a1525}'+
'.sugg-remove code{color:#ef4444;border:1px solid #ef444430}'+
'.sugg-add code{color:#4ade80;border:1px solid #4ade8030}'+
'.sugg-item span{color:#94a3b8;line-height:1.5}'+
'.sugg-count{display:inline-flex;align-items:center;justify-content:center;width:16px;height:16px;background:#f59e0b;color:#000;border-radius:50%;font-size:9px;font-weight:700;margin-left:4px}'+
'.expand-tabs{display:flex;gap:4px;margin-bottom:12px}'+
'.etab{font-size:10px;padding:4px 10px;border-radius:5px;cursor:pointer;background:transparent;color:#3a5068;border:1px solid #1a2840;font-family:"JetBrains Mono",monospace;transition:all .2s}'+
'.etab:hover{border-color:#38bdf8;color:#38bdf8}'+
'.etab.active{background:#061828;border-color:#0ea5e9;color:#38bdf8}'+
'.epanel{}.epanel.active{display:block}'+
'.perm-wrap{display:flex;flex-wrap:wrap;gap:4px}'+
'.pb{display:inline-flex;align-items:center;gap:3px;font-size:10px;padding:2px 7px;border-radius:5px;border:1px solid;font-family:"JetBrains Mono",monospace;position:relative}'+
'.pt{font-size:8px;font-weight:700;opacity:.6}'+
'.pb-wrap{position:relative;display:inline-block;margin:2px}'+
'.pb-tooltip{display:none;position:absolute;bottom:calc(100% + 6px);left:50%;transform:translateX(-50%);background:#0a1a2a;border:1px solid #1e4060;border-radius:8px;padding:8px 12px;font-size:11px;color:#c8d8e8;white-space:pre-wrap;max-width:280px;min-width:180px;z-index:9999;box-shadow:0 8px 24px rgba(0,0,0,.7);line-height:1.5;pointer-events:none;text-align:left}'+
'.pb-wrap:hover .pb-tooltip{display:block}'+
'.leg{display:flex;gap:10px;font-size:10px;color:#2a4060;margin-bottom:10px;flex-wrap:wrap;font-family:"JetBrains Mono",monospace}'+

// Secrets
'.secrets-wrap{display:flex;flex-direction:column;gap:6px}'+
'.secret-item{display:flex;align-items:center;gap:12px;padding:8px 10px;background:#0a1525;border-radius:6px;flex-wrap:wrap}'+
'.secret-name{font-size:11px;color:#c8d8e8;font-family:"JetBrains Mono",monospace;flex:1}'+
'.secret-dates{font-size:10px;color:#3a5068}'+
'.secret-status{font-size:10px;font-weight:700;font-family:"JetBrains Mono",monospace}'+

// Audit
'.audit-wrap{display:flex;flex-direction:column;gap:4px}'+
'.audit-title{font-size:10px;color:#3a5068;margin-bottom:6px;font-family:"JetBrains Mono",monospace;text-transform:uppercase;letter-spacing:1px}'+
'.audit-item{display:flex;align-items:center;gap:10px;padding:6px 8px;background:#0a1525;border-radius:5px;flex-wrap:wrap}'+
'.audit-action{font-size:11px;color:#c8d8e8;flex:1}'+
'.audit-actor{font-size:10px;color:#38bdf8;font-family:"JetBrains Mono",monospace}'+
'.audit-time{font-size:10px;color:#3a5068}'+

// Side panel
'.side-card{background:#0d1520;border:1px solid #1a2840;border-radius:12px;padding:16px;margin-bottom:12px}'+
'.side-title{font-family:"JetBrains Mono",monospace;font-size:10px;color:#3a5068;text-transform:uppercase;letter-spacing:2px;margin-bottom:12px;display:flex;align-items:center;justify-content:space-between}'+
'.change-item{padding:9px 10px;border-left:2px solid #1a2840;background:#060d16;border-radius:0 6px 6px 0;margin-bottom:6px}'+
'.change-top{display:flex;align-items:center;gap:6px;flex-wrap:wrap}'+
'.change-msg{font-size:11px;color:#c8d8e8;flex:1}'+
'.change-time{font-size:10px;color:#3a5068;white-space:nowrap;font-family:"JetBrains Mono",monospace}'+
'.perm-changes{display:flex;flex-wrap:wrap;gap:3px;margin-top:6px;padding-top:6px;border-top:1px solid #1a2840}'+
'.pc{font-size:10px;font-weight:600;padding:1px 5px;background:#060a0f;border-radius:3px;font-family:"JetBrains Mono",monospace}'+
'.no-changes{font-size:11px;color:#2a4060;text-align:center;padding:20px 0;font-family:"JetBrains Mono",monospace}'+
'.empty-tab{font-size:12px;color:#2a4060;text-align:center;padding:40px 0;font-family:"JetBrains Mono",monospace}'+

// Toasts
'#toast-area{position:fixed;bottom:16px;right:16px;z-index:999;display:flex;flex-direction:column;gap:6px;max-width:360px}'+
'.toast{background:#0d1520;border:1px solid #1a2840;border-radius:10px;padding:10px 14px;font-size:12px;display:flex;align-items:flex-start;gap:8px;box-shadow:0 8px 32px rgba(0,0,0,.6);animation:slideUp .3s ease}'+
'.toast.critico{border-color:#ef4444;background:#1a0808}.toast.aviso{border-color:#f59e0b;background:#1a1208}'+
'.toast.melhora{border-color:#4ade80;background:#081a10}.toast.info{border-color:#60a5fa;background:#08101a}'+
'.tc{margin-left:auto;color:#2a4060;cursor:pointer;font-size:14px}'+
'@keyframes slideUp{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}'+
'.foot{text-align:center;padding:20px;color:#2a4060;font-size:11px;font-family:"JetBrains Mono",monospace}.foot a{color:#0ea5e9;text-decoration:none}'+
'</style></head><body>'+

'<div id="toast-area"></div>'+

'<div class="hdr">'+
  '<div class="hdr-brand">'+
    '<div><h1>// APP MONITOR</h1><div class="tid">'+session.tenantId+'</div></div>'+
  '</div>'+
  '<div class="hdr-right">'+
    '<div class="live"><div class="dot"></div>LIVE</div>'+
    '<div class="cd" id="cd">NEXT: <strong id="timer">5:00</strong></div>'+
    '<div class="ri" id="ri" title="Atualizar agora" onclick="forceRefresh()">↻</div>'+
    '<div class="upd">UPD: <span id="upd">agora</span></div>'+
  '</div>'+
'</div>'+

'<div class="wrap">'+

  // Stats clicaveis
  '<div class="stats">'+
    '<div class="sc active-tab" id="tab-btn-all" onclick="switchMainTab(\'all\',this)"><div class="sn" id="stTotal">'+allApps.length+'</div><div class="sl">Todos</div></div>'+
    '<div class="sc" id="tab-btn-risky" onclick="switchMainTab(\'risky\',this)"><div class="sn" id="stRisky" style="color:#f59e0b">'+riskyApps.length+'</div><div class="sl">App Perm</div></div>'+
    '<div class="sc" id="tab-btn-recent" onclick="switchMainTab(\'recent\',this)"><div class="sn" id="stRecent" style="color:#60a5fa">'+recentApps.length+'</div><div class="sl">Criados 30d</div></div>'+
    '<div class="sc" id="tab-btn-noowner" onclick="switchMainTab(\'noowner\',this)"><div class="sn" id="stNoOwner" style="color:#ef4444">'+noOwnerApps.length+'</div><div class="sl">Sem Owner</div></div>'+
    '<div class="sc" id="tab-btn-secrets" onclick="switchMainTab(\'secrets\',this)"><div class="sn" id="stSecrets" style="color:#a78bfa">'+appsWithSecrets.length+'</div><div class="sl">Com Secrets</div></div>'+
    '<div class="sc" id="tab-btn-expsecrets" onclick="switchMainTab(\'expsecrets\',this)"><div class="sn" id="stExpSecrets" style="color:#ef4444">'+expSecrets.length+'</div><div class="sl">Secrets Exp.</div></div>'+
  '</div>'+

  '<div class="layout">'+

    // Main panel
    '<div>'+
      '<div class="card">'+
        '<div class="card-header">'+
          '<div class="card-title" id="tabLabel">Todas as Aplicacoes ('+allApps.length+')</div>'+
          '<div class="leg">'+
            '<span style="color:#ef4444">■ Critico</span>'+
            '<span style="color:#f59e0b">■ Alto</span>'+
            '<span style="color:#4ade80">■ Normal</span>'+
            '<span>APP=Application | DEL=Delegated | Clique para expandir</span>'+
          '</div>'+
        '</div>'+
        '<input class="search-bar" id="search" type="text" placeholder="Buscar por nome, owner, criador ou permissao..." oninput="filterTable()">'+

        '<div id="tp-all" class="tab-panel active">'+
          '<table><thead><tr><th>Nome</th><th>Criado em</th><th>Criado por</th><th>Owner(s)</th><th>Permissoes</th></tr></thead>'+
          '<tbody>'+allApps.map(function(a){return buildAppRow(a,"all");}).join("")+'</tbody></table>'+
        '</div>'+
        '<div id="tp-risky" class="tab-panel">'+
          buildTabTable(riskyApps, "Nenhum app com Application Permission","risky")+
        '</div>'+
        '<div id="tp-recent" class="tab-panel">'+
          buildTabTable(recentApps, "Nenhum app criado nos ultimos 30 dias","recent")+
        '</div>'+
        '<div id="tp-noowner" class="tab-panel">'+
          buildTabTable(noOwnerApps, "Todos os apps possuem owner","noowner")+
        '</div>'+
        '<div id="tp-secrets" class="tab-panel">'+
          buildTabTable(appsWithSecrets, "Nenhum app com secrets registradas","secrets")+
        '</div>'+
        '<div id="tp-expsecrets" class="tab-panel">'+
          buildTabTable(expSecrets, "Nenhuma secret expirada ou expirando","expsecrets")+
        '</div>'+
      '</div>'+
    '</div>'+

    // Side panel
    '<div>'+
      '<div class="side-card">'+
        '<div class="side-title"><span>⚠️ Mudancas (24h)</span><span style="color:#2a4060">'+changes24h.length+'</span></div>'+
        '<div id="changesPanel">'+changesHtml+'</div>'+
      '</div>'+
      '<div class="side-card">'+
        '<div class="side-title"><span>🔑 Secrets Expirando</span><span style="color:#2a4060">'+allSecretIssues.length+'</span></div>'+
        '<div id="secretAlertsPanel">'+secretAlertsHtml+'</div>'+
      '</div>'+
    '</div>'+
  '</div>'+
'</div>'+

'<div class="foot"><a href="/">← Nova analise</a></div>'+

'<script>'+
'var SID="'+sessionId+'";'+
'var INTERVAL=5*60*1000;'+
'var next=Date.now()+INTERVAL;'+
'var busy=false;'+
'var currentTab="all";'+
'var initChanges='+initChangesJson+';'+
'if(initChanges&&initChanges.length>0){setTimeout(function(){initChanges.forEach(showToast);},700);}'+

// Countdown
'setInterval(function(){'+
'  if(busy)return;'+
'  var r=Math.max(0,next-Date.now());'+
'  var m=Math.floor(r/60000),s=Math.floor((r%60000)/1000);'+
'  document.getElementById("timer").textContent=m+":"+(s<10?"0":"")+s;'+
'  if(r<=0)doRefresh();'+
'},1000);'+

'function forceRefresh(){next=Date.now();}'+

// Switch tab principal (clique no stat card)
'function switchMainTab(name, el){'+
'  currentTab=name;'+
'  document.querySelectorAll(".sc").forEach(function(e){e.classList.remove("active-tab");});'+
'  el.classList.add("active-tab");'+
'  document.querySelectorAll(".tab-panel").forEach(function(e){e.classList.remove("active");e.style.display="none";});'+
'  var panel=document.getElementById("tp-"+name);'+
'  if(panel){panel.classList.add("active");panel.style.display="block";}'+
'  var labels={all:"Todas as Aplicacoes",risky:"App Permissions",recent:"Criados nos ultimos 30 dias",noowner:"Sem Owner",secrets:"Com Secrets",expsecrets:"Secrets Expirando/Expiradas"};'+
'  var counts={all:document.getElementById("stTotal").textContent,risky:document.getElementById("stRisky").textContent,recent:document.getElementById("stRecent").textContent,noowner:document.getElementById("stNoOwner").textContent,secrets:document.getElementById("stSecrets").textContent,expsecrets:document.getElementById("stExpSecrets").textContent};'+
'  document.getElementById("tabLabel").textContent=(labels[name]||name)+" ("+counts[name]+")";'+
'  document.getElementById("search").value="";'+
'}'+

// Filtro de busca
'function filterTable(){'+
'  var q=document.getElementById("search").value.toLowerCase();'+
'  var panelId="tp-"+currentTab;'+
'  var rows=document.querySelectorAll("#"+panelId+" tr.ar");'+
'  rows.forEach(function(row){'+
'    var text=row.textContent.toLowerCase();'+
'    var show=q===""||text.includes(q);'+
'    row.style.display=show?"":"none";'+
'    var id=row.getAttribute("onclick").replace("toggle(\'r-","").replace("\')","")||"";'+
'    var exp=document.getElementById("r-"+id.split("\'")[0]);'+
'    if(exp&&!show)exp.style.display="none";'+
'  });'+
'}'+

// Toggle expand row
'function toggle(id){var r=document.getElementById(id);if(r)r.style.display=r.style.display==="none"?"table-row":"none";}'+

// Toggle aba dentro do expand
'function etab(el,panelId){'+
'  var expand=el.closest(".expand-cell");'+
'  expand.querySelectorAll(".etab").forEach(function(e){e.classList.remove("active");});'+
'  expand.querySelectorAll(".epanel").forEach(function(e){e.style.display="none";});'+
'  el.classList.add("active");'+
'  var p=document.getElementById(panelId);if(p){p.style.display="block";}'+
'}'+

// Atualiza stat com flash
'function upd(id,v){var el=document.getElementById(id);if(el&&el.textContent!=String(v)){el.textContent=v;el.classList.remove("changed");void el.offsetWidth;el.classList.add("changed");}}'+

// Refresh
'function doRefresh(){'+
'  if(busy)return;busy=true;next=Date.now()+INTERVAL;'+
'  var ri=document.getElementById("ri");ri.classList.add("refresh-spin");'+
'  document.getElementById("cd").innerHTML="ATUALIZANDO...";'+
'  fetch("/refresh/"+SID).then(function(r){return r.json();})'+
'  .then(function(data){'+
'    if(data.error){showToast({severity:"critico",message:"Erro: "+data.error});return;}'+

'    var apps=data.apps;'+
'    var risky=apps.filter(function(a){return a.appRoles&&a.appRoles.length>0;}).length;'+
'    var recent=apps.filter(function(a){return a.createdDateTime&&(Date.now()-new Date(a.createdDateTime).getTime())/86400000<=30;}).length;'+
'    var noowner=apps.filter(function(a){return !a._owners||a._owners.length===0;}).length;'+
'    var wsecrets=apps.filter(function(a){return a.secrets&&a.secrets.length>0;}).length;'+
'    var expsec=apps.filter(function(a){return(a.secrets||[]).some(function(s){return s.status==="expirada"||s.status==="expirando";});}).length;'+

'    upd("stTotal",apps.length);upd("stRisky",risky);upd("stRecent",recent);'+
'    upd("stNoOwner",noowner);upd("stSecrets",wsecrets);upd("stExpSecrets",expsec);'+

'    if(data.changesLast24h){'+
'      var ch=data.changesLast24h;'+
'      var panel=document.getElementById("changesPanel");'+
'      if(ch.length===0){panel.innerHTML=\'<div class="no-changes">Nenhuma mudanca nas ultimas 24 horas</div>\';}'+
'      else{'+
'        panel.innerHTML=ch.slice().reverse().map(function(c){'+
'          var icon=c.severity==="critico"?"🚨":c.severity==="aviso"?"⚠️":c.type==="removido"?"🗑️":c.type==="novo"?"✨":"✅";'+
'          var color=c.severity==="critico"?"#ef4444":c.severity==="aviso"?"#f59e0b":c.severity==="melhora"?"#4ade80":"#60a5fa";'+
'          var pd="";'+
'          if(c.permChanges&&c.permChanges.length>0){'+
'            pd=\'<div class="perm-changes">\'+c.permChanges.map(function(pc){'+
'              var pcc=pc.action==="adicionada"?(pc.severity==="critico"?"#ef4444":"#f59e0b"):"#4ade80";'+
'              return\'<span class="pc" style="color:\'+pcc+\'">\'+( pc.action==="adicionada"?"+":"-")+\' [\'+pc.type+\'] \'+pc.name+"</span>";'+
'            }).join("")+"</div>";'+
'          }'+
'          return\'<div class="change-item" style="border-left-color:\'+color+\'">\'+'+
'            \'<div class="change-top"><span>\'+icon+\'</span><span class="change-msg">\'+c.message+\'</span><span class="change-time">\'+new Date(c.detectedAt).toLocaleTimeString("pt-BR")+\'</span></div>\'+'+
'            pd+"</div>";'+
'        }).join("");'+
'      }'+
'      if(data.newChanges&&data.newChanges.length>0){data.newChanges.forEach(showToast);}'+
'    }'+

'    document.getElementById("upd").textContent=new Date().toLocaleTimeString("pt-BR");'+
'  })'+
'  .catch(function(e){showToast({severity:"critico",message:"Falha: "+e.message});})'+
'  .finally(function(){'+
'    busy=false;ri.classList.remove("refresh-spin");'+
'    document.getElementById("cd").innerHTML=\'NEXT: <strong id="timer">5:00</strong>\';'+
'  });'+
'}'+

'function showToast(c){'+
'  var area=document.getElementById("toast-area");'+
'  var icons={critico:"🚨",aviso:"⚠️",melhora:"✅",info:"ℹ️"};'+
'  var t=document.createElement("div");'+
'  t.className="toast "+(c.severity||"info");'+
'  t.innerHTML=\'<span>\'+( icons[c.severity]||"ℹ️")+\'</span><span>\'+c.message+\'</span><span class="tc" onclick="this.parentElement.remove()">×</span>\';'+
'  area.appendChild(t);'+
'  setTimeout(function(){if(t.parentElement)t.remove();},10000);'+
'}'+

// Inicializa exibicao
'document.querySelectorAll(".tab-panel").forEach(function(e){if(!e.classList.contains("active"))e.style.display="none";});'+
'</script></body></html>';
}

app.listen(3001, () => console.log("📦 App Monitor rodando em http://localhost:3001"));