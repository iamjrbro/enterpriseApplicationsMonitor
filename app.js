require("dotenv").config();
const express = require("express");
const { ConfidentialClientApplication } = require("@azure/msal-node");
const axios = require("axios");

const app = express();
const REDIRECT_URI = "http://localhost:3001/callback";

const cca = new ConfidentialClientApplication({
  auth: {
    clientId: process.env.CLIENT_ID,
    authority: "https://login.microsoftonline.com/common",
    clientSecret: process.env.CLIENT_SECRET,
  },
});

const sessions = {};

// ─── Graph helpers ────────────────────────────────────────────────────────────
async function graphRequest(url, token) {
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

// Busca apps com campos extras: owners, auditLogs (quem criou)
async function getApps(token) {
  return graphPaged(
    "/applications?$select=displayName,appId,id,requiredResourceAccess,createdDateTime,signInAudience,notes,tags,web,publicClient&$top=999",
    token, 10000
  );
}

// Busca owners de um app especifico
async function getAppOwners(appObjectId, token) {
  try {
    var res = await graphRequest("/applications/" + appObjectId + "/owners?$select=displayName,userPrincipalName,mail", token);
    return res.value || [];
  } catch (e) {
    return [];
  }
}

// Busca service principals para resolver nomes de permissoes
async function getAllSPs(token) {
  return graphPaged(
    "/servicePrincipals?$select=displayName,appId,oauth2PermissionScopes,appRoles&$top=999",
    token, 10000
  );
}

// Busca SP especifico do Microsoft Graph (tem todas as permissoes do Graph API)
async function getMsGraphSP(token) {
  try {
    var res = await graphRequest(
      "/servicePrincipals?$filter=appId eq '00000003-0000-0000-c000-000000000000'&$select=displayName,appId,oauth2PermissionScopes,appRoles",
      token
    );
    return res.value || [];
  } catch (e) { return []; }
}

async function getExchangeSP(token) {
  try {
    var res = await graphRequest(
      "/servicePrincipals?$filter=appId eq '00000002-0000-0ff1-ce00-000000000000'&$select=displayName,appId,oauth2PermissionScopes,appRoles",
      token
    );
    return res.value || [];
  } catch (e) { return []; }
}

async function getSharePointSP(token) {
  try {
    var res = await graphRequest(
      "/servicePrincipals?$filter=appId eq '00000003-0000-0ff1-ce00-000000000000'&$select=displayName,appId,oauth2PermissionScopes,appRoles",
      token
    );
    return res.value || [];
  } catch (e) { return []; }
}

// ─── Coleta completa de apps ──────────────────────────────────────────────────
async function collectApps(token) {
  var [appsData, allSPs, msGraphSPs, exchangeSPs, sharePointSPs] = await Promise.all([
    getApps(token),
    getAllSPs(token),
    getMsGraphSP(token),
    getExchangeSP(token),
    getSharePointSP(token),
  ]);

  // Mapa appId -> SP
  var spMap = {};
  for (var sp of allSPs.value) spMap[sp.appId] = sp;
  for (var sp of [...msGraphSPs, ...exchangeSPs, ...sharePointSPs]) spMap[sp.appId] = sp;

  // Busca owners em paralelo (limitado a 20 simultaneos para nao sobrecarregar)
  var apps = appsData.value;
  var chunkSize = 20;
  var appsWithOwners = [];
  for (var i = 0; i < apps.length; i += chunkSize) {
    var chunk = apps.slice(i, i + chunkSize);
    var ownersChunk = await Promise.all(
      chunk.map(function(a) { return getAppOwners(a.id, token); })
    );
    for (var j = 0; j < chunk.length; j++) {
      chunk[j]._owners = ownersChunk[j];
    }
    appsWithOwners = appsWithOwners.concat(chunk);
  }

  // Resolve permissoes
  var result = appsWithOwners.map(function(application) {
    var appRoles = [];
    var delegated = [];

    if (application.requiredResourceAccess) {
      for (var resource of application.requiredResourceAccess) {
        var resourceSp = spMap[resource.resourceAppId];
        for (var access of resource.resourceAccess) {
          if (access.type === "Role") {
            var roleDef = resourceSp && resourceSp.appRoles
              ? resourceSp.appRoles.find(function(r) { return r.id === access.id; }) : null;
            appRoles.push({
              id: access.id,
              name: roleDef ? roleDef.value : null,
              description: roleDef ? roleDef.displayName : null,
              resource: resourceSp ? resourceSp.displayName : resource.resourceAppId,
            });
          } else {
            var scopeDef = resourceSp && resourceSp.oauth2PermissionScopes
              ? resourceSp.oauth2PermissionScopes.find(function(s) { return s.id === access.id; }) : null;
            delegated.push({
              id: access.id,
              name: scopeDef ? scopeDef.value : null,
              description: scopeDef ? scopeDef.adminConsentDisplayName : null,
              resource: resourceSp ? resourceSp.displayName : resource.resourceAppId,
            });
          }
        }
      }
    }

    return Object.assign({}, application, { appRoles, delegated });
  });

  return result;
}

// ─── Detecta mudancas entre dois snapshots de apps ───────────────────────────
function detectAppChanges(prevApps, currApps) {
  var changes = [];
  var prevMap = {};
  var currMap = {};

  for (var a of prevApps) prevMap[a.appId] = a;
  for (var a of currApps)  currMap[a.appId] = a;

  // Apps novos
  for (var appId in currMap) {
    if (!prevMap[appId]) {
      changes.push({
        type: "novo",
        severity: "aviso",
        appName: currMap[appId].displayName || appId,
        appId: appId,
        message: "Nova aplicacao registrada: " + (currMap[appId].displayName || appId),
      });
    }
  }

  // Apps removidos
  for (var appId in prevMap) {
    if (!currMap[appId]) {
      changes.push({
        type: "removido",
        severity: "info",
        appName: prevMap[appId].displayName || appId,
        appId: appId,
        message: "Aplicacao removida: " + (prevMap[appId].displayName || appId),
      });
    }
  }

  // Apps modificados
  for (var appId in currMap) {
    if (!prevMap[appId]) continue;
    var prev = prevMap[appId];
    var curr = currMap[appId];

    var permChanges = [];

    // Permissoes adicionadas
    var prevRoleIds = (prev.appRoles || []).map(function(r) { return r.id; });
    var currRoleIds = (curr.appRoles || []).map(function(r) { return r.id; });
    var addedRoles = currRoleIds.filter(function(id) { return !prevRoleIds.includes(id); });
    var removedRoles = prevRoleIds.filter(function(id) { return !currRoleIds.includes(id); });

    for (var id of addedRoles) {
      var perm = (curr.appRoles || []).find(function(r) { return r.id === id; });
      permChanges.push({ action: "adicionada", type: "APP", name: perm ? (perm.name || id) : id, severity: "critico" });
    }
    for (var id of removedRoles) {
      var perm = (prev.appRoles || []).find(function(r) { return r.id === id; });
      permChanges.push({ action: "removida", type: "APP", name: perm ? (perm.name || id) : id, severity: "melhora" });
    }

    var prevDelIds = (prev.delegated || []).map(function(r) { return r.id; });
    var currDelIds = (curr.delegated || []).map(function(r) { return r.id; });
    var addedDel = currDelIds.filter(function(id) { return !prevDelIds.includes(id); });
    var removedDel = prevDelIds.filter(function(id) { return !currDelIds.includes(id); });

    for (var id of addedDel) {
      var perm = (curr.delegated || []).find(function(r) { return r.id === id; });
      permChanges.push({ action: "adicionada", type: "DEL", name: perm ? (perm.name || id) : id, severity: "aviso" });
    }
    for (var id of removedDel) {
      var perm = (prev.delegated || []).find(function(r) { return r.id === id; });
      permChanges.push({ action: "removida", type: "DEL", name: perm ? (perm.name || id) : id, severity: "melhora" });
    }

    if (permChanges.length > 0) {
      var worstSeverity = permChanges.some(function(c) { return c.severity === "critico"; }) ? "critico"
        : permChanges.some(function(c) { return c.severity === "aviso"; }) ? "aviso" : "melhora";
      changes.push({
        type: "permissao",
        severity: worstSeverity,
        appName: curr.displayName || appId,
        appId: appId,
        message: (curr.displayName || appId) + ": " + permChanges.length + " alteracao(es) de permissao",
        permChanges: permChanges,
      });
    }
  }

  return changes;
}

// ─── Classifica risco de permissao ───────────────────────────────────────────
function classifyPerm(name) {
  if (!name) return "normal";
  var critical = ["Mail.ReadWrite","Mail.Send","Files.ReadWrite.All","Directory.ReadWrite.All",
    "User.ReadWrite.All","RoleManagement.ReadWrite.Directory","Application.ReadWrite.All",
    "Group.ReadWrite.All","full_access_as_app"];
  var high = ["Mail.Read","Files.Read.All","User.Read.All","Directory.Read.All",
    "AuditLog.Read.All","Policy.Read.All","IdentityRiskyUser.Read.All"];
  if (critical.some(function(c) { return name.includes(c); })) return "critico";
  if (high.some(function(h) { return name.includes(h); })) return "alto";
  return "normal";
}

function permLabel(p) {
  return p.name || "[" + p.id.substring(0, 8) + "...]";
}

function fmt(date) {
  if (!date) return "—";
  return new Date(date).toLocaleString("pt-BR");
}

function sleep(ms) { return new Promise(function(r) { setTimeout(r, ms); }); }

// ─── Rotas ────────────────────────────────────────────────────────────────────
app.get("/", async (req, res) => {
  const authUrl = await cca.getAuthCodeUrl({
    scopes: ["User.Read", "Directory.Read.All", "Application.Read.All", "AuditLog.Read.All"],
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
      scopes: ["User.Read", "Directory.Read.All", "Application.Read.All", "AuditLog.Read.All"],
      redirectUri: REDIRECT_URI,
    });

    const sessionId = Math.random().toString(36).slice(2);
    sessions[sessionId] = {
      token: tokenResponse.accessToken,
      tenantId: tokenResponse.tenantId,
      snapshots: [],
      lastApps: null,
      lastChanges: [],
      lastUpdated: null,
    };

    res.send(buildLoadingPage(sessionId, tokenResponse.tenantId));
  } catch (err) {
    console.error(err);
    res.status(500).send("<h2>Erro</h2><pre>" + err.message + "</pre><a href='/'>Tentar novamente</a>");
  }
});

app.get("/progress/:sessionId", function(req, res) {
  const sessionId = req.params.sessionId;
  if (!sessions[sessionId]) return res.status(404).end();

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();

  function send(data) { res.write("data: " + JSON.stringify(data) + "\n\n"); }

  runCollection(sessionId, send).then(function() {
    send({ type: "done" });
    res.end();
  }).catch(function(err) {
    send({ type: "error", message: err.message });
    res.end();
  });
});

async function runCollection(sessionId, send) {
  var session = sessions[sessionId];

  send({ type: "step", status: "running", label: "Conectando ao tenant..." });
  await sleep(200);
  send({ type: "step", status: "done", label: "Conectado: " + session.tenantId });

  send({ type: "step", status: "running", label: "Buscando aplicacoes registradas..." });
  var apps = await collectApps(session.token);
  send({ type: "step", status: "done", label: apps.length + " aplicacoes encontradas" });

  send({ type: "step", status: "running", label: "Resolvendo permissoes e owners..." });
  await sleep(200);
  var totalPerms = apps.reduce(function(acc, a) { return acc + (a.appRoles||[]).length + (a.delegated||[]).length; }, 0);
  send({ type: "step", status: "done", label: totalPerms + " permissoes mapeadas em " + apps.length + " apps" });

  send({ type: "step", status: "running", label: "Detectando mudancas..." });
  var changes = session.lastApps ? detectAppChanges(session.lastApps, apps) : [];
  send({ type: "step", status: "done", label: changes.length + " mudanca(s) detectada(s)" });

  // Salva snapshot
  session.snapshots.push({ timestamp: new Date().toISOString(), count: apps.length });
  if (session.snapshots.length > 50) session.snapshots.shift();
  session.lastApps = apps;
  session.lastChanges = changes;
  session.lastUpdated = new Date();

  send({ type: "step", status: "running", label: "Gerando dashboard..." });
  await sleep(200);
  send({ type: "step", status: "done", label: "Pronto!" });
}

app.get("/refresh/:sessionId", async function(req, res) {
  var session = sessions[req.params.sessionId];
  if (!session) return res.status(404).json({ error: "Sessao nao encontrada" });

  try {
    var apps = await collectApps(session.token);
    var changes = session.lastApps ? detectAppChanges(session.lastApps, apps) : [];

    session.snapshots.push({ timestamp: new Date().toISOString(), count: apps.length });
    if (session.snapshots.length > 50) session.snapshots.shift();
    session.lastApps = apps;
    session.lastChanges = changes;
    session.lastUpdated = new Date();

    res.json({ apps: apps, changes: changes, updatedAt: session.lastUpdated, snapshots: session.snapshots });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/dashboard/:sessionId", function(req, res) {
  var session = sessions[req.params.sessionId];
  if (!session || !session.lastApps) return res.status(404).send("Dashboard nao encontrado.");
  res.send(buildDashboard(session));
});

// ─── Loading page ─────────────────────────────────────────────────────────────
function buildLoadingPage(sessionId, tenantId) {
  return '<!DOCTYPE html><html lang="pt-BR"><head>' +
'<meta charset="UTF-8"><title>Carregando...</title>' +
'<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}.card{background:#1e293b;border-radius:20px;padding:48px 40px;max-width:560px;width:100%}h1{font-size:22px;color:#f1f5f9;margin-bottom:6px}.tid{font-size:12px;color:#475569;margin-bottom:28px}.bar-wrap{height:4px;background:#0f172a;border-radius:2px;margin-bottom:28px;overflow:hidden}.bar{height:100%;background:linear-gradient(90deg,#3b82f6,#8b5cf6);border-radius:2px;width:0%;transition:width .6s ease}.steps{display:flex;flex-direction:column;gap:8px}.step{display:flex;align-items:center;gap:12px;padding:11px 14px;border-radius:10px;background:#0f172a;font-size:13px;color:#64748b;transition:all .3s}.step.running{background:#172554;color:#93c5fd}.step.done{background:#052e16;color:#86efac}.step.error{background:#2a0f0f;color:#fca5a5}.icon{width:18px;height:18px;display:flex;align-items:center;justify-content:center;flex-shrink:0}.spinner{width:14px;height:14px;border:2px solid #334155;border-top-color:#60a5fa;border-radius:50%;animation:spin .7s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}.reveal{text-align:center;margin-top:32px;display:none}.big{font-size:56px;font-weight:800;color:#60a5fa}.sub{font-size:13px;color:#64748b;margin-top:6px}.btn{display:inline-block;margin-top:20px;padding:13px 32px;background:#3b82f6;color:#fff;border-radius:10px;text-decoration:none;font-weight:600;font-size:14px}</style></head><body>' +
'<div class="card"><h1>📦 App Permission Monitor</h1><div class="tid">'+tenantId+'</div>' +
'<div class="bar-wrap"><div class="bar" id="bar"></div></div>' +
'<div class="steps" id="steps"></div>' +
'<div class="reveal" id="reveal"><div class="big" id="bigNum"></div><div class="sub">aplicacoes encontradas</div><a class="btn" id="btn" href="#">Abrir monitor</a></div></div>' +
'<script>' +
'var total=5,done=0,active=null;' +
'var stepsEl=document.getElementById("steps"),bar=document.getElementById("bar");' +
'var es=new EventSource("/progress/'+sessionId+'");' +
'es.onmessage=function(e){' +
'  var d=JSON.parse(e.data);' +
'  if(d.type==="step"){' +
'    if(d.status==="running"){' +
'      if(active){active.className="step done";active.querySelector(".icon").innerHTML="✓";done++;bar.style.width=Math.min(90,Math.round(done/total*100))+"%";}' +
'      var el=document.createElement("div");el.className="step running";' +
'      el.innerHTML="<div class=\\"icon\\"><div class=\\"spinner\\"></div></div><span>"+d.label+"</span>";' +
'      stepsEl.appendChild(el);el.scrollIntoView({behavior:"smooth"});active=el;' +
'    } else if(d.status==="done"&&active){active.querySelector("span").textContent=d.label;}' +
'  }' +
'  if(d.type==="done"){' +
'    if(active){active.className="step done";active.querySelector(".icon").innerHTML="✓";}' +
'    bar.style.width="100%";es.close();' +
'    document.getElementById("btn").href="/dashboard/'+sessionId+'";' +
'    document.getElementById("reveal").style.display="block";' +
'  }' +
'  if(d.type==="error"){' +
'    if(active){active.className="step error";active.querySelector(".icon").innerHTML="✗";}' +
'    var err=document.createElement("div");err.className="step error";' +
'    err.innerHTML="<div class=\\"icon\\">✗</div><span>Erro: "+d.message+"</span>";' +
'    stepsEl.appendChild(err);es.close();' +
'  }' +
'};' +
'</script></body></html>';
}

// ─── Dashboard principal ──────────────────────────────────────────────────────
function buildDashboard(session) {
  var apps = session.lastApps;
  var changes = session.lastChanges || [];
  var sessionId = Object.keys(sessions).find(function(k) { return sessions[k] === session; });
  var riskColor = { critico:"#ef4444", alto:"#f59e0b", normal:"#22c55e" };

  var totalApps = apps.length;
  var appsWithAppPerm = apps.filter(function(a) { return a.appRoles && a.appRoles.length > 0; }).length;
  var appsWithoutOwner = apps.filter(function(a) { return !a._owners || a._owners.length === 0; }).length;
  var recentApps = apps.filter(function(a) {
    return a.createdDateTime && (Date.now() - new Date(a.createdDateTime).getTime()) / 86400000 <= 30;
  }).length;

  // Tabela de apps
  var appsRows = apps.map(function(a) {
    var allPerms = (a.appRoles || []).concat(a.delegated || []);
    var isRisky = a.appRoles && a.appRoles.length > 0;
    var owners = (a._owners || []).map(function(o) { return o.displayName || o.userPrincipalName || o.mail || "?"; });
    var ownersStr = owners.length > 0 ? owners.join(", ") : '<span style="color:#ef4444">Sem owner</span>';

    var permsHtml = allPerms.length === 0
      ? '<span style="color:#475569;font-size:12px">Nenhuma permissao</span>'
      : allPerms.map(function(p) {
          var risk = classifyPerm(p.name);
          var isApp = !!(a.appRoles || []).find(function(r) { return r.id === p.id; });
          var label = permLabel(p);
          var desc = p.description ? p.description : label;
          return '<span class="pb" style="border-color:'+riskColor[risk]+';color:'+riskColor[risk]+'" title="'+desc+'">' +
            '<span class="pt">'+(isApp?"APP":"DEL")+'</span> '+label+'</span>';
        }).join("");

    var rowClass = isRisky ? "ar risky" : "ar";
    return '<tr class="'+rowClass+'" onclick="toggle(\'r-'+a.appId+'\')">' +
      '<td><strong>'+(a.displayName||"—")+'</strong>' +
        (isRisky ? '<span class="risk-badge">App Permission</span>' : '') +
      '</td>' +
      '<td>'+fmt(a.createdDateTime)+'</td>' +
      '<td>'+ownersStr+'</td>' +
      '<td>'+(a.signInAudience||"—")+'</td>' +
      '<td style="text-align:center">'+(a.appRoles||[]).length+'APP / '+(a.delegated||[]).length+'DEL</td>' +
    '</tr>' +
    '<tr id="r-'+a.appId+'" style="display:none">' +
      '<td colspan="5" class="expand-cell">' +
        '<div class="expand-header">Permissoes de <strong>'+(a.displayName||a.appId)+'</strong> — clique para fechar</div>' +
        '<div class="perm-wrap">'+permsHtml+'</div>' +
        (a.notes ? '<div class="expand-notes">Notas: '+a.notes+'</div>' : '') +
      '</td>' +
    '</tr>';
  }).join("");

  // Painel de mudancas
  var changesHtml = changes.length === 0
    ? '<div class="no-changes">Nenhuma mudanca detectada nesta atualizacao</div>'
    : changes.map(function(c) {
        var icon = c.severity === "critico" ? "🚨" : c.severity === "aviso" ? "⚠️" : c.type === "removido" ? "🗑️" : c.type === "novo" ? "✨" : "✅";
        var color = c.severity === "critico" ? "#ef4444" : c.severity === "aviso" ? "#f59e0b" : c.severity === "melhora" ? "#22c55e" : "#60a5fa";
        var permDetail = "";
        if (c.permChanges && c.permChanges.length > 0) {
          permDetail = '<div class="perm-changes">' +
            c.permChanges.map(function(pc) {
              var pc_color = pc.action === "adicionada"
                ? (pc.severity === "critico" ? "#ef4444" : "#f59e0b")
                : "#22c55e";
              var pc_icon = pc.action === "adicionada" ? "+" : "-";
              return '<span class="pc" style="color:'+pc_color+'">' +
                pc_icon + ' [' + pc.type + '] ' + pc.name + '</span>';
            }).join("") +
          '</div>';
        }
        return '<div class="change-item" style="border-left-color:'+color+'">' +
          '<div class="change-top">' +
            '<span class="change-icon">'+icon+'</span>' +
            '<span class="change-msg">'+c.message+'</span>' +
            '<span class="change-time">'+new Date().toLocaleTimeString("pt-BR")+'</span>' +
          '</div>' +
          permDetail +
        '</div>';
      }).join("");

  // Log de historico de snapshots
  var snapshotHtml = (session.snapshots || []).slice(-15).reverse().map(function(s) {
    return '<div class="snap"><span class="snap-time">'+new Date(s.timestamp).toLocaleTimeString("pt-BR")+'</span>' +
      '<span class="snap-count">'+s.count+' apps</span></div>';
  }).join("");

  var initialChangesJson = JSON.stringify(changes);

  return '<!DOCTYPE html><html lang="pt-BR"><head>' +
'<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
'<title>App Permission Monitor</title>' +
'<style>' +
'*{box-sizing:border-box;margin:0;padding:0}' +
'body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}' +
'.hdr{background:#1e293b;border-bottom:1px solid #334155;padding:14px 28px;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:100}' +
'.hdr-left h1{font-size:17px;color:#f1f5f9}.tid{font-size:11px;color:#475569;margin-top:2px}' +
'.hdr-right{display:flex;align-items:center;gap:14px}' +
'.live{display:flex;align-items:center;gap:6px;font-size:12px;color:#22c55e;background:#052e16;padding:5px 12px;border-radius:20px;border:1px solid #166534}' +
'.dot{width:7px;height:7px;background:#22c55e;border-radius:50%;animation:pulse 2s infinite}' +
'@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}' +
'.cd{font-size:12px;color:#475569}.upd{font-size:12px;color:#475569}' +
'.ri{font-size:18px;cursor:pointer;color:#475569;transition:transform .3s}.ri:hover{color:#94a3b8}' +
'.refresh-spin{animation:spin .8s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}' +
'.wrap{max-width:1300px;margin:0 auto;padding:24px 20px}' +
'.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}' +
'.sc{background:#1e293b;border-radius:12px;padding:18px;text-align:center}' +
'.sn{font-size:38px;font-weight:800;color:#f1f5f9}.sl{font-size:12px;color:#64748b;margin-top:4px}' +
'.sn.changed{animation:flash .6s}@keyframes flash{0%,100%{opacity:1}50%{opacity:.3}}' +
'.layout{display:grid;grid-template-columns:1fr 340px;gap:16px;align-items:start}' +
'.card{background:#1e293b;border-radius:14px;padding:20px;margin-bottom:16px}' +
'.card h2{font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:.08em;font-weight:700;margin-bottom:14px}' +
'.search-bar{width:100%;background:#0f172a;border:1px solid #334155;border-radius:8px;padding:8px 12px;color:#e2e8f0;font-size:13px;margin-bottom:14px;outline:none}' +
'.search-bar:focus{border-color:#3b82f6}' +
'table{width:100%;border-collapse:collapse;font-size:13px}' +
'th{text-align:left;padding:9px 12px;color:#64748b;font-weight:600;font-size:11px;text-transform:uppercase;border-bottom:1px solid #334155;white-space:nowrap}' +
'td{padding:10px 12px;border-bottom:1px solid #1e293b;color:#cbd5e1;vertical-align:top}' +
'.ar{cursor:pointer}.ar:hover td{background:#162032}' +
'.ar.risky td:first-child{border-left:3px solid #f59e0b}' +
'.risk-badge{display:inline-block;margin-left:8px;font-size:10px;font-weight:700;padding:1px 6px;border-radius:10px;background:#f59e0b20;color:#f59e0b;vertical-align:middle}' +
'.expand-cell{background:#0a1120;padding:14px 16px}' +
'.expand-header{font-size:11px;color:#64748b;margin-bottom:10px}' +
'.perm-wrap{display:flex;flex-wrap:wrap;gap:5px}' +
'.expand-notes{font-size:12px;color:#475569;margin-top:10px;padding-top:10px;border-top:1px solid #1e293b}' +
'.pb{display:inline-flex;align-items:center;gap:3px;font-size:11px;padding:3px 8px;border-radius:6px;border:1px solid;cursor:help}' +
'.pt{font-size:9px;font-weight:700;opacity:.7}' +
'.leg{display:flex;gap:12px;font-size:11px;color:#64748b;margin-bottom:10px;flex-wrap:wrap}' +
'/* Painel direito */' +
'.side-card{background:#1e293b;border-radius:14px;padding:18px;margin-bottom:14px}' +
'.side-card h2{font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:.08em;font-weight:700;margin-bottom:12px}' +
'.change-item{padding:10px 12px;border-left:3px solid #334155;background:#0f172a;border-radius:0 8px 8px 0;margin-bottom:8px}' +
'.change-top{display:flex;align-items:center;gap:8px}' +
'.change-icon{font-size:14px;flex-shrink:0}' +
'.change-msg{font-size:13px;color:#e2e8f0;flex:1}' +
'.change-time{font-size:11px;color:#475569;white-space:nowrap}' +
'.perm-changes{display:flex;flex-wrap:wrap;gap:4px;margin-top:8px;padding-top:8px;border-top:1px solid #1e293b}' +
'.pc{font-size:11px;font-weight:600;padding:2px 6px;background:#0a1120;border-radius:4px}' +
'.no-changes{font-size:13px;color:#475569;text-align:center;padding:20px 0}' +
'.snap{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid #1e293b;font-size:12px}' +
'.snap-time{color:#64748b}.snap-count{color:#94a3b8}' +
'/* Toasts */' +
'#toast-area{position:fixed;bottom:20px;right:20px;z-index:999;display:flex;flex-direction:column;gap:8px;max-width:360px}' +
'.toast{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:12px 16px;font-size:13px;display:flex;align-items:flex-start;gap:10px;box-shadow:0 8px 24px rgba(0,0,0,.4);animation:slideIn .3s ease}' +
'.toast.critico{border-color:#ef4444;background:#2a0f0f}.toast.aviso{border-color:#f59e0b;background:#2a1f00}' +
'.toast.melhora{border-color:#22c55e;background:#052e16}.toast.info{border-color:#60a5fa;background:#0f2a4a}' +
'.tc{margin-left:auto;color:#475569;cursor:pointer}' +
'@keyframes slideIn{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}' +
'.foot{text-align:center;padding:20px;color:#475569;font-size:12px}.foot a{color:#60a5fa;text-decoration:none}' +
'</style></head><body>' +

'<div id="toast-area"></div>' +

'<div class="hdr">' +
  '<div class="hdr-left"><h1>📦 App Permission Monitor</h1><div class="tid">'+session.tenantId+'</div></div>' +
  '<div class="hdr-right">' +
    '<div class="live"><div class="dot"></div>LIVE</div>' +
    '<div class="cd" id="cd">Prox. atualizacao: <strong id="timer">5:00</strong></div>' +
    '<div class="ri" id="ri" title="Atualizar agora" onclick="forceRefresh()">↻</div>' +
    '<div class="upd">Atualizado: <span id="upd">agora</span></div>' +
  '</div>' +
'</div>' +

'<div class="wrap">' +
  '<div class="stats">' +
    '<div class="sc"><div class="sn" id="stTotal">'+totalApps+'</div><div class="sl">Total de Apps</div></div>' +
    '<div class="sc"><div class="sn" id="stRisky" style="color:#f59e0b">'+appsWithAppPerm+'</div><div class="sl">Com App Permission</div></div>' +
    '<div class="sc"><div class="sn" id="stNoOwner" style="color:#ef4444">'+appsWithoutOwner+'</div><div class="sl">Sem Owner</div></div>' +
    '<div class="sc"><div class="sn" id="stRecent" style="color:#60a5fa">'+recentApps+'</div><div class="sl">Criados (30 dias)</div></div>' +
  '</div>' +

  '<div class="layout">' +
    '<div>' +
      '<div class="card">' +
        '<h2>Aplicacoes ('+totalApps+')</h2>' +
        '<input class="search-bar" id="search" type="text" placeholder="Buscar por nome, owner ou permissao..." oninput="filterTable()">' +
        '<div class="leg">' +
          '<span><span style="color:#ef4444">■</span> Critico</span>' +
          '<span><span style="color:#f59e0b">■</span> Alto</span>' +
          '<span><span style="color:#22c55e">■</span> Normal</span>' +
          '<span>APP=Application | DEL=Delegated | Clique para expandir | Passe o mouse na permissao para descricao</span>' +
        '</div>' +
        '<table>' +
          '<thead><tr>' +
            '<th>Nome</th>' +
            '<th>Criado em</th>' +
            '<th>Owner(s)</th>' +
            '<th>Audiencia</th>' +
            '<th style="text-align:center">Permissoes</th>' +
          '</tr></thead>' +
          '<tbody id="appsBody">'+appsRows+'</tbody>' +
        '</table>' +
      '</div>' +
    '</div>' +

    '<div>' +
      '<div class="side-card">' +
        '<h2>Mudancas detectadas</h2>' +
        '<div id="changesPanel">'+changesHtml+'</div>' +
      '</div>' +
      '<div class="side-card">' +
        '<h2>Historico de coletas</h2>' +
        '<div id="snapshotLog">'+snapshotHtml+'</div>' +
      '</div>' +
    '</div>' +
  '</div>' +
'</div>' +

'<div class="foot"><a href="/">Nova analise</a></div>' +

'<script>' +
'var SID="'+sessionId+'";' +
'var INTERVAL=5*60*1000;' +
'var next=Date.now()+INTERVAL;' +
'var busy=false;' +
'var initChanges='+initialChangesJson+';' +
'if(initChanges&&initChanges.length>0){setTimeout(function(){initChanges.forEach(showToast);},600);}' +

// Countdown
'setInterval(function(){' +
'  if(busy)return;' +
'  var r=Math.max(0,next-Date.now());' +
'  var m=Math.floor(r/60000),s=Math.floor((r%60000)/1000);' +
'  document.getElementById("timer").textContent=m+":"+(s<10?"0":"")+s;' +
'  if(r<=0)doRefresh();' +
'},1000);' +

'function forceRefresh(){next=Date.now();}' +

'function doRefresh(){' +
'  if(busy)return;busy=true;next=Date.now()+INTERVAL;' +
'  var ri=document.getElementById("ri");ri.classList.add("refresh-spin");' +
'  document.getElementById("cd").innerHTML="Atualizando...";' +
'  fetch("/refresh/"+SID).then(function(r){return r.json();})' +
'  .then(function(data){' +
'    if(data.error){showToast({severity:"critico",message:"Erro: "+data.error});return;}' +

    // Atualiza stats
'    var ta=data.apps.length;' +
'    var tr=data.apps.filter(function(a){return a.appRoles&&a.appRoles.length>0;}).length;' +
'    var tn=data.apps.filter(function(a){return !a._owners||a._owners.length===0;}).length;' +
'    var tc=data.apps.filter(function(a){return a.createdDateTime&&(Date.now()-new Date(a.createdDateTime).getTime())/86400000<=30;}).length;' +
'    upd("stTotal",ta);upd("stRisky",tr);upd("stNoOwner",tn);upd("stRecent",tc);' +

    // Atualiza painel de mudancas
'    var riskColor={critico:"#ef4444",alto:"#f59e0b",normal:"#22c55e"};' +
'    var panel=document.getElementById("changesPanel");' +
'    if(data.changes&&data.changes.length>0){' +
'      panel.innerHTML=data.changes.map(function(c){' +
'        var icon=c.severity==="critico"?"🚨":c.severity==="aviso"?"⚠️":c.type==="removido"?"🗑️":c.type==="novo"?"✨":"✅";' +
'        var color=c.severity==="critico"?"#ef4444":c.severity==="aviso"?"#f59e0b":c.severity==="melhora"?"#22c55e":"#60a5fa";' +
'        var pd="";' +
'        if(c.permChanges&&c.permChanges.length>0){' +
'          pd=\'<div class="perm-changes">\'+c.permChanges.map(function(pc){' +
'            var pcc=pc.action==="adicionada"?(pc.severity==="critico"?"#ef4444":"#f59e0b"):"#22c55e";' +
'            return\'<span class="pc" style="color:\'+pcc+\'">\'+( pc.action==="adicionada"?"+":"-")+\' [\'+pc.type+\'] \'+pc.name+"</span>";' +
'          }).join("")+"</div>";' +
'        }' +
'        return\'<div class="change-item" style="border-left-color:\'+color+\'">\'+' +
'          \'<div class="change-top"><span class="change-icon">\'+icon+\'</span><span class="change-msg">\'+c.message+\'</span><span class="change-time">\'+new Date().toLocaleTimeString("pt-BR")+\'</span></div>\'+' +
'          pd+"</div>";' +
'      }).join("");' +
'      data.changes.forEach(showToast);' +
'    } else {' +
'      panel.innerHTML=\'<div class="no-changes">Nenhuma mudanca detectada</div>\';' +
'    }' +

    // Atualiza historico
'    if(data.snapshots){' +
'      document.getElementById("snapshotLog").innerHTML=data.snapshots.slice(-15).reverse().map(function(s){' +
'        return\'<div class="snap"><span class="snap-time">\'+new Date(s.timestamp).toLocaleTimeString("pt-BR")+\'</span><span class="snap-count">\'+s.count+\' apps</span></div>\';' +
'      }).join("");' +
'    }' +

'    document.getElementById("upd").textContent=new Date().toLocaleTimeString("pt-BR");' +
'  })' +
'  .catch(function(e){showToast({severity:"critico",message:"Falha: "+e.message});})' +
'  .finally(function(){' +
'    busy=false;ri.classList.remove("refresh-spin");' +
'    document.getElementById("cd").innerHTML=\'Prox. atualizacao: <strong id="timer">5:00</strong>\';' +
'  });' +
'}' +

'function upd(id,v){var el=document.getElementById(id);if(el&&el.textContent!=String(v)){el.textContent=v;el.classList.remove("changed");void el.offsetWidth;el.classList.add("changed");}}' +

'function toggle(id){var r=document.getElementById(id);r.style.display=r.style.display==="none"?"table-row":"none";}' +

'function filterTable(){' +
'  var q=document.getElementById("search").value.toLowerCase();' +
'  var rows=document.querySelectorAll("#appsBody tr.ar");' +
'  rows.forEach(function(row){' +
'    var text=row.textContent.toLowerCase();' +
'    var expand=document.getElementById(row.getAttribute("onclick").replace("toggle(\'","").replace("\')","")); ' +
'    var show=q===""||text.includes(q);' +
'    row.style.display=show?"":"none";' +
'    if(expand)expand.style.display="none";' +
'  });' +
'}' +

'function showToast(c){' +
'  var area=document.getElementById("toast-area");' +
'  var icons={critico:"🚨",aviso:"⚠️",melhora:"✅",info:"ℹ️"};' +
'  var t=document.createElement("div");' +
'  t.className="toast "+(c.severity||"info");' +
'  t.innerHTML=\'<span>\'+( icons[c.severity]||"ℹ️")+\'</span><span>\'+c.message+\'</span><span class="tc" onclick="this.parentElement.remove()">×</span>\';' +
'  area.appendChild(t);' +
'  setTimeout(function(){if(t.parentElement)t.remove();},10000);' +
'}' +
'</script></body></html>';
}

app.listen(3001, () => console.log("📦 App Monitor rodando em http://localhost:3001"));