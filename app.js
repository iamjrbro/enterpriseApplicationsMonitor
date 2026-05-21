require("dotenv").config();
const express = require("express");
const { ConfidentialClientApplication } = require("@azure/msal-node");
const axios = require("axios");

const app = express();
const REDIRECT_URI = process.env.REDIRECT_URI ||
  "https://enterprise-applications-monitor.onrender.com/callback";

const cca = new ConfidentialClientApplication({
  auth: {
    clientId: process.env.CLIENT_ID,
    authority: "https://login.microsoftonline.com/common",
    clientSecret: process.env.CLIENT_SECRET,
  },
});

const sessions = {};

const SCOPES = [
  "User.Read",
  "Directory.Read.All",
  "Application.Read.All",
  "AuditLog.Read.All",
];

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function safeJson(value) {
  return JSON.stringify(value).replace(/</g, "\\u003c");
}

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

async function getApps(token) {
  return graphPaged(
    "/applications?$select=displayName,appId,id,requiredResourceAccess,createdDateTime,signInAudience,notes,tags,passwordCredentials&$top=999",
    token, 10000
  );
}

async function getAppOwners(appObjectId, token) {
  try {
    var res = await graphGet("/applications/" + appObjectId + "/owners?$select=displayName,userPrincipalName,mail", token);
    return res.value || [];
  } catch (e) { return []; }
}

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

async function getLastSignIn(appId, token) {
  try {
    const safeId = appId.replace(/'/g, "''");
    const base = "https://graph.microsoft.com/beta/auditLogs/signIns";
    const userUrl = base + "?$filter=appId eq '" + safeId + "'&$orderby=createdDateTime desc&$top=1&$select=createdDateTime,userDisplayName,userPrincipalName,ipAddress,clientAppUsed,resourceDisplayName,location,signInEventTypes";
    const spUrl = base + "?$filter=appId eq '" + safeId + "' and signInEventTypes/any(t: t eq 'servicePrincipal')&$orderby=createdDateTime desc&$top=1&$select=createdDateTime,servicePrincipalName,servicePrincipalId,ipAddress,resourceDisplayName,signInEventTypes";
    const results = await Promise.allSettled([
      axios.get(userUrl, { headers: { Authorization: "Bearer " + token } }),
      axios.get(spUrl, { headers: { Authorization: "Bearer " + token } }),
    ]);
    const signIns = [];
    results.forEach(function(r) {
      if (r.status === "fulfilled" && r.value.data.value) signIns.push.apply(signIns, r.value.data.value);
    });
    signIns.sort(function(a, b) { return new Date(b.createdDateTime) - new Date(a.createdDateTime); });
    return signIns.length > 0 ? signIns.slice(0, 3) : null;
  } catch (e) { return null; }
}

async function getServicePrincipalByAppId(appId, token) {
  try {
    const safeId = appId.replace(/'/g, "''");
    const res = await graphGet("/servicePrincipals?$filter=appId eq '" + safeId + "'&$select=displayName,appId,id,servicePrincipalType,accountEnabled,publisherName,homepage,replyUrls", token);
    return res.value && res.value.length > 0 ? res.value[0] : null;
  } catch (e) { return null; }
}

function resolveActor(log) {
  var ib = log.initiatedBy;
  if (!ib) return null;
  if (ib.user) {
    var u = ib.user;
    var name = u.displayName || u.userPrincipalName || null;
    if (!name && u.id) name = "Usuario (" + u.id.substring(0, 8) + "...)";
    return name || "Usuario desconhecido";
  }
  if (ib.app) return "__SYSTEM__:" + (ib.app.displayName || ib.app.appId || "Sistema");
  return "__SYSTEM__:Azure AD";
}

function isHumanActor(actor) { return actor && !actor.startsWith("__SYSTEM__:"); }
function formatActor(actor) {
  if (!actor) return null;
  if (actor.startsWith("__SYSTEM__:")) return null;
  return actor;
}

function analyzeWritePermissions(app) {
  const allPerms = [].concat(app.appRoles || []).concat(app.delegated || []);
  return allPerms.filter(function(p) {
    const n = (p.name || "").toLowerCase();
    return n.includes("write") || n.includes("readwrite") || n.includes("manage") || n.includes("send") || n.includes("full_access_as_app");
  });
}

function getWriteCategories(a) {
  const writePerms = a._writePermissions || [];
  const categories = [];
  function has(prefixes) {
    return writePerms.some(function(p) {
      const n = p.name || "";
      return prefixes.some(function(prefix) { return n.startsWith(prefix); });
    });
  }
  if (has(["Group."])) categories.push("groups");
  if (has(["User."])) categories.push("users");
  if (has(["Mail.", "MailboxSettings."])) categories.push("email");
  if (has(["Files.", "Sites."])) categories.push("files");
  if (has(["Directory.", "RoleManagement."])) categories.push("directory");
  if (has(["Application."])) categories.push("apps");
  return categories;
}

function buildUsageAnalysis(app) {
  const allPerms = [].concat(app.appRoles || []).concat(app.delegated || []);
  const workloads = [];
  function has(prefix) { return allPerms.some(function(p) { return (p.name || "").startsWith(prefix); }); }
  if (has("Mail.") || has("MailboxSettings.")) workloads.push("Exchange Online / E-mail");
  if (has("Files.") || has("Sites.") || has("SharePoint.")) workloads.push("SharePoint / OneDrive");
  if (has("Chat.") || has("Team.") || has("Channel.")) workloads.push("Microsoft Teams");
  if (has("Device.") || has("DeviceManagement")) workloads.push("Intune / Device Management");
  if (has("Directory.") || has("User.") || has("Group.")) workloads.push("Entra ID / Diretorio");
  if (has("Calendars.")) workloads.push("Calendario");
  if (has("Tasks.") || has("Planner.")) workloads.push("Planner / Tasks");
  if (has("AuditLog.") || has("SecurityEvents.") || has("IdentityRisk")) workloads.push("Seguranca / Auditoria");
  if (has("Reports.")) workloads.push("Relatorios M365");
  if (has("RoleManagement.")) workloads.push("Gerenciamento de Roles");
  return { workloads };
}

function calculateRisk(app) {
  const perms = analyzeWritePermissions(app);
  const criticalPerms = ["Directory.ReadWrite.All","RoleManagement.ReadWrite.Directory","Application.ReadWrite.All","full_access_as_app","Mail.ReadWrite","Files.ReadWrite.All","Group.ReadWrite.All","User.ReadWrite.All"];
  let score = 0;
  perms.forEach(function(p) {
    if (criticalPerms.some(function(c) { return (p.name || "").includes(c); })) score += 40;
    else score += 10;
  });
  if (app._lastSignIn) score += 10;
  if (!app._owners || app._owners.length === 0) score += 20;
  if (score >= 80) return "Critical";
  if (score >= 50) return "High";
  if (score >= 25) return "Medium";
  return "Low";
}

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

  var spMap = {};
  for (var sp of allSPs.value) spMap[sp.appId] = sp;
  for (var sp of [...msGraphSPs, ...exchangeSPs]) spMap[sp.appId] = sp;

  var auditMap = {};
  function addToMap(key, entry) {
    if (!key) return;
    if (!auditMap[key]) auditMap[key] = [];
    auditMap[key].push(entry);
  }

  for (var log of auditLogs) {
    var actor = resolveActor(log);
    for (var target of (log.targetResources || [])) {
      var entry = { action: log.activityDisplayName, timestamp: log.activityDateTime, actor: actor, isHuman: isHumanActor(actor), result: log.result, targetName: target.displayName, modifiedProps: target.modifiedProperties || [] };
      addToMap(target.id, entry);
      if (target.displayName) addToMap(target.displayName, entry);
      if (target.modifiedProperties) {
        for (var prop of target.modifiedProperties) {
          if (prop.displayName === "AppId" && prop.newValue) addToMap(prop.newValue.replace(/"/g, "").trim(), entry);
        }
      }
    }
  }

  var apps = appsData.value;
  var chunkSize = 10;
  var appsEnriched = [];

  for (var i = 0; i < apps.length; i += chunkSize) {
    var chunk = apps.slice(i, i + chunkSize);
    var [ownersChunk, signInsChunk, spChunk] = await Promise.all([
      Promise.all(chunk.map(function(a) { return getAppOwners(a.id, token); })),
      Promise.all(chunk.map(function(a) { return getLastSignIn(a.appId, token); })),
      Promise.all(chunk.map(function(a) { return getServicePrincipalByAppId(a.appId, token); })),
    ]);

    for (var j = 0; j < chunk.length; j++) {
      chunk[j]._owners = ownersChunk[j];
      chunk[j]._lastSignIn = signInsChunk[j];
      chunk[j]._servicePrincipal = spChunk[j];

      var appLogs = [].concat(auditMap[chunk[j].id] || []).concat(auditMap[chunk[j].appId] || []).concat(auditMap[chunk[j].displayName] || []);
      var seen = {};
      appLogs = appLogs.filter(function(l) { var key = l.timestamp + l.action; if (seen[key]) return false; seen[key] = true; return true; });
      appLogs.sort(function(a, b) { return new Date(b.timestamp) - new Date(a.timestamp); });
      chunk[j]._auditLogs = appLogs;

      var createActions = ["add application", "add service principal"];
      var createLog = appLogs.find(function(l) { return l.isHuman && l.action && createActions.some(function(a) { return l.action.toLowerCase().includes(a); }); });
      if (!createLog) createLog = appLogs.find(function(l) { return l.action && createActions.some(function(a) { return l.action.toLowerCase().includes(a); }); });
      if (!createLog) {
        var humanLogs = appLogs.filter(function(l) { return l.isHuman; });
        if (humanLogs.length > 0) createLog = humanLogs.slice().sort(function(a, b) { return new Date(a.timestamp) - new Date(b.timestamp); })[0];
      }

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

  var result = appsEnriched.map(function(application) {
    var appRoles = [], delegated = [];
    if (application.requiredResourceAccess) {
      for (var resource of application.requiredResourceAccess) {
        var resourceSp = spMap[resource.resourceAppId];
        for (var access of resource.resourceAccess) {
          if (access.type === "Role") {
            var roleDef = resourceSp && resourceSp.appRoles ? resourceSp.appRoles.find(function(r) { return r.id === access.id; }) : null;
            appRoles.push({ id: access.id, name: roleDef ? roleDef.value : null, description: roleDef ? roleDef.displayName : null, resource: resourceSp ? resourceSp.displayName : resource.resourceAppId });
          } else {
            var scopeDef = resourceSp && resourceSp.oauth2PermissionScopes ? resourceSp.oauth2PermissionScopes.find(function(s) { return s.id === access.id; }) : null;
            delegated.push({ id: access.id, name: scopeDef ? scopeDef.value : null, description: scopeDef ? scopeDef.adminConsentDisplayName : null, resource: resourceSp ? resourceSp.displayName : resource.resourceAppId });
          }
        }
      }
    }

    var secrets = (application.passwordCredentials || []).map(function(cred) {
      var now = Date.now();
      var expDate = cred.endDateTime ? new Date(cred.endDateTime) : null;
      var daysToExp = expDate ? Math.ceil((expDate.getTime() - now) / 86400000) : null;
      var status = !expDate ? "sem-expiracao" : daysToExp < 0 ? "expirada" : daysToExp <= 30 ? "expirando" : "ativa";
      return { hint: cred.hint || "***", displayName: cred.displayName || "Secret", startDate: cred.startDateTime, endDate: cred.endDateTime, daysToExp, status };
    });

    var appObject = Object.assign({}, application, { appRoles, delegated, secrets });
    appObject._writePermissions = analyzeWritePermissions(appObject);
    appObject._usageAnalysis = buildUsageAnalysis(appObject);
    appObject._riskLevel = calculateRisk(appObject);
    return appObject;
  });

  return result;
}

// ─── Detecta mudancas ─────────────────────────────────────────────────────────
function detectChanges(prevApps, currApps) {
  var changes = [], prevMap = {}, currMap = {};
  for (var a of prevApps) prevMap[a.appId] = a;
  for (var a of currApps) currMap[a.appId] = a;

  for (var appId in currMap) {
    if (!prevMap[appId]) {
      var a = currMap[appId];
      changes.push({ type: "novo", severity: "aviso", appId, appName: a.displayName || appId, message: "Nova aplicacao: " + (a.displayName || appId) + (a._createdBy ? " por " + a._createdBy : ""), permChanges: [] });
    }
  }
  for (var appId in prevMap) {
    if (!currMap[appId]) changes.push({ type: "removido", severity: "info", appId, appName: prevMap[appId].displayName || appId, message: "Aplicacao removida: " + (prevMap[appId].displayName || appId), permChanges: [] });
  }
  for (var appId in currMap) {
    if (!prevMap[appId]) continue;
    var prev = prevMap[appId], curr = currMap[appId], permChanges = [];

    var prevRoles = (prev.appRoles || []).map(function(r) { return r.id; });
    var currRoles = (curr.appRoles || []).map(function(r) { return r.id; });
    for (var id of currRoles.filter(function(id) { return !prevRoles.includes(id); })) { var p = (curr.appRoles || []).find(function(r) { return r.id === id; }); permChanges.push({ action: "adicionada", type: "APP", name: p ? (p.name || id) : id, severity: "critico" }); }
    for (var id of prevRoles.filter(function(id) { return !currRoles.includes(id); })) { var p = (prev.appRoles || []).find(function(r) { return r.id === id; }); permChanges.push({ action: "removida", type: "APP", name: p ? (p.name || id) : id, severity: "melhora" }); }

    var prevDel = (prev.delegated || []).map(function(r) { return r.id; });
    var currDel = (curr.delegated || []).map(function(r) { return r.id; });
    for (var id of currDel.filter(function(id) { return !prevDel.includes(id); })) { var p = (curr.delegated || []).find(function(r) { return r.id === id; }); permChanges.push({ action: "adicionada", type: "DEL", name: p ? (p.name || id) : id, severity: "aviso" }); }
    for (var id of prevDel.filter(function(id) { return !currDel.includes(id); })) { var p = (prev.delegated || []).find(function(r) { return r.id === id; }); permChanges.push({ action: "removida", type: "DEL", name: p ? (p.name || id) : id, severity: "melhora" }); }

    var prevSecrets = (prev.secrets || []).length, currSecrets = (curr.secrets || []).length;
    if (currSecrets > prevSecrets) permChanges.push({ action: "adicionada", type: "SECRET", name: "Nova secret", severity: "aviso" });
    if (currSecrets < prevSecrets) permChanges.push({ action: "removida", type: "SECRET", name: "Secret removida", severity: "info" });

    if (permChanges.length > 0) {
      var worst = permChanges.some(function(c) { return c.severity === "critico"; }) ? "critico" : permChanges.some(function(c) { return c.severity === "aviso"; }) ? "aviso" : "melhora";
      var recentLog = (curr._auditLogs || []).filter(function(l) { return (Date.now() - new Date(l.timestamp).getTime()) < 3600000; }).sort(function(a, b) { return new Date(b.timestamp) - new Date(a.timestamp); })[0];
      changes.push({ type: "permissao", severity: worst, appId, appName: curr.displayName || appId, message: (curr.displayName || appId) + ": " + permChanges.length + " alteracao(es)" + (recentLog && recentLog.isHuman ? " por " + recentLog.actor : ""), permChanges });
    }
  }
  return changes;
}

function classifyPerm(name) {
  if (!name) return "normal";
  var critical = ["Mail.ReadWrite","Mail.Send","Files.ReadWrite.All","Directory.ReadWrite.All","User.ReadWrite.All","RoleManagement.ReadWrite.Directory","Application.ReadWrite.All","Group.ReadWrite.All","full_access_as_app"];
  var high = ["Mail.Read","Files.Read.All","User.Read.All","Directory.Read.All","AuditLog.Read.All","Policy.Read.All","IdentityRiskyUser.Read.All"];
  if (critical.some(function(c) { return name.includes(c); })) return "critico";
  if (high.some(function(h) { return name.includes(h); })) return "alto";
  return "normal";
}

function permLabel(p) { return p.name || "[" + p.id.substring(0, 8) + "...]"; }
function fmtDate(d) { if (!d) return ""; return new Date(d).toLocaleString("pt-BR"); }
function fmtDateOnly(d) { if (!d) return ""; return new Date(d).toLocaleDateString("pt-BR"); }

function fmtLastUsed(signIns) {
  if (!signIns || signIns.length === 0) return { text: "Nunca", color: "#3a5068", full: "Nenhum sign-in detectado" };
  var last = signIns[0];
  var days = Math.floor((Date.now() - new Date(last.createdDateTime).getTime()) / 86400000);
  var color = days > 90 ? "#ef4444" : days > 30 ? "#f59e0b" : "#4ade80";
  var text = days === 0 ? "Hoje" : days === 1 ? "Ontem" : days + "d atras";
  return { text, color, full: fmtDate(last.createdDateTime) };
}

// ─── Rotas ────────────────────────────────────────────────────────────────────
app.get("/", async (req, res) => {
  const authUrl = await cca.getAuthCodeUrl({ scopes: SCOPES, redirectUri: REDIRECT_URI, prompt: "select_account" });
  res.redirect(authUrl);
});

app.get("/callback", async (req, res) => {
  if (!req.query.code) return res.status(400).send("Codigo nao encontrado.");
  try {
    const tokenResponse = await cca.acquireTokenByCode({ code: req.query.code, scopes: SCOPES, redirectUri: REDIRECT_URI });
    const sessionId = Math.random().toString(36).slice(2);
    sessions[sessionId] = { token: tokenResponse.accessToken, tenantId: tokenResponse.tenantId, lastApps: null, changesLast24h: [], snapshots: [], lastUpdated: null };
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
  function send(d) { res.write("data: " + JSON.stringify(d) + "\n\n"); }
  runCollection(sessionId, send).then(function() { send({ type: "done" }); res.end(); }).catch(function(err) { send({ type: "error", message: err.message }); res.end(); });
});

async function runCollection(sessionId, send) {
  var session = sessions[sessionId];
  send({ type: "step", status: "running", label: "Conectando ao tenant..." });
  await sleep(200);
  send({ type: "step", status: "done", label: "Conectado: " + session.tenantId });
  send({ type: "step", status: "running", label: "Buscando aplicacoes, sign-ins e audit logs..." });
  var apps = await collectApps(session.token);
  send({ type: "step", status: "done", label: apps.length + " aplicacoes coletadas" });
  send({ type: "step", status: "running", label: "Analisando permissoes, secrets e riscos..." });
  await sleep(200);
  var totalPerms = apps.reduce(function(acc, a) { return acc + (a.appRoles || []).length + (a.delegated || []).length; }, 0);
  var totalSecrets = apps.reduce(function(acc, a) { return acc + (a.secrets || []).length; }, 0);
  var writeApps = apps.filter(function(a) { return a._writePermissions && a._writePermissions.length > 0; }).length;
  send({ type: "step", status: "done", label: totalPerms + " permissoes | " + totalSecrets + " secrets | " + writeApps + " com Write" });
  send({ type: "step", status: "running", label: "Detectando mudancas..." });
  var newChanges = session.lastApps ? detectChanges(session.lastApps, apps) : [];
  var now = Date.now();
  var stamped = newChanges.map(function(c) { return Object.assign({}, c, { detectedAt: new Date().toISOString() }); });
  session.changesLast24h = session.changesLast24h.filter(function(c) { return (now - new Date(c.detectedAt).getTime()) < 24 * 60 * 60 * 1000; }).concat(stamped);
  send({ type: "step", status: "done", label: newChanges.length + " mudanca(s) | " + session.changesLast24h.length + " nas ultimas 24h" });
  session.snapshots.push({ timestamp: new Date().toISOString(), count: apps.length });
  if (session.snapshots.length > 50) session.snapshots.shift();
  session.lastApps = apps;
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
    var newChanges = session.lastApps ? detectChanges(session.lastApps, apps) : [];
    var now = Date.now();
    var stamped = newChanges.map(function(c) { return Object.assign({}, c, { detectedAt: new Date().toISOString() }); });
    session.changesLast24h = session.changesLast24h.filter(function(c) { return (now - new Date(c.detectedAt).getTime()) < 24 * 60 * 60 * 1000; }).concat(stamped);
    session.snapshots.push({ timestamp: new Date().toISOString(), count: apps.length });
    if (session.snapshots.length > 50) session.snapshots.shift();
    session.lastApps = apps;
    session.lastUpdated = new Date();
    res.json({ apps, changesLast24h: session.changesLast24h, newChanges, snapshots: session.snapshots, updatedAt: session.lastUpdated });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get("/dashboard/:sessionId", function(req, res) {
  var session = sessions[req.params.sessionId];
  if (!session || !session.lastApps) return res.status(404).send("Dashboard nao encontrado.");
  res.send(buildDashboard(session, req.params.sessionId));
});

// ─── Loading Page ─────────────────────────────────────────────────────────────
function buildLoadingPage(sessionId, tenantId) {
  return '<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><title>Carregando...</title>' +
    '<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:"SF Mono",Monaco,monospace;background:#060a0f;color:#c8d8e8;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}.card{background:#0d1520;border:1px solid #1a2840;border-radius:16px;padding:48px 40px;max-width:580px;width:100%}h1{font-size:18px;color:#4fc3f7;margin-bottom:4px;letter-spacing:2px;text-transform:uppercase}.tid{font-size:11px;color:#3a5068;margin-bottom:32px}.bar-wrap{height:2px;background:#0a1525;border-radius:2px;margin-bottom:32px}.bar{height:100%;background:linear-gradient(90deg,#0ea5e9,#38bdf8,#7dd3fc);border-radius:2px;width:0%;transition:width .8s}.steps{display:flex;flex-direction:column;gap:6px}.step{display:flex;align-items:center;gap:10px;padding:10px 14px;border-radius:8px;background:#060d16;font-size:12px;color:#3a5068;border:1px solid transparent;transition:all .4s}.step.running{background:#061828;border-color:#0ea5e9;color:#7dd3fc}.step.done{background:#061a10;border-color:#22c55e40;color:#4ade80}.step.error{background:#1a0606;border-color:#ef444440;color:#f87171}.icon{width:16px;height:16px;display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:11px}.spinner{width:12px;height:12px;border:1.5px solid #1a3050;border-top-color:#0ea5e9;border-radius:50%;animation:spin .7s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}.reveal{text-align:center;margin-top:36px;display:none}.big{font-size:64px;font-weight:700;color:#0ea5e9;letter-spacing:-2px}.sub{font-size:12px;color:#3a5068;margin-top:4px;letter-spacing:2px;text-transform:uppercase}.btn{display:inline-block;margin-top:24px;padding:12px 32px;background:linear-gradient(135deg,#0369a1,#0ea5e9);color:#fff;border-radius:8px;text-decoration:none;font-weight:600;font-size:13px;text-transform:uppercase}</style></head><body>' +
    '<div class="card"><h1>ENTERPRISE APPLICATIONS MONITOR</h1><div class="tid">' + tenantId + '</div><div class="bar-wrap"><div class="bar" id="bar"></div></div><div class="steps" id="steps"></div><div class="reveal" id="reveal"><div class="big">&#10003;</div><div class="sub">analise concluida</div><a class="btn" id="btn" href="#">ABRIR MONITOR</a></div></div>' +
    '<script>var total=5,done=0,active=null;var stepsEl=document.getElementById("steps"),bar=document.getElementById("bar");var es=new EventSource("/progress/' + sessionId + '");es.onmessage=function(e){var d=JSON.parse(e.data);if(d.type==="step"){if(d.status==="running"){if(active){active.className="step done";active.querySelector(".icon").innerHTML="&#10003;";done++;bar.style.width=Math.min(92,Math.round(done/total*100))+"%";}var el=document.createElement("div");el.className="step running";el.innerHTML="<div class=\'icon\'><div class=\'spinner\'></div></div><span>"+d.label+"</span>";stepsEl.appendChild(el);el.scrollIntoView({behavior:"smooth"});active=el;}else if(d.status==="done"&&active){active.querySelector("span").textContent=d.label;}}if(d.type==="done"){if(active){active.className="step done";active.querySelector(".icon").innerHTML="&#10003;";}bar.style.width="100%";es.close();document.getElementById("btn").href="/dashboard/' + sessionId + '";document.getElementById("reveal").style.display="block";}if(d.type==="error"){if(active){active.className="step error";active.querySelector(".icon").innerHTML="&#10007;";}var err=document.createElement("div");err.className="step error";err.innerHTML="<div class=\'icon\'>&#10007;</div><span>Erro: "+d.message+"</span>";stepsEl.appendChild(err);es.close();}};' +
    '</script></body></html>';
}

// ─── Dashboard ────────────────────────────────────────────────────────────────
function buildDashboard(session, sessionId) {
  var apps = session.lastApps;
  var changes24h = session.changesLast24h || [];
  var riskColor = { critico: "#ef4444", alto: "#f59e0b", normal: "#4ade80" };

  var allApps         = apps;
  var riskyApps       = apps.filter(function(a) { return a.appRoles && a.appRoles.length > 0; });
  var writeApps       = apps.filter(function(a) { return a._writePermissions && a._writePermissions.length > 0; });
  var writeGroupsApps = apps.filter(function(a) { return getWriteCategories(a).includes("groups"); });
  var writeUsersApps  = apps.filter(function(a) { return getWriteCategories(a).includes("users"); });
  var writeEmailApps  = apps.filter(function(a) { return getWriteCategories(a).includes("email"); });
  var writeFilesApps  = apps.filter(function(a) { return getWriteCategories(a).includes("files"); });
  var recentApps      = apps.filter(function(a) { return a.createdDateTime && (Date.now() - new Date(a.createdDateTime).getTime()) / 86400000 <= 30; });
  var noOwnerApps     = apps.filter(function(a) { return !a._owners || a._owners.length === 0; });
  var appsWithSecrets = apps.filter(function(a) { return a.secrets && a.secrets.length > 0; });
  var expSecrets      = apps.filter(function(a) { return (a.secrets || []).some(function(s) { return s.status === "expirada" || s.status === "expirando"; }); });
  var criticalApps    = apps.filter(function(a) { return a._riskLevel === "Critical"; });

  // Serializa todos os grupos de apps como JSON para uso no cliente
  var appDatasets = {
    all:         allApps,
    risky:       riskyApps,
    write:       writeApps,
    writegroups: writeGroupsApps,
    writeusers:  writeUsersApps,
    writeemail:  writeEmailApps,
    writefiles:  writeFilesApps,
    critical:    criticalApps,
    recent:      recentApps,
    noowner:     noOwnerApps,
    secrets:     appsWithSecrets,
    expsecrets:  expSecrets,
  };

  // Tooltips
  var RISK_TOOLTIPS = {
    "Mail.ReadWrite":"CRITICO — Le e modifica todos os e-mails da org.","Mail.Send":"CRITICO — Envia e-mails como qualquer usuario.","Files.ReadWrite.All":"CRITICO — Le e escreve em todos os arquivos SharePoint/OneDrive.","Directory.ReadWrite.All":"CRITICO — Le e modifica todo o diretorio Azure AD.","User.ReadWrite.All":"CRITICO — Cria, edita e deleta qualquer usuario.","RoleManagement.ReadWrite.Directory":"CRITICO — Atribui e remove roles de administrador.","Application.ReadWrite.All":"CRITICO — Cria e modifica qualquer aplicacao, incluindo secrets.","Group.ReadWrite.All":"CRITICO — Cria e modifica todos os grupos.","full_access_as_app":"CRITICO — Acesso total ao Exchange Online como aplicacao.","Mail.Read":"ALTO — Le todos os e-mails de todos os usuarios.","Files.Read.All":"ALTO — Le todos os arquivos de todos os usuarios.","User.Read.All":"ALTO — Le dados de todos os usuarios.","Directory.Read.All":"ALTO — Le todo o diretorio AD.","AuditLog.Read.All":"ALTO — Acessa os logs de auditoria do tenant.","Policy.Read.All":"ALTO — Le todas as politicas de seguranca.","IdentityRiskyUser.Read.All":"ALTO — Le dados de usuarios sinalizados como risco.","User.Read":"NORMAL — Le apenas o perfil do usuario que autorizou.","openid":"NORMAL — Permite login com conta Microsoft.","profile":"NORMAL — Le nome, foto e info basica do usuario logado.","email":"NORMAL — Le o e-mail do usuario logado.","offline_access":"NORMAL — Permite funcionar em segundo plano.","Calendars.Read":"NORMAL — Le eventos de calendario do usuario logado.","Calendars.ReadWrite":"MEDIO — Le e cria eventos no calendario.","Tasks.ReadWrite":"NORMAL — Le e cria tarefas no Planner/To Do.",
  };

  function getPermTooltip(name, description, risk) {
    if (!name) return description || "Permissao nao identificada";
    for (var key in RISK_TOOLTIPS) { if (name === key || name.startsWith(key)) return RISK_TOOLTIPS[key]; }
    return (risk === "critico" ? "CRITICO" : risk === "alto" ? "ALTO" : "NORMAL") + " — " + (description || name);
  }

  function getSuggestions(a) {
    var name = (a.displayName || "").toLowerCase();
    var currentNames = (a.appRoles || []).concat(a.delegated || []).map(function(p) { return p.name || ""; });
    var suggestions = { add: [], remove: [] };
    ["Directory.ReadWrite.All","User.ReadWrite.All","RoleManagement.ReadWrite.Directory","Application.ReadWrite.All","full_access_as_app"].forEach(function(perm) {
      if (currentNames.some(function(n) { return n === perm; })) suggestions.remove.push({ name: perm, reason: "Permissao de escrita critica. Considere substituir pela versao Read-only." });
    });
    if ((name.includes("mail")||name.includes("email")||name.includes("outlook"))&&!currentNames.includes("Mail.Read")) suggestions.add.push({ name:"Mail.Read", reason:"Apps de e-mail geralmente precisam ler mensagens." });
    if ((name.includes("mail")||name.includes("email"))&&currentNames.includes("Mail.ReadWrite")) suggestions.remove.push({ name:"Mail.ReadWrite", reason:"Use Mail.Read se o app apenas le e-mails." });
    if ((name.includes("user")||name.includes("people")||name.includes("directory"))&&!currentNames.includes("User.Read.All")) suggestions.add.push({ name:"User.Read.All", reason:"Apps de diretorio precisam desta permissao." });
    if ((name.includes("report")||name.includes("audit")||name.includes("monitor")||name.includes("security")||name.includes("scan"))&&!currentNames.includes("AuditLog.Read.All")) suggestions.add.push({ name:"AuditLog.Read.All", reason:"Apps de monitoramento precisam ler logs." });
    if ((name.includes("file")||name.includes("sharepoint")||name.includes("document"))&&!currentNames.includes("Files.Read.All")) suggestions.add.push({ name:"Files.Read.All", reason:"Apps de documentos precisam ler arquivos." });
    if ((name.includes("file")||name.includes("sharepoint"))&&currentNames.includes("Files.ReadWrite.All")) suggestions.remove.push({ name:"Files.ReadWrite.All", reason:"Use Files.Read.All se o app apenas le arquivos." });
    if (currentNames.filter(function(n) { return n; }).length === 0) suggestions.add.push({ name:"User.Read", reason:"A maioria dos apps precisa ao menos desta permissao." });
    return suggestions;
  }

  function buildAppRow(a, tabPrefix) {
    tabPrefix = tabPrefix || "all";
    var uid = (tabPrefix + "-" + a.appId).replace(/[^a-zA-Z0-9_-]/g, "_");
    var allPerms = (a.appRoles || []).concat(a.delegated || []);
    var isRisky = a.appRoles && a.appRoles.length > 0;
    var writePerms = a._writePermissions || [];
    var writeCategories = getWriteCategories(a);
    var owners = (a._owners || []).map(function(o) { return escapeHtml(o.displayName || o.userPrincipalName || o.mail || "?"); });
    var ownersStr = owners.length > 0 ? owners.join(", ") : '<span style="color:#ef4444">Sem owner</span>';
    var createdBy = a._createdBy ? escapeHtml(a._createdBy) : a._createdBySystem ? '<span style="color:#3a5068;font-size:10px">via ' + escapeHtml(a._createdBySystem) + '</span>' : '<span style="color:#2a4060;font-size:10px">Anterior a 30 dias</span>';
    var lastUsed = fmtLastUsed(a._lastSignIn);
    var lastUsedCell = '<span style="color:' + lastUsed.color + ';font-family:\'JetBrains Mono\',monospace;font-size:11px" title="' + escapeHtml(lastUsed.full) + '">' + lastUsed.text + '</span>';
    var riskBadgeColor = a._riskLevel === "Critical" ? "#ef4444" : a._riskLevel === "High" ? "#f59e0b" : a._riskLevel === "Medium" ? "#a78bfa" : "#4ade80";
    var notesHtml = a.notes ? '<div class="notes-box"><span class="notes-label">Notas:</span> ' + escapeHtml(a.notes) + '</div>' : "";

    var permsHtml = allPerms.length === 0 ? '<span style="color:#3a5068;font-size:11px">Nenhuma permissao registrada</span>'
      : allPerms.map(function(p) {
          var risk = classifyPerm(p.name);
          var isApp = !!(a.appRoles || []).find(function(r) { return r.id === p.id; });
          var label = escapeHtml(permLabel(p));
          var tooltip = escapeHtml(getPermTooltip(p.name, p.description, risk));
          var isWrite = !!(p.name || "").toLowerCase().match(/write|send|manage|full_access/);
          return '<div class="pb-wrap"><span class="pb" style="border-color:' + riskColor[risk] + ';color:' + riskColor[risk] + (isWrite ? ';font-weight:700' : '') + '"><span class="pt">' + (isApp ? "APP" : "DEL") + '</span> ' + label + (isWrite ? ' &#9999;' : '') + '</span><div class="pb-tooltip">' + tooltip + '</div></div>';
        }).join("");

    var sugg = getSuggestions(a);
    var suggHtml = sugg.add.length === 0 && sugg.remove.length === 0
      ? '<div class="sugg-ok">Permissoes parecem adequadas para este app.</div>'
      : (sugg.remove.length > 0 ? '<div class="sugg-section"><div class="sugg-title" style="color:#ef4444">Considere REMOVER:</div>' + sugg.remove.map(function(s) { return '<div class="sugg-item sugg-remove"><code>' + s.name + '</code><span>' + s.reason + '</span></div>'; }).join("") + '</div>' : "")
        + (sugg.add.length > 0 ? '<div class="sugg-section"><div class="sugg-title" style="color:#4ade80">Considere ADICIONAR:</div>' + sugg.add.map(function(s) { return '<div class="sugg-item sugg-add"><code>' + s.name + '</code><span>' + s.reason + '</span></div>'; }).join("") + '</div>' : "");

    var secretsHtml = (a.secrets && a.secrets.length > 0)
      ? '<div class="secrets-wrap">' + a.secrets.map(function(s) {
          var sc = s.status === "expirada" ? "#ef4444" : s.status === "expirando" ? "#f59e0b" : s.status === "sem-expiracao" ? "#94a3b8" : "#4ade80";
          var slabel = s.status === "expirada" ? "EXPIRADA" : s.status === "expirando" ? "EXPIRA EM " + s.daysToExp + "d" : s.status === "sem-expiracao" ? "SEM EXPIRACAO" : "ATIVA";
          return '<div class="secret-item"><span class="secret-name">&#128273; ' + escapeHtml(s.displayName) + ' (' + s.hint + '***)</span><span class="secret-dates">Criada: ' + fmtDateOnly(s.startDate) + ' Expira: ' + fmtDateOnly(s.endDate) + '</span><span class="secret-status" style="color:' + sc + '">' + slabel + '</span></div>';
        }).join("") + '</div>'
      : '<span style="color:#3a5068;font-size:12px">Nenhuma secret registrada</span>';

    var recentLogs = (a._auditLogs || []).slice(0, 5);
    var auditHtml = recentLogs.length > 0
      ? '<div class="audit-wrap"><div class="audit-title">Atividade recente (ultimos 30 dias):</div>' + recentLogs.map(function(l) {
          var actorDisplay = l.isHuman ? escapeHtml(l.actor) : (formatActor(l.actor) || "Sistema");
          var actorColor = l.isHuman ? "#38bdf8" : "#3a5068";
          return '<div class="audit-item"><span class="audit-action">' + escapeHtml(l.action) + '</span><span class="audit-actor" style="color:' + actorColor + '">por ' + actorDisplay + '</span><span class="audit-time">' + fmtDate(l.timestamp) + '</span></div>';
        }).join("") + '</div>'
      : '<span style="color:#3a5068;font-size:12px">Nenhuma atividade nos ultimos 30 dias</span>';

    var signIns = a._lastSignIn;
    var lastUsoHtml = "";
    if (signIns && signIns.length > 0) {
      var last = signIns[0];
      var daysAgo = Math.floor((Date.now() - new Date(last.createdDateTime).getTime()) / 86400000);
      var stColor = daysAgo > 90 ? "#ef4444" : daysAgo > 30 ? "#f59e0b" : "#4ade80";
      var stLabel = daysAgo === 0 ? "Hoje" : daysAgo === 1 ? "Ontem" : daysAgo + " dias atras";
      var isSP = !!(last.signInEventTypes && last.signInEventTypes.some(function(t) { return t === "servicePrincipal"; }));
      lastUsoHtml = '<div class="audit-wrap"><div class="audit-item"><span class="audit-action" style="color:#c8d8e8;font-weight:600">Ultimo uso detectado</span><span style="color:' + stColor + ';font-family:\'JetBrains Mono\',monospace;font-size:11px">' + stLabel + '</span></div><div class="audit-item"><span class="audit-action">Data e hora exata</span><span class="audit-time">' + fmtDate(last.createdDateTime) + '</span></div><div class="audit-item"><span class="audit-action">Tipo de acesso</span><span style="color:#a78bfa;font-size:11px">' + (isSP ? "Service Principal (automacao)" : "Sign-in de usuario") + '</span></div>' + (last.userDisplayName || last.userPrincipalName ? '<div class="audit-item"><span class="audit-action">Usuario</span><span style="color:#38bdf8;font-size:11px">' + escapeHtml(last.userDisplayName || last.userPrincipalName) + '</span></div>' : '') + (last.servicePrincipalName ? '<div class="audit-item"><span class="audit-action">Service Principal</span><span style="color:#a78bfa;font-size:11px">' + escapeHtml(last.servicePrincipalName) + '</span></div>' : '') + '<div class="audit-item"><span class="audit-action">IP de origem</span><span style="color:#94a3b8;font-size:11px;font-family:monospace">' + escapeHtml(last.ipAddress || "N/A") + '</span></div>' + (last.clientAppUsed ? '<div class="audit-item"><span class="audit-action">Cliente usado</span><span style="color:#94a3b8;font-size:11px">' + escapeHtml(last.clientAppUsed) + '</span></div>' : '') + '<div class="audit-item"><span class="audit-action">Recurso acessado</span><span style="color:#94a3b8;font-size:11px">' + escapeHtml(last.resourceDisplayName || "N/A") + '</span></div>' + (last.location ? '<div class="audit-item"><span class="audit-action">Localizacao</span><span style="color:#94a3b8;font-size:11px">' + escapeHtml((last.location.city || "") + (last.location.countryOrRegion ? ", " + last.location.countryOrRegion : "")) + '</span></div>' : '') + (signIns.length > 1 ? '<div class="audit-title" style="margin-top:10px">Acessos anteriores:</div>' + signIns.slice(1).map(function(si) { var siSP = !!(si.signInEventTypes && si.signInEventTypes.some(function(t) { return t === "servicePrincipal"; })); return '<div class="audit-item"><span class="audit-action">' + fmtDate(si.createdDateTime) + '</span><span style="color:#3a5068;font-size:10px">' + (siSP ? "SP" : escapeHtml(si.userDisplayName || si.userPrincipalName || "—")) + ' | ' + escapeHtml(si.ipAddress || "—") + '</span></div>'; }).join("") : '') + '</div>';
    } else {
      lastUsoHtml = '<div class="audit-wrap"><div class="audit-item"><span class="audit-action">Nenhum sign-in encontrado</span><span style="color:#ef4444;font-size:11px">App possivelmente inativo</span></div><div style="font-size:11px;color:#3a5068;padding:8px;line-height:1.6">Sign-ins do tipo client_credentials nao aparecem nos logs padrao. Verifique Azure Monitor Workbooks.</div></div>';
    }

    var usage = a._usageAnalysis, sp = a._servicePrincipal;
    var writeCatLabels = { groups:"Grupos", users:"Usuarios", email:"E-mail", files:"Arquivos/SharePoint", directory:"Diretorio", apps:"Aplicacoes" };
    var usoHtml = '<div class="audit-wrap"><div class="audit-title">Onde este app e provavelmente usado:</div><div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:14px">' + (usage.workloads.length > 0 ? usage.workloads.map(function(w) { return '<span class="wb">' + escapeHtml(w) + '</span>'; }).join("") : '<span style="color:#3a5068">Nenhum workload identificado</span>') + '</div><div class="audit-title">Categorias com permissao de escrita:</div><div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:14px">' + (writeCategories.length > 0 ? writeCategories.map(function(c) { return '<span class="wc-badge">' + (writeCatLabels[c] || c) + '</span>'; }).join("") : '<span style="color:#4ade80;font-size:12px">Nenhuma escrita detectada</span>') + '</div><div class="audit-title">Permissoes de escrita detalhadas:</div>' + (writePerms.length > 0 ? writePerms.map(function(p) { var risk = classifyPerm(p.name); return '<div class="audit-item"><span class="audit-action" style="color:' + riskColor[risk] + ';font-weight:600">&#9999; ' + escapeHtml(permLabel(p)) + '</span><span style="color:#3a5068;font-size:10px">' + escapeHtml(p.resource || "") + '</span></div>'; }).join("") : '<div class="audit-item"><span style="color:#4ade80">Nenhuma permissao de escrita</span></div>') + (sp ? '<div class="audit-title" style="margin-top:12px">Service Principal:</div><div class="audit-item"><span class="audit-action">Tipo</span><span style="color:#94a3b8">' + escapeHtml(sp.servicePrincipalType || "N/A") + '</span></div><div class="audit-item"><span class="audit-action">Publisher</span><span style="color:#94a3b8">' + escapeHtml(sp.publisherName || "N/A") + '</span></div>' + (sp.homepage ? '<div class="audit-item"><span class="audit-action">Homepage</span><span style="color:#60a5fa;font-size:10px">' + escapeHtml(sp.homepage) + '</span></div>' : '') + (sp.replyUrls && sp.replyUrls.length > 0 ? '<div class="audit-item"><span class="audit-action">Reply URLs</span><div style="display:flex;flex-direction:column;gap:2px">' + sp.replyUrls.map(function(u) { return '<span style="color:#60a5fa;font-size:10px;font-family:monospace">' + escapeHtml(u) + '</span>'; }).join("") + '</div></div>' : '') : '') + '</div>';

    var riskLevelColor = a._riskLevel === "Critical" ? "#ef4444" : a._riskLevel === "High" ? "#f59e0b" : a._riskLevel === "Medium" ? "#a78bfa" : "#4ade80";
    var riscoHtml = '<div class="audit-wrap"><div class="audit-item"><span class="audit-action" style="color:#c8d8e8;font-weight:600">Classificacao</span><span style="color:' + riskLevelColor + ';font-family:\'JetBrains Mono\',monospace;font-weight:700;font-size:14px">' + a._riskLevel + '</span></div><div class="audit-item"><span class="audit-action">Permissoes de escrita</span><span style="color:' + (writePerms.length > 0 ? "#f59e0b" : "#4ade80") + '">' + writePerms.length + ' permissao(oes)</span></div><div class="audit-item"><span class="audit-action">Owner</span><span style="color:' + (owners.length === 0 ? "#ef4444" : "#4ade80") + '">' + (owners.length === 0 ? "Sem owner (+20pts risco)" : owners.length + " owner(s)") + '</span></div><div class="audit-item"><span class="audit-action">Ultimo uso</span><span style="color:' + lastUsed.color + '">' + lastUsed.text + (lastUsed.full !== "Nenhum sign-in detectado" ? " — " + lastUsed.full : "") + '</span></div>' + (writePerms.length > 0 ? '<div class="audit-title" style="margin-top:10px">Permissoes criticas:</div>' + writePerms.map(function(p) { var risk = classifyPerm(p.name); return '<div class="audit-item"><span style="color:' + riskColor[risk] + ';font-weight:600">' + escapeHtml(permLabel(p)) + '</span><span style="color:#3a5068;font-size:10px">' + escapeHtml(getPermTooltip(p.name, p.description, risk).substring(0, 70)) + '...</span></div>'; }).join("") : '<div class="audit-item"><span style="color:#4ade80">Nenhuma permissao critica</span></div>') + '</div>';

    return '<tr class="ar' + (isRisky ? " risky" : "") + '" onclick="toggle(\'rx-' + uid + '\')">' +
      '<td><div class="app-name">' + escapeHtml(a.displayName || "—") + (isRisky ? '<span class="risk-badge">App Perm</span>' : '') + (writePerms.length > 0 ? '<span class="write-badge">W</span>' : '') + (writeCategories.includes("groups") ? '<span class="wcat-badge">Groups</span>' : '') + (writeCategories.includes("users") ? '<span class="wcat-badge">Users</span>' : '') + (writeCategories.includes("email") ? '<span class="wcat-badge">Mail</span>' : '') + (writeCategories.includes("files") ? '<span class="wcat-badge">Files</span>' : '') + ((a.secrets && a.secrets.length > 0) ? '<span class="secret-badge">' + a.secrets.length + 's</span>' : '') + (a.notes ? '<span class="notes-badge">n</span>' : '') + '<span class="rl-badge" style="border-color:' + riskBadgeColor + ';color:' + riskBadgeColor + '">' + a._riskLevel + '</span></div></td>' +
      '<td>' + fmtDate(a.createdDateTime) + '</td>' +
      '<td>' + lastUsedCell + '</td>' +
      '<td>' + createdBy + '</td>' +
      '<td>' + ownersStr + '</td>' +
      '<td style="text-align:center"><span style="color:#f59e0b">' + (a.appRoles || []).length + '</span>/<span style="color:#60a5fa">' + (a.delegated || []).length + '</span></td>' +
      '</tr>' +
      '<tr id="rx-' + uid + '" style="display:none"><td colspan="6" class="expand-cell">' +
        notesHtml +
        '<div class="expand-tabs">' +
          '<div class="etab active" onclick="etab(this,\'epp-' + uid + '\')">Permissoes</div>' +
          '<div class="etab" onclick="etab(this,\'esg-' + uid + '\')">Sugestoes' + (sugg.add.length + sugg.remove.length > 0 ? ' <span class="sugg-count">' + (sugg.add.length + sugg.remove.length) + '</span>' : '') + '</div>' +
          '<div class="etab" onclick="etab(this,\'esr-' + uid + '\')">Secrets</div>' +
          '<div class="etab" onclick="etab(this,\'eat-' + uid + '\')">Atividade</div>' +
          '<div class="etab" onclick="etab(this,\'els-' + uid + '\')">Ultimo Uso</div>' +
          '<div class="etab" onclick="etab(this,\'eus-' + uid + '\')">Onde e Usado</div>' +
          '<div class="etab" onclick="etab(this,\'erk-' + uid + '\')" style="color:' + riskBadgeColor + ';border-color:' + riskBadgeColor + '40">Risco (' + a._riskLevel + ')</div>' +
        '</div>' +
        '<div id="epp-' + uid + '" class="epanel active"><div class="perm-wrap">' + permsHtml + '</div></div>' +
        '<div id="esg-' + uid + '" class="epanel" style="display:none"><div class="sugg-wrap">' + suggHtml + '</div></div>' +
        '<div id="esr-' + uid + '" class="epanel" style="display:none">' + secretsHtml + '</div>' +
        '<div id="eat-' + uid + '" class="epanel" style="display:none">' + auditHtml + '</div>' +
        '<div id="els-' + uid + '" class="epanel" style="display:none">' + lastUsoHtml + '</div>' +
        '<div id="eus-' + uid + '" class="epanel" style="display:none">' + usoHtml + '</div>' +
        '<div id="erk-' + uid + '" class="epanel" style="display:none">' + riscoHtml + '</div>' +
      '</td></tr>';
  }

  function buildTabTable(list, emptyMsg, tabPrefix) {
    if (list.length === 0) return '<div class="empty-tab">' + emptyMsg + '</div>';
    return '<table><thead><tr><th>Nome</th><th>Criado em</th><th>Ultimo Uso</th><th>Criado por</th><th>Owner(s)</th><th>Perms</th></tr></thead><tbody>' +
      list.map(function(a) { return buildAppRow(a, tabPrefix || "all"); }).join("") + '</tbody></table>';
  }

  var changesHtml = changes24h.length === 0
    ? '<div class="no-changes">Nenhuma mudanca nas ultimas 24 horas</div>'
    : changes24h.slice().reverse().map(function(c) {
        var icon = c.severity === "critico" ? "!!" : c.severity === "aviso" ? "!" : c.type === "removido" ? "-" : c.type === "novo" ? "+" : "ok";
        var color = c.severity === "critico" ? "#ef4444" : c.severity === "aviso" ? "#f59e0b" : c.severity === "melhora" ? "#4ade80" : "#60a5fa";
        var pd = "";
        if (c.permChanges && c.permChanges.length > 0) {
          pd = '<div class="perm-changes">' + c.permChanges.map(function(pc) { var pcc = pc.action === "adicionada" ? (pc.severity === "critico" ? "#ef4444" : "#f59e0b") : "#4ade80"; return '<span class="pc" style="color:' + pcc + '">' + (pc.action === "adicionada" ? "+" : "-") + ' [' + escapeHtml(pc.type) + '] ' + escapeHtml(pc.name) + '</span>'; }).join("") + '</div>';
        }
        return '<div class="change-item" style="border-left-color:' + color + '"><div class="change-top"><span style="color:' + color + ';font-weight:700;font-size:12px">[' + icon + ']</span><span class="change-msg">' + escapeHtml(c.message) + '</span><span class="change-time">' + fmtDate(c.detectedAt) + '</span></div>' + pd + '</div>';
      }).join("");

  var initChangesJson = safeJson(changes24h.filter(function(c) { return (Date.now() - new Date(c.detectedAt).getTime()) < 300000; }));

  var allSecretIssues = [];
  for (var a of apps) {
    for (var s of (a.secrets || [])) {
      if (s.status === "expirada" || s.status === "expirando") allSecretIssues.push({ appName: a.displayName, secret: s });
    }
  }
  var secretAlertsHtml = allSecretIssues.length === 0
    ? '<div class="no-changes">Nenhuma secret expirando</div>'
    : allSecretIssues.map(function(item) {
        var color = item.secret.status === "expirada" ? "#ef4444" : "#f59e0b";
        var label = item.secret.status === "expirada" ? "EXPIRADA" : "EXPIRA EM " + item.secret.daysToExp + "d";
        return '<div class="change-item" style="border-left-color:' + color + '"><div class="change-top"><span style="color:' + color + ';font-weight:700">[!]</span><span class="change-msg"><strong>' + escapeHtml(item.appName) + '</strong> — ' + escapeHtml(item.secret.displayName) + '</span><span class="change-time" style="color:' + color + '">' + label + '</span></div><div style="font-size:10px;color:#3a5068;margin-top:4px;padding-left:20px">Criada: ' + fmtDateOnly(item.secret.startDate) + ' / Expira: ' + fmtDateOnly(item.secret.endDate) + '</div></div>';
      }).join("");

  // Serializa datasets para uso no cliente (export Excel)
  var datasetsJson = safeJson(appDatasets);

  return '<!DOCTYPE html><html lang="pt-BR"><head>' +
'<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>App Monitor</title>' +
// SheetJS via CDN para export Excel no browser
'<script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"><\/script>' +
'<style>' +
'@import url("https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600&display=swap");' +
'*{box-sizing:border-box;margin:0;padding:0}body{font-family:"Inter",sans-serif;background:#060a0f;color:#c8d8e8;min-height:100vh}' +
'.hdr{background:#0a1220;border-bottom:1px solid #1a2840;padding:12px 28px;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:200}' +
'.hdr-brand h1{font-family:"JetBrains Mono",monospace;font-size:14px;color:#38bdf8;letter-spacing:2px;text-transform:uppercase}' +
'.tid{font-size:10px;color:#2a4060;margin-top:2px;font-family:"JetBrains Mono",monospace}' +
'.hdr-right{display:flex;align-items:center;gap:12px}' +
'.live{display:flex;align-items:center;gap:5px;font-size:11px;color:#4ade80;background:#0a1f10;padding:4px 10px;border-radius:20px;border:1px solid #166534;font-family:"JetBrains Mono",monospace}' +
'.dot{width:6px;height:6px;background:#4ade80;border-radius:50%;animation:pulse 2s infinite}@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}' +
'.cd{font-size:11px;color:#2a4060;font-family:"JetBrains Mono",monospace}' +
'.ri{font-size:16px;cursor:pointer;color:#2a4060;transition:color .2s}.ri:hover{color:#38bdf8}' +
'.refresh-spin{animation:spin .8s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}' +
'.upd{font-size:11px;color:#2a4060}' +
'.wrap{max-width:1500px;margin:0 auto;padding:20px}' +
'.stats{display:grid;grid-template-columns:repeat(12,1fr);gap:6px;margin-bottom:14px}' +
'.sc{background:#0d1520;border:1px solid #1a2840;border-radius:8px;padding:10px 6px;text-align:center;cursor:pointer;transition:all .2s}' +
'.sc:hover{border-color:#38bdf8;transform:translateY(-2px)}.sc.active-tab{border-color:#0ea5e9;background:#061828}' +
'.sn{font-size:20px;font-weight:700;color:#c8d8e8;font-family:"JetBrains Mono",monospace}.sn.changed{animation:flash .6s}@keyframes flash{0%,100%{opacity:1}50%{opacity:.2}}' +
'.sl{font-size:8px;color:#3a5068;margin-top:2px;text-transform:uppercase;letter-spacing:.5px;line-height:1.2}' +
'.layout{display:grid;grid-template-columns:1fr 300px;gap:14px;align-items:start}' +
'.card{background:#0d1520;border:1px solid #1a2840;border-radius:12px;padding:16px;margin-bottom:12px}' +
'.card-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;flex-wrap:wrap;gap:8px}' +
'.card-title{font-family:"JetBrains Mono",monospace;font-size:11px;color:#3a5068;text-transform:uppercase;letter-spacing:2px}' +
// Botao de export Excel
'.btn-excel{display:inline-flex;align-items:center;gap:5px;padding:5px 12px;background:#166534;border:1px solid #22c55e40;border-radius:6px;color:#4ade80;font-size:10px;font-family:"JetBrains Mono",monospace;cursor:pointer;transition:all .2s;text-transform:uppercase;letter-spacing:1px;white-space:nowrap}' +
'.btn-excel:hover{background:#15803d;border-color:#22c55e}' +
'.search-bar{width:100%;background:#060a0f;border:1px solid #1a2840;border-radius:7px;padding:8px 12px;color:#c8d8e8;font-size:12px;margin-bottom:10px;outline:none;font-family:"JetBrains Mono",monospace;transition:border-color .2s}' +
'.search-bar:focus{border-color:#0ea5e9}' +
'.tab-panel{display:none}.tab-panel.active{display:block}' +
'table{width:100%;border-collapse:collapse;font-size:11px}' +
'th{text-align:left;padding:7px 8px;color:#2a4060;font-weight:600;font-size:9px;text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid #1a2840;font-family:"JetBrains Mono",monospace;white-space:nowrap}' +
'td{padding:8px 8px;border-bottom:1px solid #0d1a2a;color:#94a3b8;vertical-align:middle}' +
'.ar{cursor:pointer;transition:background .15s}.ar:hover td{background:#0a1525}' +
'.ar.risky td:first-child{border-left:2px solid #f59e0b}' +
'.app-name{display:flex;align-items:center;gap:4px;flex-wrap:wrap;color:#c8d8e8;font-weight:500}' +
'.risk-badge{font-size:8px;font-weight:700;padding:1px 5px;border-radius:8px;background:#f59e0b20;color:#f59e0b;border:1px solid #f59e0b40;font-family:"JetBrains Mono",monospace;white-space:nowrap}' +
'.write-badge{font-size:8px;font-weight:700;padding:1px 5px;border-radius:8px;background:#ef444420;color:#ef4444;border:1px solid #ef444440;font-family:"JetBrains Mono",monospace}' +
'.wcat-badge{font-size:8px;font-weight:700;padding:1px 5px;border-radius:8px;background:#f59e0b10;color:#f59e0b;border:1px solid #f59e0b30;font-family:"JetBrains Mono",monospace}' +
'.secret-badge{font-size:8px;font-weight:700;padding:1px 5px;border-radius:8px;background:#60a5fa20;color:#60a5fa;border:1px solid #60a5fa40;font-family:"JetBrains Mono",monospace}' +
'.notes-badge{font-size:8px;padding:1px 4px;border-radius:8px;background:#4ade8020;color:#4ade80;border:1px solid #4ade8040}' +
'.rl-badge{font-size:8px;font-weight:700;padding:1px 5px;border-radius:8px;border:1px solid;font-family:"JetBrains Mono",monospace;white-space:nowrap}' +
'.expand-cell{background:#060d16;padding:12px 14px;border-bottom:1px solid #1a2840}' +
'.notes-box{background:#0a1f10;border:1px solid #166534;border-radius:6px;padding:8px 12px;margin-bottom:10px;font-size:11px;color:#86efac;line-height:1.5}' +
'.notes-label{font-weight:700;margin-right:6px;font-family:"JetBrains Mono",monospace;font-size:9px;text-transform:uppercase;letter-spacing:1px}' +
'.sugg-wrap{display:flex;flex-direction:column;gap:8px}.sugg-ok{font-size:11px;color:#4ade80;padding:8px;background:#061a10;border-radius:5px;font-family:"JetBrains Mono",monospace}' +
'.sugg-section{display:flex;flex-direction:column;gap:4px}.sugg-title{font-size:9px;font-weight:700;margin-bottom:4px;font-family:"JetBrains Mono",monospace;text-transform:uppercase;letter-spacing:1px}' +
'.sugg-item{display:flex;align-items:flex-start;gap:8px;padding:6px 8px;border-radius:5px;background:#060a0f;font-size:11px}' +
'.sugg-item code{font-family:"JetBrains Mono",monospace;font-size:10px;flex-shrink:0;padding:1px 4px;border-radius:3px;background:#0a1525}' +
'.sugg-remove code{color:#ef4444;border:1px solid #ef444430}.sugg-add code{color:#4ade80;border:1px solid #4ade8030}.sugg-item span{color:#94a3b8;line-height:1.4}' +
'.sugg-count{display:inline-flex;align-items:center;justify-content:center;width:14px;height:14px;background:#f59e0b;color:#000;border-radius:50%;font-size:8px;font-weight:700;margin-left:3px}' +
'.expand-tabs{display:flex;gap:3px;margin-bottom:10px;flex-wrap:wrap}' +
'.etab{font-size:9px;padding:3px 8px;border-radius:4px;cursor:pointer;background:transparent;color:#3a5068;border:1px solid #1a2840;font-family:"JetBrains Mono",monospace;transition:all .2s;white-space:nowrap}' +
'.etab:hover{border-color:#38bdf8;color:#38bdf8}.etab.active{background:#061828;border-color:#0ea5e9;color:#38bdf8}' +
'.epanel{display:none}.epanel.active{display:block}' +
'.perm-wrap{display:flex;flex-wrap:wrap;gap:3px}' +
'.pb{display:inline-flex;align-items:center;gap:2px;font-size:9px;padding:2px 6px;border-radius:4px;border:1px solid;font-family:"JetBrains Mono",monospace}' +
'.pt{font-size:7px;font-weight:700;opacity:.6}' +
'.pb-wrap{position:relative;display:inline-block;margin:2px}' +
'.pb-tooltip{display:none;position:absolute;bottom:calc(100% + 5px);left:50%;transform:translateX(-50%);background:#0a1a2a;border:1px solid #1e4060;border-radius:7px;padding:8px 10px;font-size:10px;color:#c8d8e8;white-space:pre-wrap;max-width:260px;min-width:160px;z-index:9999;box-shadow:0 8px 24px rgba(0,0,0,.8);line-height:1.5;pointer-events:none}' +
'.pb-wrap:hover .pb-tooltip{display:block}' +
'.leg{display:flex;gap:8px;font-size:9px;color:#2a4060;margin-bottom:8px;flex-wrap:wrap;font-family:"JetBrains Mono",monospace}' +
'.secrets-wrap{display:flex;flex-direction:column;gap:5px}' +
'.secret-item{display:flex;align-items:center;gap:10px;padding:7px 8px;background:#0a1525;border-radius:5px;flex-wrap:wrap}' +
'.secret-name{font-size:10px;color:#c8d8e8;font-family:"JetBrains Mono",monospace;flex:1}.secret-dates{font-size:9px;color:#3a5068}.secret-status{font-size:9px;font-weight:700;font-family:"JetBrains Mono",monospace}' +
'.audit-wrap{display:flex;flex-direction:column;gap:4px}' +
'.audit-title{font-size:9px;color:#3a5068;margin-bottom:5px;font-family:"JetBrains Mono",monospace;text-transform:uppercase;letter-spacing:1px}' +
'.audit-item{display:flex;align-items:flex-start;gap:8px;padding:5px 7px;background:#0a1525;border-radius:4px;flex-wrap:wrap}' +
'.audit-action{font-size:10px;color:#c8d8e8;flex:1;min-width:100px}.audit-actor{font-size:9px;color:#38bdf8;font-family:"JetBrains Mono",monospace}.audit-time{font-size:9px;color:#3a5068}' +
'.wb{display:inline-flex;align-items:center;font-size:10px;padding:2px 8px;border-radius:5px;background:#0a1f30;border:1px solid #1e4060;color:#38bdf8;font-family:"JetBrains Mono",monospace}' +
'.wc-badge{display:inline-flex;align-items:center;font-size:10px;padding:2px 8px;border-radius:5px;background:#1a0f00;border:1px solid #f59e0b40;color:#f59e0b;font-family:"JetBrains Mono",monospace}' +
'.side-card{background:#0d1520;border:1px solid #1a2840;border-radius:10px;padding:14px;margin-bottom:10px}' +
'.side-title{font-family:"JetBrains Mono",monospace;font-size:9px;color:#3a5068;text-transform:uppercase;letter-spacing:2px;margin-bottom:10px;display:flex;align-items:center;justify-content:space-between}' +
'.change-item{padding:7px 8px;border-left:2px solid #1a2840;background:#060d16;border-radius:0 5px 5px 0;margin-bottom:5px}' +
'.change-top{display:flex;align-items:center;gap:5px;flex-wrap:wrap}.change-msg{font-size:10px;color:#c8d8e8;flex:1}.change-time{font-size:9px;color:#3a5068;white-space:nowrap;font-family:"JetBrains Mono",monospace}' +
'.perm-changes{display:flex;flex-wrap:wrap;gap:3px;margin-top:5px;padding-top:5px;border-top:1px solid #1a2840}' +
'.pc{font-size:9px;font-weight:600;padding:1px 4px;background:#060a0f;border-radius:3px;font-family:"JetBrains Mono",monospace}' +
'.no-changes{font-size:10px;color:#2a4060;text-align:center;padding:16px 0;font-family:"JetBrains Mono",monospace}.empty-tab{font-size:11px;color:#2a4060;text-align:center;padding:32px 0;font-family:"JetBrains Mono",monospace}' +
'#toast-area{position:fixed;bottom:14px;right:14px;z-index:999;display:flex;flex-direction:column;gap:5px;max-width:340px}' +
'.toast{background:#0d1520;border:1px solid #1a2840;border-radius:8px;padding:8px 12px;font-size:11px;display:flex;align-items:flex-start;gap:7px;box-shadow:0 6px 24px rgba(0,0,0,.6);animation:slideUp .3s ease}' +
'.toast.critico{border-color:#ef4444;background:#1a0808}.toast.aviso{border-color:#f59e0b;background:#1a1208}.toast.melhora{border-color:#4ade80;background:#081a10}.toast.info{border-color:#60a5fa;background:#08101a}' +
'.tc{margin-left:auto;color:#2a4060;cursor:pointer;font-size:13px}' +
'@keyframes slideUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}' +
'.foot{text-align:center;padding:18px;color:#2a4060;font-size:10px;font-family:"JetBrains Mono",monospace}.foot a{color:#0ea5e9;text-decoration:none}' +
'</style></head><body>' +

'<div id="toast-area"></div>' +
'<div class="hdr"><div class="hdr-brand"><div><h1>ENTERPRISE APPLICATIONS MONITOR</h1><div class="tid">' + session.tenantId + '</div></div></div>' +
'<div class="hdr-right"><div class="live"><div class="dot"></div>LIVE</div><div class="cd" id="cd">NEXT: <strong id="timer">5:00</strong></div><div class="ri" id="ri" title="Atualizar agora" onclick="forceRefresh()">&#8635;</div><div class="upd">UPD: <span id="upd">agora</span></div></div></div>' +

'<div class="wrap">' +
'<div class="stats">' +
'<div class="sc active-tab" id="tab-btn-all" onclick="switchMainTab(\'all\',this)"><div class="sn" id="stTotal">' + allApps.length + '</div><div class="sl">Todos</div></div>' +
'<div class="sc" id="tab-btn-risky" onclick="switchMainTab(\'risky\',this)"><div class="sn" id="stRisky" style="color:#f59e0b">' + riskyApps.length + '</div><div class="sl">App Perm</div></div>' +
'<div class="sc" id="tab-btn-write" onclick="switchMainTab(\'write\',this)"><div class="sn" id="stWrite" style="color:#ef4444">' + writeApps.length + '</div><div class="sl">Write</div></div>' +
'<div class="sc" id="tab-btn-writegroups" onclick="switchMainTab(\'writegroups\',this)"><div class="sn" id="stWriteGroups" style="color:#ef4444">' + writeGroupsApps.length + '</div><div class="sl">W Groups</div></div>' +
'<div class="sc" id="tab-btn-writeusers" onclick="switchMainTab(\'writeusers\',this)"><div class="sn" id="stWriteUsers" style="color:#ef4444">' + writeUsersApps.length + '</div><div class="sl">W Users</div></div>' +
'<div class="sc" id="tab-btn-writeemail" onclick="switchMainTab(\'writeemail\',this)"><div class="sn" id="stWriteEmail" style="color:#ef4444">' + writeEmailApps.length + '</div><div class="sl">W E-mail</div></div>' +
'<div class="sc" id="tab-btn-writefiles" onclick="switchMainTab(\'writefiles\',this)"><div class="sn" id="stWriteFiles" style="color:#ef4444">' + writeFilesApps.length + '</div><div class="sl">W Files</div></div>' +
'<div class="sc" id="tab-btn-critical" onclick="switchMainTab(\'critical\',this)"><div class="sn" id="stCritical" style="color:#ef4444">' + criticalApps.length + '</div><div class="sl">Critical</div></div>' +
'<div class="sc" id="tab-btn-recent" onclick="switchMainTab(\'recent\',this)"><div class="sn" id="stRecent" style="color:#60a5fa">' + recentApps.length + '</div><div class="sl">30 dias</div></div>' +
'<div class="sc" id="tab-btn-noowner" onclick="switchMainTab(\'noowner\',this)"><div class="sn" id="stNoOwner" style="color:#ef4444">' + noOwnerApps.length + '</div><div class="sl">Sem Owner</div></div>' +
'<div class="sc" id="tab-btn-secrets" onclick="switchMainTab(\'secrets\',this)"><div class="sn" id="stSecrets" style="color:#a78bfa">' + appsWithSecrets.length + '</div><div class="sl">Secrets</div></div>' +
'<div class="sc" id="tab-btn-expsecrets" onclick="switchMainTab(\'expsecrets\',this)"><div class="sn" id="stExpSecrets" style="color:#ef4444">' + expSecrets.length + '</div><div class="sl">Exp.Secrets</div></div>' +
'</div>' +

'<div class="layout"><div><div class="card">' +
'<div class="card-header">' +
  '<div class="card-title" id="tabLabel">Todas as Aplicacoes (' + allApps.length + ')</div>' +
  '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
    '<div class="leg" style="margin:0"><span style="color:#ef4444">■ Critico</span><span style="color:#f59e0b">■ Alto</span><span style="color:#4ade80">■ Normal</span><span>W=Write</span></div>' +
    '<button class="btn-excel" onclick="exportExcel()">&#8595; Excel</button>' +
  '</div>' +
'</div>' +
'<input class="search-bar" id="search" type="text" placeholder="Buscar por nome, owner, criador, permissao, workload..." oninput="filterTable()">' +

'<div id="tp-all" class="tab-panel active"><table><thead><tr><th>Nome</th><th>Criado em</th><th>Ultimo Uso</th><th>Criado por</th><th>Owner(s)</th><th>Perms</th></tr></thead><tbody>' + allApps.map(function(a) { return buildAppRow(a, "all"); }).join("") + '</tbody></table></div>' +
'<div id="tp-risky" class="tab-panel">' + buildTabTable(riskyApps, "Nenhum app com Application Permission", "risky") + '</div>' +
'<div id="tp-write" class="tab-panel">' + buildTabTable(writeApps, "Nenhum app com permissoes de escrita", "write") + '</div>' +
'<div id="tp-writegroups" class="tab-panel">' + buildTabTable(writeGroupsApps, "Nenhum app com Write em Groups", "writegroups") + '</div>' +
'<div id="tp-writeusers" class="tab-panel">' + buildTabTable(writeUsersApps, "Nenhum app com Write em Users", "writeusers") + '</div>' +
'<div id="tp-writeemail" class="tab-panel">' + buildTabTable(writeEmailApps, "Nenhum app com Write em E-mail", "writeemail") + '</div>' +
'<div id="tp-writefiles" class="tab-panel">' + buildTabTable(writeFilesApps, "Nenhum app com Write em Files", "writefiles") + '</div>' +
'<div id="tp-critical" class="tab-panel">' + buildTabTable(criticalApps, "Nenhum app com risco Critical", "critical") + '</div>' +
'<div id="tp-recent" class="tab-panel">' + buildTabTable(recentApps, "Nenhum app criado nos ultimos 30 dias", "recent") + '</div>' +
'<div id="tp-noowner" class="tab-panel">' + buildTabTable(noOwnerApps, "Todos os apps possuem owner", "noowner") + '</div>' +
'<div id="tp-secrets" class="tab-panel">' + buildTabTable(appsWithSecrets, "Nenhum app com secrets", "secrets") + '</div>' +
'<div id="tp-expsecrets" class="tab-panel">' + buildTabTable(expSecrets, "Nenhuma secret expirada ou expirando", "expsecrets") + '</div>' +
'</div></div>' +

'<div><div class="side-card"><div class="side-title"><span>Mudancas (24h)</span><span style="color:#2a4060">' + changes24h.length + '</span></div><div id="changesPanel">' + changesHtml + '</div></div>' +
'<div class="side-card"><div class="side-title"><span>Secrets Expirando</span><span style="color:#2a4060">' + allSecretIssues.length + '</span></div><div id="secretAlertsPanel">' + secretAlertsHtml + '</div></div></div>' +
'</div></div>' +

'<div class="foot"><a href="/">Nova analise</a></div>' +

'<script>' +
'var SID="' + sessionId + '";var INTERVAL=5*60*1000;var next=Date.now()+INTERVAL;var busy=false;var currentTab="all";' +
'var initChanges=' + initChangesJson + ';' +
'if(initChanges&&initChanges.length>0){setTimeout(function(){initChanges.forEach(showToast);},700);}' +

// Datasets para export — todos os grupos pre-calculados no servidor
'var DATASETS=' + datasetsJson + ';' +

'setInterval(function(){if(busy)return;var r=Math.max(0,next-Date.now());var m=Math.floor(r/60000),s=Math.floor((r%60000)/1000);document.getElementById("timer").textContent=m+":"+(s<10?"0":"")+s;if(r<=0)doRefresh();},1000);' +
'function forceRefresh(){next=Date.now();}' +

'function switchMainTab(name,el){' +
'  currentTab=name;' +
'  document.querySelectorAll(".sc").forEach(function(e){e.classList.remove("active-tab");});' +
'  el.classList.add("active-tab");' +
'  document.querySelectorAll(".tab-panel").forEach(function(e){e.classList.remove("active");e.style.display="none";});' +
'  var panel=document.getElementById("tp-"+name);if(panel){panel.classList.add("active");panel.style.display="block";}' +
'  var labels={all:"Todas",risky:"App Permissions",write:"Permissoes Write",writegroups:"Write em Groups",writeusers:"Write em Users",writeemail:"Write em E-mail",writefiles:"Write em Files",critical:"Risco Critical",recent:"Criados 30 dias",noowner:"Sem Owner",secrets:"Com Secrets",expsecrets:"Secrets Expirando"};' +
'  var counts={all:"stTotal",risky:"stRisky",write:"stWrite",writegroups:"stWriteGroups",writeusers:"stWriteUsers",writeemail:"stWriteEmail",writefiles:"stWriteFiles",critical:"stCritical",recent:"stRecent",noowner:"stNoOwner",secrets:"stSecrets",expsecrets:"stExpSecrets"};' +
'  var countEl=document.getElementById(counts[name]);' +
'  document.getElementById("tabLabel").textContent=(labels[name]||name)+" ("+(countEl?countEl.textContent:"?")+")";' +
'  document.getElementById("search").value="";' +
'}' +

'function filterTable(){' +
'  var q=document.getElementById("search").value.toLowerCase();' +
'  var rows=document.querySelectorAll("#tp-"+currentTab+" tr.ar");' +
'  rows.forEach(function(row){' +
'    var show=q===""||row.textContent.toLowerCase().includes(q);' +
'    row.style.display=show?"":"none";' +
'    var onclick=row.getAttribute("onclick")||"";' +
'    var match=onclick.match(/toggle\\(\'([^\']+)\'\\)/);' +
'    if(match){var exp=document.getElementById(match[1]);if(exp&&!show)exp.style.display="none";}' +
'  });' +
'}' +

'function toggle(id){var r=document.getElementById(id);if(r)r.style.display=r.style.display==="none"?"table-row":"none";}' +
'function etab(el,panelId){var expand=el.closest(".expand-cell");expand.querySelectorAll(".etab").forEach(function(e){e.classList.remove("active");});expand.querySelectorAll(".epanel").forEach(function(e){e.style.display="none";});el.classList.add("active");var p=document.getElementById(panelId);if(p){p.style.display="block";}}' +
'function upd(id,v){var el=document.getElementById(id);if(el&&el.textContent!=String(v)){el.textContent=v;el.classList.remove("changed");void el.offsetWidth;el.classList.add("changed");}}' +
'function esc(s){return String(s==null?"":s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/\'/g,"&#39;");}' +

// ── exportExcel: gera .xlsx da aba atual no browser ──────────────────────────
'function exportExcel(){' +
'  if(typeof XLSX==="undefined"){alert("SheetJS nao carregado. Verifique sua conexao.");return;}' +
'  var dataset=DATASETS[currentTab]||[];' +
'  if(dataset.length===0){alert("Nenhum dado para exportar nesta aba.");return;}' +
'  var labels={all:"Todas",risky:"App_Permissions",write:"Write",writegroups:"Write_Groups",writeusers:"Write_Users",writeemail:"Write_Email",writefiles:"Write_Files",critical:"Critical",recent:"Criados_30d",noowner:"Sem_Owner",secrets:"Com_Secrets",expsecrets:"Exp_Secrets"};' +
// Monta linhas da planilha
'  var rows=dataset.map(function(a){' +
'    var owners=(a._owners||[]).map(function(o){return o.displayName||o.userPrincipalName||o.mail||"";}).join("; ");' +
'    var appPerms=(a.appRoles||[]).map(function(p){return p.name||p.id;}).join("; ");' +
'    var delPerms=(a.delegated||[]).map(function(p){return p.name||p.id;}).join("; ");' +
'    var writePerms=(a._writePermissions||[]).map(function(p){return p.name||p.id;}).join("; ");' +
'    var workloads=((a._usageAnalysis&&a._usageAnalysis.workloads)||[]).join("; ");' +
'    var secrets=(a.secrets||[]).map(function(s){return s.displayName+"("+s.status+",exp:"+( s.endDate?new Date(s.endDate).toLocaleDateString("pt-BR"):"sem data")+")";}).join("; ");' +
'    var lastSignIn=a._lastSignIn&&a._lastSignIn.length>0?new Date(a._lastSignIn[0].createdDateTime).toLocaleString("pt-BR"):"";' +
'    var lastUser=a._lastSignIn&&a._lastSignIn.length>0?(a._lastSignIn[0].userDisplayName||a._lastSignIn[0].userPrincipalName||a._lastSignIn[0].servicePrincipalName||""):"";' +
'    var createdBy=a._createdBy||"";' +
'    return {' +
'      "Nome": a.displayName||"",' +
'      "App ID": a.appId||"",' +
'      "Criado em": a.createdDateTime?new Date(a.createdDateTime).toLocaleString("pt-BR"):"",' +
'      "Criado por": createdBy,' +
'      "Owner(s)": owners,' +
'      "Risco": a._riskLevel||"",' +
'      "Ultimo Uso": lastSignIn,' +
'      "Ultimo Usuario": lastUser,' +
'      "Sign-in Audience": a.signInAudience||"",' +
'      "App Permissions (APP)": appPerms,' +
'      "Delegated Permissions (DEL)": delPerms,' +
'      "Write Permissions": writePerms,' +
'      "Write em Groups": (a._writePermissions||[]).some(function(p){return(p.name||"").startsWith("Group.")})?("Sim"):"Nao",' +
'      "Write em Users": (a._writePermissions||[]).some(function(p){return(p.name||"").startsWith("User.")})?("Sim"):"Nao",' +
'      "Write em E-mail": (a._writePermissions||[]).some(function(p){return(p.name||"").startsWith("Mail.")||(p.name||"").startsWith("MailboxSettings.")})?("Sim"):"Nao",' +
'      "Write em Files": (a._writePermissions||[]).some(function(p){return(p.name||"").startsWith("Files.")||(p.name||"").startsWith("Sites.")})?("Sim"):"Nao",' +
'      "Workloads": workloads,' +
'      "Secrets": secrets,' +
'      "Notas": a.notes||""' +
'    };' +
'  });' +

// Cria workbook com duas abas: dados + resumo
'  var wb=XLSX.utils.book_new();' +

// Aba principal com os dados
'  var ws=XLSX.utils.json_to_sheet(rows);' +

// Larguras de coluna
'  ws["!cols"]=[' +
'    {wch:40},{wch:38},{wch:20},{wch:25},{wch:30},{wch:10},' +
'    {wch:20},{wch:25},{wch:18},{wch:60},{wch:60},{wch:50},' +
'    {wch:15},{wch:14},{wch:15},{wch:14},{wch:50},{wch:60},{wch:30}' +
'  ];' +

'  XLSX.utils.book_append_sheet(wb,ws,"Apps");' +

// Aba de resumo
'  var summary=[' +
'    ["Relatorio: Enterprise Applications Monitor"],' +
'    ["Tenant ID","' + session.tenantId + '"],' +
'    ["Gerado em",new Date().toLocaleString("pt-BR")],' +
'    ["Aba exportada",labels[currentTab]||currentTab],' +
'    ["Total de apps",dataset.length],' +
'    [],' +
'    ["Categoria","Quantidade"],' +
'    ["Total de apps",' + allApps.length + '],' +
'    ["Com App Permission",' + riskyApps.length + '],' +
'    ["Com Write Permission",' + writeApps.length + '],' +
'    ["Write em Groups",' + writeGroupsApps.length + '],' +
'    ["Write em Users",' + writeUsersApps.length + '],' +
'    ["Write em E-mail",' + writeEmailApps.length + '],' +
'    ["Write em Files",' + writeFilesApps.length + '],' +
'    ["Risco Critical",' + criticalApps.length + '],' +
'    ["Criados nos ultimos 30 dias",' + recentApps.length + '],' +
'    ["Sem Owner",' + noOwnerApps.length + '],' +
'    ["Com Secrets",' + appsWithSecrets.length + '],' +
'    ["Secrets Expirando/Expiradas",' + expSecrets.length + '],' +
'  ];' +
'  var wsSummary=XLSX.utils.aoa_to_sheet(summary);' +
'  wsSummary["!cols"]=[{wch:35},{wch:45}];' +
'  XLSX.utils.book_append_sheet(wb,wsSummary,"Resumo");' +

// Baixa o arquivo
'  var tabName=labels[currentTab]||currentTab;' +
'  var ts=new Date().toISOString().slice(0,10);' +
'  XLSX.writeFile(wb,"EnterpriseApps_"+tabName+"_"+ts+".xlsx");' +
'}' +

'function doRefresh(){' +
'  if(busy)return;busy=true;next=Date.now()+INTERVAL;' +
'  var ri=document.getElementById("ri");ri.classList.add("refresh-spin");' +
'  document.getElementById("cd").innerHTML="ATUALIZANDO...";' +
'  fetch("/refresh/"+SID).then(function(r){return r.json();}).then(function(data){' +
'    if(data.error){showToast({severity:"critico",message:"Erro: "+data.error});return;}' +
'    var apps=data.apps;' +
// Atualiza datasets em memoria para o proximo export refletir os dados novos
'    DATASETS.all=apps;' +
'    DATASETS.risky=apps.filter(function(a){return a.appRoles&&a.appRoles.length>0;});' +
'    DATASETS.write=apps.filter(function(a){return a._writePermissions&&a._writePermissions.length>0;});' +
'    DATASETS.critical=apps.filter(function(a){return a._riskLevel==="Critical";});' +
'    DATASETS.recent=apps.filter(function(a){return a.createdDateTime&&(Date.now()-new Date(a.createdDateTime).getTime())/86400000<=30;});' +
'    DATASETS.noowner=apps.filter(function(a){return !a._owners||a._owners.length===0;});' +
'    DATASETS.secrets=apps.filter(function(a){return a.secrets&&a.secrets.length>0;});' +
'    DATASETS.expsecrets=apps.filter(function(a){return(a.secrets||[]).some(function(s){return s.status==="expirada"||s.status==="expirando";});});' +
'    upd("stTotal",apps.length);upd("stRisky",DATASETS.risky.length);upd("stWrite",DATASETS.write.length);' +
'    upd("stCritical",DATASETS.critical.length);upd("stRecent",DATASETS.recent.length);upd("stNoOwner",DATASETS.noowner.length);' +
'    upd("stSecrets",DATASETS.secrets.length);upd("stExpSecrets",DATASETS.expsecrets.length);' +
'    if(data.changesLast24h){var ch=data.changesLast24h;var panel=document.getElementById("changesPanel");' +
'      if(ch.length===0){panel.innerHTML=\'<div class="no-changes">Nenhuma mudanca nas ultimas 24 horas</div>\';}' +
'      else{panel.innerHTML=ch.slice().reverse().map(function(c){var icon=c.severity==="critico"?"[!!]":c.severity==="aviso"?"[!]":c.type==="removido"?"[-]":c.type==="novo"?"[+]":"[ok]";var color=c.severity==="critico"?"#ef4444":c.severity==="aviso"?"#f59e0b":c.severity==="melhora"?"#4ade80":"#60a5fa";var pd="";if(c.permChanges&&c.permChanges.length>0){pd=\'<div class="perm-changes">\'+c.permChanges.map(function(pc){var pcc=pc.action==="adicionada"?(pc.severity==="critico"?"#ef4444":"#f59e0b"):"#4ade80";return\'<span class="pc" style="color:\'+pcc+\'">\'+(pc.action==="adicionada"?"+":"-")+\' [\'+esc(pc.type)+\'] \'+esc(pc.name)+"</span>";}).join("")+"</div>";}return\'<div class="change-item" style="border-left-color:\'+color+\'"><div class="change-top"><span style="color:\'+color+\';font-weight:700;font-size:10px">\'+icon+\'</span><span class="change-msg">\'+esc(c.message)+\'</span><span class="change-time">\'+new Date(c.detectedAt).toLocaleString("pt-BR")+\'</span></div>\'+pd+"</div>";}).join("");}' +
'      if(data.newChanges&&data.newChanges.length>0){data.newChanges.forEach(showToast);}' +
'    }' +
'    document.getElementById("upd").textContent=new Date().toLocaleTimeString("pt-BR");' +
'  }).catch(function(e){showToast({severity:"critico",message:"Falha: "+e.message});})' +
'  .finally(function(){busy=false;document.getElementById("ri").classList.remove("refresh-spin");document.getElementById("cd").innerHTML=\'NEXT: <strong id="timer">5:00</strong>\';});' +
'}' +

'function showToast(c){var area=document.getElementById("toast-area");var icons={critico:"[!!]",aviso:"[!]",melhora:"[ok]",info:"[i]"};var t=document.createElement("div");t.className="toast "+(c.severity||"info");t.innerHTML=\'<span style="font-weight:700">\'+(icons[c.severity]||"[i]")+\'</span><span>\'+esc(c.message)+\'</span><span class="tc" onclick="this.parentElement.remove()">x</span>\';area.appendChild(t);setTimeout(function(){if(t.parentElement)t.remove();},10000);}' +
'document.querySelectorAll(".tab-panel").forEach(function(e){if(!e.classList.contains("active"))e.style.display="none";});' +
'</script></body></html>';
}

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log("App Monitor rodando na porta " + PORT));
