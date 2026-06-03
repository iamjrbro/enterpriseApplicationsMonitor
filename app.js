require("dotenv").config();
const express = require("express");
const { ConfidentialClientApplication } = require("@azure/msal-node");
const axios = require("axios");

const app = express();
app.use(express.json());

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

// ─── Helpers ──────────────────────────────────────────────────────────────────
function escapeHtml(v) {
  return String(v ?? "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
}
function safeJson(v) { return JSON.stringify(v).replace(/</g,"\\u003c"); }
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
function fmtDate(d) { if (!d) return "—"; return new Date(d).toLocaleString("pt-BR"); }
function fmtDateOnly(d) { if (!d) return "—"; return new Date(d).toLocaleDateString("pt-BR"); }

// ─── Graph com retry e throttling ─────────────────────────────────────────────
async function graphRequest(url, token, retries = 4) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await axios.get(url, {
        headers: { Authorization: "Bearer " + token },
        timeout: 30000,
      });
      return res.data;
    } catch (e) {
      if (e.response && e.response.status === 429) {
        const wait = parseInt(e.response.headers["retry-after"] || "10") * 1000;
        console.warn(`Graph throttled, waiting ${wait}ms (attempt ${attempt + 1})`);
        await sleep(wait);
        continue;
      }
      if (e.response && e.response.status === 401 && attempt === 0) {
        throw new Error("TOKEN_EXPIRED");
      }
      if (attempt === retries) throw e;
      await sleep(Math.pow(2, attempt) * 500);
    }
  }
}

async function graphGet(url, token) {
  const base = url.startsWith("http") ? "" : "https://graph.microsoft.com/v1.0";
  return graphRequest(base + url, token);
}

async function graphGetBeta(url, token) {
  const base = url.startsWith("http") ? "" : "https://graph.microsoft.com/beta";
  return graphRequest(base + url, token);
}

async function graphPaged(url, token, limit = 10000) {
  let results = [];
  const base = url.startsWith("http") ? "" : "https://graph.microsoft.com/v1.0";
  let nextUrl = base + url;
  while (nextUrl && results.length < limit) {
    const data = await graphRequest(nextUrl, token);
    if (data.value) results = results.concat(data.value);
    nextUrl = data["@odata.nextLink"] || null;
    if (results.length >= limit) { results = results.slice(0, limit); break; }
  }
  return { value: results };
}

// ─── Graph queries ─────────────────────────────────────────────────────────────
async function getApps(token) {
  return graphPaged(
    "/applications?$select=displayName,appId,id,requiredResourceAccess,createdDateTime,signInAudience,notes,tags,passwordCredentials,keyCredentials,web,spa,publicClient,info,publisherDomain,verifiedPublisher&$top=999",
    token, 10000
  );
}

async function getAllServicePrincipals(token) {
  return graphPaged(
    "/servicePrincipals?$select=id,appId,displayName,accountEnabled,servicePrincipalType,publisherName,homepage,replyUrls,preferredSingleSignOnMode,samlSingleSignOnSettings,loginUrl,logoutUrl,appRoles,oauth2PermissionScopes,tags,notes,createdDateTime&$top=999",
    token, 10000
  );
}

async function getDeletedApps(token) {
  try {
    const res = await graphPaged(
      "/directory/deletedItems/microsoft.graph.application?$select=displayName,appId,id,createdDateTime,deletedDateTime,signInAudience,tags&$top=999",
      token, 5000
    );
    return res.value || [];
  } catch (e) {
    console.warn("Deleted apps not available:", e.message);
    return [];
  }
}

async function getAppOwners(appObjectId, token) {
  try {
    const res = await graphGet(
      "/applications/" + appObjectId + "/owners?$select=displayName,userPrincipalName,mail,id,jobTitle,department,officeLocation,mobilePhone,businessPhones",
      token
    );
    return res.value || [];
  } catch (e) { return []; }
}

async function getAuditLogs(token) {
  try {
    const since = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    const res = await graphPaged(
      "/auditLogs/directoryAudits?$filter=category eq 'ApplicationManagement' and activityDateTime ge " + since +
      "&$select=activityDateTime,activityDisplayName,initiatedBy,targetResources,result&$top=999",
      token, 5000
    );
    return res.value || [];
  } catch (e) { console.error("Audit logs:", e.message); return []; }
}

async function getLastSignIn(appId, token) {
  try {
    const safeId = appId.replace(/'/g, "''");
    const base = "https://graph.microsoft.com/beta/auditLogs/signIns";
    const [r1, r2] = await Promise.allSettled([
      axios.get(base + "?$filter=appId eq '" + safeId + "'&$orderby=createdDateTime desc&$top=1&$select=createdDateTime,userDisplayName,userPrincipalName,ipAddress,clientAppUsed,resourceDisplayName,location,signInEventTypes", { headers: { Authorization: "Bearer " + token }, timeout: 15000 }),
      axios.get(base + "?$filter=appId eq '" + safeId + "' and signInEventTypes/any(t: t eq 'servicePrincipal')&$orderby=createdDateTime desc&$top=1&$select=createdDateTime,servicePrincipalName,servicePrincipalId,ipAddress,resourceDisplayName,signInEventTypes", { headers: { Authorization: "Bearer " + token }, timeout: 15000 }),
    ]);
    const signIns = [];
    [r1, r2].forEach(r => { if (r.status === "fulfilled" && r.value.data.value) signIns.push(...r.value.data.value); });
    signIns.sort((a, b) => new Date(b.createdDateTime) - new Date(a.createdDateTime));
    return signIns.length > 0 ? signIns.slice(0, 3) : null;
  } catch (e) { return null; }
}

async function getSpSsoDetails(spId, token) {
  try {
    const [claims, certRes] = await Promise.allSettled([
      graphGet("/servicePrincipals/" + spId + "/claimsMappingPolicies", token),
      graphGetBeta("/servicePrincipals/" + spId + "/tokenSigningCertificates", token),
    ]);
    return {
      claimsPolicies: claims.status === "fulfilled" ? (claims.value?.value || []) : [],
      samlCerts: certRes.status === "fulfilled" ? (certRes.value?.value || []) : [],
    };
  } catch (e) { return { claimsPolicies: [], samlCerts: [] }; }
}

async function getAppRoleAssignments(spId, token) {
  try {
    const res = await graphPaged("/servicePrincipals/" + spId + "/appRoleAssignedTo?$top=999", token, 500);
    return res.value || [];
  } catch (e) { return []; }
}

// ─── Análise de permissões ─────────────────────────────────────────────────────
function analyzeWritePermissions(app) {
  return [].concat(app.appRoles || [], app.delegated || []).filter(p => {
    const n = (p.name || "").toLowerCase();
    return n.includes("write") || n.includes("readwrite") || n.includes("manage") || n.includes("send") || n.includes("full_access_as_app");
  });
}

function getWriteCategories(a) {
  const wp = a._writePermissions || [];
  const cats = [];
  const has = (prefixes) => wp.some(p => prefixes.some(pfx => (p.name || "").startsWith(pfx)));
  if (has(["Group."])) cats.push("groups");
  if (has(["User."])) cats.push("users");
  if (has(["Mail.", "MailboxSettings."])) cats.push("email");
  if (has(["Files.", "Sites."])) cats.push("files");
  if (has(["Directory.", "RoleManagement."])) cats.push("directory");
  if (has(["Application."])) cats.push("apps");
  return cats;
}

function buildUsageAnalysis(app) {
  const allPerms = [].concat(app.appRoles || [], app.delegated || []);
  const workloads = [];
  const has = (pfx) => allPerms.some(p => (p.name || "").startsWith(pfx));
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
  perms.forEach(p => { score += criticalPerms.some(c => (p.name || "").includes(c)) ? 40 : 10; });
  if (app._lastSignIn) score += 10;
  if (!app._owners || app._owners.length === 0) score += 20;
  if (app._status === "disabled") score += 5;
  if (score >= 80) return "Critical";
  if (score >= 50) return "High";
  if (score >= 25) return "Medium";
  return "Low";
}

function classifyPerm(name) {
  if (!name) return "normal";
  const critical = ["Mail.ReadWrite","Mail.Send","Files.ReadWrite.All","Directory.ReadWrite.All","User.ReadWrite.All","RoleManagement.ReadWrite.Directory","Application.ReadWrite.All","Group.ReadWrite.All","full_access_as_app"];
  const high = ["Mail.Read","Files.Read.All","User.Read.All","Directory.Read.All","AuditLog.Read.All","Policy.Read.All","IdentityRiskyUser.Read.All"];
  if (critical.some(c => name.includes(c))) return "critico";
  if (high.some(h => name.includes(h))) return "alto";
  return "normal";
}

function permLabel(p) { return p.name || "[" + p.id.substring(0, 8) + "...]"; }

function getRedirectUris(a) {
  let uris = [];
  if (a.web?.redirectUris) uris = uris.concat(a.web.redirectUris);
  if (a.spa?.redirectUris) uris = uris.concat(a.spa.redirectUris);
  if (a.publicClient?.redirectUris) uris = uris.concat(a.publicClient.redirectUris);
  return uris;
}

function getRedirectUriTypes(a) {
  const t = [];
  if (a.web?.redirectUris?.length > 0) t.push("Web");
  if (a.spa?.redirectUris?.length > 0) t.push("SPA");
  if (a.publicClient?.redirectUris?.length > 0) t.push("Mobile/Desktop");
  return t;
}

function fmtLastUsed(signIns) {
  if (!signIns || signIns.length === 0) return { text: "Nunca", color: "#3a5068", full: "Nenhum sign-in detectado" };
  const last = signIns[0];
  const days = Math.floor((Date.now() - new Date(last.createdDateTime).getTime()) / 86400000);
  const color = days > 90 ? "#ef4444" : days > 30 ? "#f59e0b" : "#4ade80";
  const text = days === 0 ? "Hoje" : days === 1 ? "Ontem" : days + "d atras";
  return { text, color, full: fmtDate(last.createdDateTime) };
}

function resolveActor(log) {
  const ib = log.initiatedBy;
  if (!ib) return null;
  if (ib.user) { const u = ib.user; return u.displayName || u.userPrincipalName || (u.id ? "Usuario (" + u.id.substring(0,8) + "...)" : "Usuario desconhecido"); }
  if (ib.app) return "__SYSTEM__:" + (ib.app.displayName || ib.app.appId || "Sistema");
  return "__SYSTEM__:Azure AD";
}
function isHumanActor(a) { return a && !a.startsWith("__SYSTEM__:"); }
function formatActor(a) { if (!a || a.startsWith("__SYSTEM__:")) return null; return a; }

// ─── Coleta completa ──────────────────────────────────────────────────────────
async function collectApps(token) {
  const [appsData, allSPsData, msGraphSPs, exchangeSPs, auditLogs, deletedApps] = await Promise.all([
    getApps(token),
    getAllServicePrincipals(token),
    graphPaged("/servicePrincipals?$filter=appId eq '00000003-0000-0000-c000-000000000000'&$select=displayName,appId,oauth2PermissionScopes,appRoles", token, 1),
    graphPaged("/servicePrincipals?$filter=appId eq '00000002-0000-0ff1-ce00-000000000000'&$select=displayName,appId,oauth2PermissionScopes,appRoles", token, 1),
    getAuditLogs(token),
    getDeletedApps(token),
  ]);

  // Mapeia SPs por appId para lookup rápido
  const spMap = {};
  for (const sp of allSPsData.value) spMap[sp.appId] = sp;
  for (const sp of [...(msGraphSPs.value || []), ...(exchangeSPs.value || [])]) spMap[sp.appId] = sp;

  // SP map para permissões
  const permSpMap = {};
  for (const sp of [...(msGraphSPs.value || []), ...(exchangeSPs.value || [])]) permSpMap[sp.appId] = sp;
  for (const sp of allSPsData.value) { if (!permSpMap[sp.appId]) permSpMap[sp.appId] = sp; }

  // Mapa de audit
  const auditMap = {};
  function addToAuditMap(key, entry) {
    if (!key) return;
    if (!auditMap[key]) auditMap[key] = [];
    auditMap[key].push(entry);
  }
  for (const log of auditLogs) {
    const actor = resolveActor(log);
    for (const target of (log.targetResources || [])) {
      const entry = { action: log.activityDisplayName, timestamp: log.activityDateTime, actor, isHuman: isHumanActor(actor), result: log.result, targetName: target.displayName };
      addToAuditMap(target.id, entry);
      if (target.displayName) addToAuditMap(target.displayName, entry);
      for (const prop of (target.modifiedProperties || [])) {
        if (prop.displayName === "AppId" && prop.newValue) addToAuditMap(prop.newValue.replace(/"/g, "").trim(), entry);
      }
    }
  }

  const apps = appsData.value;
  const chunkSize = 8;
  let appsEnriched = [];

  for (let i = 0; i < apps.length; i += chunkSize) {
    const chunk = apps.slice(i, i + chunkSize);
    const [ownersChunk, signInsChunk] = await Promise.all([
      Promise.all(chunk.map(a => getAppOwners(a.id, token))),
      Promise.all(chunk.map(a => getLastSignIn(a.appId, token))),
    ]);

    for (let j = 0; j < chunk.length; j++) {
      const a = chunk[j];
      a._owners = ownersChunk[j];
      a._lastSignIn = signInsChunk[j];

      // SP correspondente para status e SSO
      const sp = spMap[a.appId] || null;
      a._servicePrincipal = sp;
      a._status = !sp ? "no-sp" : sp.accountEnabled ? "active" : "disabled";
      a._spId = sp ? sp.id : null;

      // SSO info do SP
      if (sp) {
        a._ssoMode = sp.preferredSingleSignOnMode || null;
        a._ssoSettings = sp.samlSingleSignOnSettings || null;
        a._loginUrl = sp.loginUrl || null;
        a._logoutUrl = sp.logoutUrl || null;
        a._spReplyUrls = sp.replyUrls || [];
        a._spTags = sp.tags || [];
        a._publisherName = sp.publisherName || null;
      } else {
        a._ssoMode = null; a._ssoSettings = null; a._loginUrl = null;
        a._logoutUrl = null; a._spReplyUrls = []; a._spTags = [];
        a._publisherName = null;
      }

      // Audit logs
      let appLogs = [...(auditMap[a.id] || []), ...(auditMap[a.appId] || []), ...(auditMap[a.displayName] || [])];
      const seen = {};
      appLogs = appLogs.filter(l => { const k = l.timestamp + l.action; if (seen[k]) return false; seen[k] = true; return true; });
      appLogs.sort((x, y) => new Date(y.timestamp) - new Date(x.timestamp));
      a._auditLogs = appLogs;

      // Criador
      const createActions = ["add application", "add service principal"];
      let createLog = appLogs.find(l => l.isHuman && l.action && createActions.some(ca => l.action.toLowerCase().includes(ca)));
      if (!createLog) createLog = appLogs.find(l => l.action && createActions.some(ca => l.action.toLowerCase().includes(ca)));
      if (!createLog) { const hl = appLogs.filter(l => l.isHuman); if (hl.length) createLog = [...hl].sort((x,y) => new Date(x.timestamp) - new Date(y.timestamp))[0]; }

      a._createdBy = createLog?.isHuman ? createLog.actor : null;
      a._createdBySystem = createLog && !createLog.isHuman ? formatActor(createLog.actor) : null;
    }
    appsEnriched = appsEnriched.concat(chunk);
  }

  // Resolve permissões
  const result = appsEnriched.map(application => {
    const appRoles = [], delegated = [];
    for (const resource of (application.requiredResourceAccess || [])) {
      const rsp = permSpMap[resource.resourceAppId];
      for (const access of resource.resourceAccess) {
        if (access.type === "Role") {
          const roleDef = rsp?.appRoles?.find(r => r.id === access.id);
          appRoles.push({ id: access.id, name: roleDef?.value || null, description: roleDef?.displayName || null, resource: rsp?.displayName || resource.resourceAppId });
        } else {
          const scopeDef = rsp?.oauth2PermissionScopes?.find(s => s.id === access.id);
          delegated.push({ id: access.id, name: scopeDef?.value || null, description: scopeDef?.adminConsentDisplayName || null, resource: rsp?.displayName || resource.resourceAppId });
        }
      }
    }

    const secrets = (application.passwordCredentials || []).map(cred => {
      const now = Date.now();
      const expDate = cred.endDateTime ? new Date(cred.endDateTime) : null;
      const daysToExp = expDate ? Math.ceil((expDate.getTime() - now) / 86400000) : null;
      const status = !expDate ? "sem-expiracao" : daysToExp < 0 ? "expirada" : daysToExp <= 30 ? "expirando" : "ativa";
      return { hint: cred.hint || "***", displayName: cred.displayName || "Secret", startDate: cred.startDateTime, endDate: cred.endDateTime, daysToExp, status };
    });

    const certs = (application.keyCredentials || []).map(k => {
      const expDate = k.endDateTime ? new Date(k.endDateTime) : null;
      const now = Date.now();
      const daysToExp = expDate ? Math.ceil((expDate.getTime() - now) / 86400000) : null;
      const status = !expDate ? "sem-expiracao" : daysToExp < 0 ? "expirado" : daysToExp <= 30 ? "expirando" : "ativo";
      return { displayName: k.displayName || "Certificado", type: k.type, usage: k.usage, endDate: k.endDateTime, daysToExp, status, thumbprint: k.customKeyIdentifier || null };
    });

    const obj = Object.assign({}, application, { appRoles, delegated, secrets, certs });
    obj._writePermissions = analyzeWritePermissions(obj);
    obj._usageAnalysis = buildUsageAnalysis(obj);
    obj._riskLevel = calculateRisk(obj);
    return obj;
  });

  // Apps excluídos enriquecidos minimamente
  const deletedEnriched = deletedApps.map(a => ({
    ...a,
    _status: "deleted",
    _riskLevel: "Low",
    _owners: [],
    _lastSignIn: null,
    _writePermissions: [],
    _usageAnalysis: { workloads: [] },
    appRoles: [], delegated: [], secrets: [], certs: [],
  }));

  return { apps: result, deleted: deletedEnriched };
}

// ─── Detecta mudanças ─────────────────────────────────────────────────────────
function detectChanges(prevApps, currApps) {
  const changes = [], prevMap = {}, currMap = {};
  for (const a of prevApps) prevMap[a.appId] = a;
  for (const a of currApps) currMap[a.appId] = a;

  for (const appId in currMap) {
    if (!prevMap[appId]) {
      const a = currMap[appId];
      changes.push({ type: "novo", severity: "aviso", appId, appName: a.displayName || appId, message: "Nova aplicacao: " + (a.displayName || appId) + (a._createdBy ? " por " + a._createdBy : ""), permChanges: [] });
    }
  }
  for (const appId in prevMap) {
    if (!currMap[appId]) changes.push({ type: "removido", severity: "info", appId, appName: prevMap[appId].displayName || appId, message: "Aplicacao removida: " + (prevMap[appId].displayName || appId), permChanges: [] });
  }
  for (const appId in currMap) {
    if (!prevMap[appId]) continue;
    const prev = prevMap[appId], curr = currMap[appId], permChanges = [];
    const prevRoles = (prev.appRoles || []).map(r => r.id), currRoles = (curr.appRoles || []).map(r => r.id);
    for (const id of currRoles.filter(id => !prevRoles.includes(id))) { const p = curr.appRoles.find(r => r.id === id); permChanges.push({ action: "adicionada", type: "APP", name: p?.name || id, severity: "critico" }); }
    for (const id of prevRoles.filter(id => !currRoles.includes(id))) { const p = prev.appRoles.find(r => r.id === id); permChanges.push({ action: "removida", type: "APP", name: p?.name || id, severity: "melhora" }); }
    const prevDel = (prev.delegated || []).map(r => r.id), currDel = (curr.delegated || []).map(r => r.id);
    for (const id of currDel.filter(id => !prevDel.includes(id))) { const p = curr.delegated.find(r => r.id === id); permChanges.push({ action: "adicionada", type: "DEL", name: p?.name || id, severity: "aviso" }); }
    for (const id of prevDel.filter(id => !currDel.includes(id))) { const p = prev.delegated.find(r => r.id === id); permChanges.push({ action: "removida", type: "DEL", name: p?.name || id, severity: "melhora" }); }
    if ((curr.secrets || []).length > (prev.secrets || []).length) permChanges.push({ action: "adicionada", type: "SECRET", name: "Nova secret", severity: "aviso" });
    if ((curr.secrets || []).length < (prev.secrets || []).length) permChanges.push({ action: "removida", type: "SECRET", name: "Secret removida", severity: "info" });
    if (curr._status !== prev._status) permChanges.push({ action: curr._status === "disabled" ? "desabilitado" : "habilitado", type: "STATUS", name: "Status alterado", severity: curr._status === "disabled" ? "aviso" : "melhora" });
    if (permChanges.length > 0) {
      const worst = permChanges.some(c => c.severity === "critico") ? "critico" : permChanges.some(c => c.severity === "aviso") ? "aviso" : "melhora";
      const recentLog = (curr._auditLogs || []).filter(l => (Date.now() - new Date(l.timestamp).getTime()) < 3600000).sort((a,b) => new Date(b.timestamp) - new Date(a.timestamp))[0];
      changes.push({ type: "permissao", severity: worst, appId, appName: curr.displayName || appId, message: (curr.displayName || appId) + ": " + permChanges.length + " alteracao(es)" + (recentLog?.isHuman ? " por " + recentLog.actor : ""), permChanges });
    }
  }
  return changes;
}

// ─── Rotas OAuth ──────────────────────────────────────────────────────────────
app.get("/", async (req, res) => {
  const authUrl = await cca.getAuthCodeUrl({ scopes: SCOPES, redirectUri: REDIRECT_URI, prompt: "select_account" });
  res.redirect(authUrl);
});

app.get("/callback", async (req, res) => {
  if (!req.query.code) return res.status(400).send("Codigo nao encontrado.");
  try {
    const tokenResponse = await cca.acquireTokenByCode({ code: req.query.code, scopes: SCOPES, redirectUri: REDIRECT_URI });
    const sessionId = Math.random().toString(36).slice(2);
    sessions[sessionId] = { token: tokenResponse.accessToken, tenantId: tokenResponse.tenantId, lastApps: null, lastDeleted: [], changesLast24h: [], snapshots: [], lastUpdated: null };
    res.send(buildLoadingPage(sessionId, tokenResponse.tenantId));
  } catch (err) {
    console.error(err);
    res.status(500).send("<h2>Erro</h2><pre>" + escapeHtml(err.message) + "</pre><a href='/'>Tentar novamente</a>");
  }
});

app.get("/progress/:sessionId", (req, res) => {
  const session = sessions[req.params.sessionId];
  if (!session) return res.status(404).end();
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();
  const send = d => res.write("data: " + JSON.stringify(d) + "\n\n");
  runCollection(req.params.sessionId, send)
    .then(() => { send({ type: "done" }); res.end(); })
    .catch(err => { send({ type: "error", message: err.message }); res.end(); });
});

async function runCollection(sessionId, send) {
  const session = sessions[sessionId];
  send({ type: "step", status: "running", label: "Conectando ao tenant..." });
  await sleep(200);
  send({ type: "step", status: "done", label: "Conectado: " + session.tenantId });
  send({ type: "step", status: "running", label: "Buscando aplicacoes, service principals e itens excluidos..." });
  const { apps, deleted } = await collectApps(session.token);
  send({ type: "step", status: "done", label: apps.length + " apps | " + deleted.length + " excluidos" });
  send({ type: "step", status: "running", label: "Analisando permissoes, status e riscos..." });
  await sleep(200);
  const active = apps.filter(a => a._status === "active");
  const disabled = apps.filter(a => a._status === "disabled");
  send({ type: "step", status: "done", label: active.length + " ativos | " + disabled.length + " desabilitados | " + deleted.length + " excluidos" });
  send({ type: "step", status: "running", label: "Detectando mudancas..." });
  const newChanges = session.lastApps ? detectChanges(session.lastApps, apps) : [];
  const now = Date.now();
  const stamped = newChanges.map(c => ({ ...c, detectedAt: new Date().toISOString() }));
  session.changesLast24h = session.changesLast24h.filter(c => (now - new Date(c.detectedAt).getTime()) < 86400000).concat(stamped);
  send({ type: "step", status: "done", label: newChanges.length + " mudancas | " + session.changesLast24h.length + " nas 24h" });
  session.snapshots.push({ timestamp: new Date().toISOString(), count: apps.length });
  if (session.snapshots.length > 50) session.snapshots.shift();
  session.lastApps = apps;
  session.lastDeleted = deleted;
  session.lastUpdated = new Date();
  send({ type: "step", status: "running", label: "Gerando dashboard..." });
  await sleep(200);
  send({ type: "step", status: "done", label: "Pronto!" });
}

app.get("/refresh/:sessionId", async (req, res) => {
  const session = sessions[req.params.sessionId];
  if (!session) return res.status(404).json({ error: "Sessao nao encontrada" });
  try {
    const { apps, deleted } = await collectApps(session.token);
    const newChanges = session.lastApps ? detectChanges(session.lastApps, apps) : [];
    const now = Date.now();
    const stamped = newChanges.map(c => ({ ...c, detectedAt: new Date().toISOString() }));
    session.changesLast24h = session.changesLast24h.filter(c => (now - new Date(c.detectedAt).getTime()) < 86400000).concat(stamped);
    session.snapshots.push({ timestamp: new Date().toISOString(), count: apps.length });
    if (session.snapshots.length > 50) session.snapshots.shift();
    session.lastApps = apps;
    session.lastDeleted = deleted;
    session.lastUpdated = new Date();
    res.json({ apps, deleted, changesLast24h: session.changesLast24h, newChanges, snapshots: session.snapshots, updatedAt: session.lastUpdated });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── Endpoints de detalhes ────────────────────────────────────────────────────
app.get("/apps/:sessionId/active", (req, res) => {
  const session = sessions[req.params.sessionId];
  if (!session?.lastApps) return res.status(404).json({ error: "Nao encontrado" });
  res.json(session.lastApps.filter(a => a._status === "active"));
});

app.get("/apps/:sessionId/disabled", (req, res) => {
  const session = sessions[req.params.sessionId];
  if (!session?.lastApps) return res.status(404).json({ error: "Nao encontrado" });
  res.json(session.lastApps.filter(a => a._status === "disabled"));
});

app.get("/apps/:sessionId/deleted", (req, res) => {
  const session = sessions[req.params.sessionId];
  if (!session) return res.status(404).json({ error: "Nao encontrado" });
  res.json(session.lastDeleted || []);
});

app.get("/apps/:sessionId/details/:appId", async (req, res) => {
  const session = sessions[req.params.sessionId];
  if (!session?.lastApps) return res.status(404).json({ error: "Nao encontrado" });
  const app = session.lastApps.find(a => a.appId === req.params.appId || a.id === req.params.appId);
  if (!app) return res.status(404).json({ error: "App nao encontrado" });
  try {
    let assignments = [];
    if (app._spId) assignments = await getAppRoleAssignments(app._spId, session.token);
    res.json({ ...app, _assignments: assignments });
  } catch (e) { res.json(app); }
});

app.get("/apps/:sessionId/sso/:appId", async (req, res) => {
  const session = sessions[req.params.sessionId];
  if (!session?.lastApps) return res.status(404).json({ error: "Nao encontrado" });
  const appObj = session.lastApps.find(a => a.appId === req.params.appId || a.id === req.params.appId);
  if (!appObj) return res.status(404).json({ error: "App nao encontrado" });
  try {
    let ssoDetails = { claimsPolicies: [], samlCerts: [] };
    if (appObj._spId) ssoDetails = await getSpSsoDetails(appObj._spId, session.token);
    res.json({ ssoMode: appObj._ssoMode, ssoSettings: appObj._ssoSettings, loginUrl: appObj._loginUrl, logoutUrl: appObj._logoutUrl, replyUrls: appObj._spReplyUrls, redirectUris: getRedirectUris(appObj), ...ssoDetails });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get("/dashboard/:sessionId", (req, res) => {
  const session = sessions[req.params.sessionId];
  if (!session?.lastApps) return res.status(404).send("Dashboard nao encontrado.");
  res.send(buildDashboard(session, req.params.sessionId));
});

// ─── Loading Page ─────────────────────────────────────────────────────────────
function buildLoadingPage(sessionId, tenantId) {
  return `<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><title>Carregando...</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:"SF Mono",Monaco,monospace;background:#060a0f;color:#c8d8e8;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#0d1520;border:1px solid #1a2840;border-radius:16px;padding:48px 40px;max-width:580px;width:100%}
h1{font-size:18px;color:#4fc3f7;margin-bottom:4px;letter-spacing:2px;text-transform:uppercase}
.tid{font-size:11px;color:#3a5068;margin-bottom:32px}.bar-wrap{height:2px;background:#0a1525;border-radius:2px;margin-bottom:32px}
.bar{height:100%;background:linear-gradient(90deg,#0ea5e9,#38bdf8,#7dd3fc);border-radius:2px;width:0%;transition:width .8s}
.steps{display:flex;flex-direction:column;gap:6px}
.step{display:flex;align-items:center;gap:10px;padding:10px 14px;border-radius:8px;background:#060d16;font-size:12px;color:#3a5068;border:1px solid transparent;transition:all .4s}
.step.running{background:#061828;border-color:#0ea5e9;color:#7dd3fc}.step.done{background:#061a10;border-color:#22c55e40;color:#4ade80}.step.error{background:#1a0606;border-color:#ef444440;color:#f87171}
.icon{width:16px;height:16px;display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:11px}
.spinner{width:12px;height:12px;border:1.5px solid #1a3050;border-top-color:#0ea5e9;border-radius:50%;animation:spin .7s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}
.reveal{text-align:center;margin-top:36px;display:none}.big{font-size:64px;font-weight:700;color:#0ea5e9;letter-spacing:-2px}
.sub{font-size:12px;color:#3a5068;margin-top:4px;letter-spacing:2px;text-transform:uppercase}
.btn{display:inline-block;margin-top:24px;padding:12px 32px;background:linear-gradient(135deg,#0369a1,#0ea5e9);color:#fff;border-radius:8px;text-decoration:none;font-weight:600;font-size:13px;text-transform:uppercase}
</style></head><body>
<div class="card"><h1>ENTERPRISE APPLICATIONS MONITOR</h1><div class="tid">${tenantId}</div>
<div class="bar-wrap"><div class="bar" id="bar"></div></div>
<div class="steps" id="steps"></div>
<div class="reveal" id="reveal"><div class="big">&#10003;</div><div class="sub">analise concluida</div><a class="btn" id="btn" href="#">ABRIR MONITOR</a></div></div>
<script>
var total=5,done=0,active=null;
var stepsEl=document.getElementById("steps"),bar=document.getElementById("bar");
var es=new EventSource("/progress/${sessionId}");
es.onmessage=function(e){
  var d=JSON.parse(e.data);
  if(d.type==="step"){
    if(d.status==="running"){
      if(active){active.className="step done";active.querySelector(".icon").innerHTML="&#10003;";done++;bar.style.width=Math.min(92,Math.round(done/total*100))+"%";}
      var el=document.createElement("div");el.className="step running";
      el.innerHTML="<div class='icon'><div class='spinner'></div></div><span>"+d.label+"</span>";
      stepsEl.appendChild(el);el.scrollIntoView({behavior:"smooth"});active=el;
    }else if(d.status==="done"&&active){active.querySelector("span").textContent=d.label;}
  }
  if(d.type==="done"){
    if(active){active.className="step done";active.querySelector(".icon").innerHTML="&#10003;";}
    bar.style.width="100%";es.close();
    document.getElementById("btn").href="/dashboard/${sessionId}";
    document.getElementById("reveal").style.display="block";
  }
  if(d.type==="error"){
    if(active){active.className="step error";active.querySelector(".icon").innerHTML="&#10007;";}
    var err=document.createElement("div");err.className="step error";
    err.innerHTML="<div class='icon'>&#10007;</div><span>Erro: "+d.message+"</span>";
    stepsEl.appendChild(err);es.close();
  }
};
</script></body></html>`;
}

// ─── Dashboard ────────────────────────────────────────────────────────────────
function buildDashboard(session, sessionId) {
  const apps = session.lastApps;
  const deleted = session.lastDeleted || [];
  const changes24h = session.changesLast24h || [];
  const riskColor = { critico: "#ef4444", alto: "#f59e0b", normal: "#4ade80" };

  const allApps         = apps;
  const activeApps      = apps.filter(a => a._status === "active");
  const disabledApps    = apps.filter(a => a._status === "disabled");
  const riskyApps       = apps.filter(a => a.appRoles && a.appRoles.length > 0);
  const writeApps       = apps.filter(a => a._writePermissions && a._writePermissions.length > 0);
  const writeGroupsApps = apps.filter(a => getWriteCategories(a).includes("groups"));
  const writeUsersApps  = apps.filter(a => getWriteCategories(a).includes("users"));
  const writeEmailApps  = apps.filter(a => getWriteCategories(a).includes("email"));
  const writeFilesApps  = apps.filter(a => getWriteCategories(a).includes("files"));
  const recentApps      = apps.filter(a => a.createdDateTime && (Date.now() - new Date(a.createdDateTime).getTime()) / 86400000 <= 30);
  const noOwnerApps     = apps.filter(a => !a._owners || a._owners.length === 0);
  const appsWithSecrets = apps.filter(a => a.secrets && a.secrets.length > 0);
  const expSecrets      = apps.filter(a => (a.secrets || []).some(s => s.status === "expirada" || s.status === "expirando"));
  const criticalApps    = apps.filter(a => a._riskLevel === "Critical");
  const ssoApps         = apps.filter(a => a._ssoMode && a._ssoMode !== "none");

  const appDatasets = {
    all: allApps, active: activeApps, disabled: disabledApps, deleted,
    risky: riskyApps, write: writeApps,
    writegroups: writeGroupsApps, writeusers: writeUsersApps,
    writeemail: writeEmailApps, writefiles: writeFilesApps,
    critical: criticalApps, recent: recentApps,
    noowner: noOwnerApps, secrets: appsWithSecrets, expsecrets: expSecrets, sso: ssoApps,
  };

  const RISK_TOOLTIPS = {
    "Mail.ReadWrite":"CRITICO — Le e modifica todos os e-mails da org.","Mail.Send":"CRITICO — Envia e-mails como qualquer usuario.","Files.ReadWrite.All":"CRITICO — Le e escreve em todos os arquivos.","Directory.ReadWrite.All":"CRITICO — Le e modifica todo o diretorio Azure AD.","User.ReadWrite.All":"CRITICO — Cria, edita e deleta qualquer usuario.","RoleManagement.ReadWrite.Directory":"CRITICO — Atribui e remove roles de administrador.","Application.ReadWrite.All":"CRITICO — Cria e modifica qualquer aplicacao.","Group.ReadWrite.All":"CRITICO — Cria e modifica todos os grupos.","full_access_as_app":"CRITICO — Acesso total ao Exchange Online.","Mail.Read":"ALTO — Le todos os e-mails.","Files.Read.All":"ALTO — Le todos os arquivos.","User.Read.All":"ALTO — Le dados de todos os usuarios.","Directory.Read.All":"ALTO — Le todo o diretorio AD.","AuditLog.Read.All":"ALTO — Acessa os logs de auditoria.","Policy.Read.All":"ALTO — Le todas as politicas de seguranca.","IdentityRiskyUser.Read.All":"ALTO — Le dados de usuarios de risco.",
  };

  function getPermTooltip(name, description, risk) {
    if (!name) return description || "Permissao nao identificada";
    for (const key in RISK_TOOLTIPS) { if (name === key || name.startsWith(key)) return RISK_TOOLTIPS[key]; }
    return (risk === "critico" ? "CRITICO" : risk === "alto" ? "ALTO" : "NORMAL") + " — " + (description || name);
  }

  function getSuggestions(a) {
    const name = (a.displayName || "").toLowerCase();
    const currentNames = (a.appRoles || []).concat(a.delegated || []).map(p => p.name || "");
    const suggestions = { add: [], remove: [] };
    ["Directory.ReadWrite.All","User.ReadWrite.All","RoleManagement.ReadWrite.Directory","Application.ReadWrite.All","full_access_as_app"].forEach(perm => {
      if (currentNames.includes(perm)) suggestions.remove.push({ name: perm, reason: "Permissao de escrita critica. Substitua pela versao Read-only." });
    });
    if ((name.includes("mail")||name.includes("email"))&&!currentNames.includes("Mail.Read")) suggestions.add.push({ name:"Mail.Read", reason:"Apps de e-mail geralmente precisam ler mensagens." });
    if ((name.includes("mail")||name.includes("email"))&&currentNames.includes("Mail.ReadWrite")) suggestions.remove.push({ name:"Mail.ReadWrite", reason:"Use Mail.Read se o app apenas le e-mails." });
    if ((name.includes("user")||name.includes("directory"))&&!currentNames.includes("User.Read.All")) suggestions.add.push({ name:"User.Read.All", reason:"Apps de diretorio precisam desta permissao." });
    if ((name.includes("report")||name.includes("monitor")||name.includes("security"))&&!currentNames.includes("AuditLog.Read.All")) suggestions.add.push({ name:"AuditLog.Read.All", reason:"Apps de monitoramento precisam ler logs." });
    if ((name.includes("file")||name.includes("sharepoint"))&&!currentNames.includes("Files.Read.All")) suggestions.add.push({ name:"Files.Read.All", reason:"Apps de documentos precisam ler arquivos." });
    if ((name.includes("file")||name.includes("sharepoint"))&&currentNames.includes("Files.ReadWrite.All")) suggestions.remove.push({ name:"Files.ReadWrite.All", reason:"Use Files.Read.All se o app apenas le arquivos." });
    if (currentNames.filter(n=>n).length === 0) suggestions.add.push({ name:"User.Read", reason:"A maioria dos apps precisa ao menos desta permissao." });
    return suggestions;
  }

  function buildAppRow(a, tabPrefix) {
    tabPrefix = tabPrefix || "all";
    const isDeleted = a._status === "deleted";
    const uid = (tabPrefix + "-" + (a.appId || a.id)).replace(/[^a-zA-Z0-9_-]/g, "_");
    const allPerms = (a.appRoles || []).concat(a.delegated || []);
    const isRisky = a.appRoles && a.appRoles.length > 0;
    const writePerms = a._writePermissions || [];
    const writeCategories = getWriteCategories(a);
    const ownerList = a._owners || [];
    const owners = ownerList.map(o => escapeHtml(o.displayName || o.userPrincipalName || o.mail || "?"));
    const ownersStr = owners.length > 0 ? owners.join(", ") : '<span style="color:#ef4444">Sem owner</span>';
    const createdBy = a._createdBy ? escapeHtml(a._createdBy) : a._createdBySystem ? '<span style="color:#3a5068;font-size:10px">via ' + escapeHtml(a._createdBySystem) + '</span>' : '<span style="color:#2a4060;font-size:10px">Anterior a 30 dias</span>';
    const lastUsed = fmtLastUsed(a._lastSignIn);
    const lastUsedCell = '<span style="color:' + lastUsed.color + ';font-family:\'JetBrains Mono\',monospace;font-size:11px" title="' + escapeHtml(lastUsed.full) + '">' + lastUsed.text + '</span>';
    const riskBadgeColor = a._riskLevel === "Critical" ? "#ef4444" : a._riskLevel === "High" ? "#f59e0b" : a._riskLevel === "Medium" ? "#a78bfa" : "#4ade80";
    const redirectUris = getRedirectUris(a);
    const redirectUriTypes = getRedirectUriTypes(a);
    const notesHtml = a.notes ? '<div class="notes-box"><span class="notes-label">Notas:</span> ' + escapeHtml(a.notes) + '</div>' : "";

    // Status badge
    const statusBadge = a._status === "active"
      ? '<span class="status-badge status-active">Ativo</span>'
      : a._status === "disabled"
        ? '<span class="status-badge status-disabled">Desabilitado</span>'
        : a._status === "deleted"
          ? '<span class="status-badge status-deleted">Excluido</span>'
          : '<span class="status-badge status-nosp">Sem SP</span>';

    // SSO badge
    const ssoMode = a._ssoMode;
    const ssoBadge = ssoMode && ssoMode !== "none"
      ? '<span class="sso-badge">SSO:' + escapeHtml(ssoMode.toUpperCase()) + '</span>'
      : '';

    if (isDeleted) {
      return '<tr class="ar" style="opacity:.6">' +
        '<td><div class="app-name">' + escapeHtml(a.displayName || "—") + statusBadge + '</div></td>' +
        '<td>' + fmtDate(a.createdDateTime) + '</td>' +
        '<td>' + fmtDate(a.deletedDateTime) + '</td>' +
        '<td><span style="color:#3a5068">—</span></td>' +
        '<td><span style="color:#3a5068">—</span></td>' +
        '<td><span style="color:#3a5068">—</span></td>' +
        '</tr>';
    }

    // Permissões
    const permsHtml = allPerms.length === 0
      ? '<span style="color:#3a5068;font-size:11px">Nenhuma permissao registrada</span>'
      : allPerms.map(p => {
          const risk = classifyPerm(p.name);
          const isApp = !!(a.appRoles || []).find(r => r.id === p.id);
          const label = escapeHtml(permLabel(p));
          const tooltip = escapeHtml(getPermTooltip(p.name, p.description, risk));
          const isWrite = !!(p.name || "").toLowerCase().match(/write|send|manage|full_access/);
          return '<div class="pb-wrap"><span class="pb" style="border-color:' + riskColor[risk] + ';color:' + riskColor[risk] + (isWrite ? ';font-weight:700' : '') + '"><span class="pt">' + (isApp ? "APP" : "DEL") + '</span> ' + label + (isWrite ? ' &#9999;' : '') + '</span><div class="pb-tooltip">' + tooltip + '</div></div>';
        }).join("");

    // Sugestões
    const sugg = getSuggestions(a);
    const suggHtml = sugg.add.length === 0 && sugg.remove.length === 0
      ? '<div class="sugg-ok">Permissoes parecem adequadas para este app.</div>'
      : (sugg.remove.length > 0 ? '<div class="sugg-section"><div class="sugg-title" style="color:#ef4444">Considere REMOVER:</div>' + sugg.remove.map(s => '<div class="sugg-item sugg-remove"><code>' + s.name + '</code><span>' + s.reason + '</span></div>').join("") + '</div>' : "")
        + (sugg.add.length > 0 ? '<div class="sugg-section"><div class="sugg-title" style="color:#4ade80">Considere ADICIONAR:</div>' + sugg.add.map(s => '<div class="sugg-item sugg-add"><code>' + s.name + '</code><span>' + s.reason + '</span></div>').join("") + '</div>' : "");

    // Secrets
    const secretsHtml = (a.secrets && a.secrets.length > 0)
      ? '<div class="secrets-wrap">' + a.secrets.map(s => {
          const sc = s.status === "expirada" ? "#ef4444" : s.status === "expirando" ? "#f59e0b" : s.status === "sem-expiracao" ? "#94a3b8" : "#4ade80";
          const sl = s.status === "expirada" ? "EXPIRADA" : s.status === "expirando" ? "EXPIRA EM " + s.daysToExp + "d" : s.status === "sem-expiracao" ? "SEM EXPIRACAO" : "ATIVA";
          return '<div class="secret-item"><span class="secret-name">&#128273; ' + escapeHtml(s.displayName) + ' (' + s.hint + '***)</span><span class="secret-dates">Criada: ' + fmtDateOnly(s.startDate) + ' Expira: ' + fmtDateOnly(s.endDate) + '</span><span class="secret-status" style="color:' + sc + '">' + sl + '</span></div>';
        }).join("") + '</div>'
      : '<span style="color:#3a5068;font-size:12px">Nenhuma secret registrada</span>';

    // Certificados
    const certsHtml = (a.certs && a.certs.length > 0)
      ? '<div class="secrets-wrap">' + a.certs.map(c => {
          const cc = c.status === "expirado" ? "#ef4444" : c.status === "expirando" ? "#f59e0b" : "#4ade80";
          const cl = c.status === "expirado" ? "EXPIRADO" : c.status === "expirando" ? "EXPIRA EM " + c.daysToExp + "d" : "ATIVO";
          return '<div class="secret-item"><span class="secret-name">&#128190; ' + escapeHtml(c.displayName) + ' (' + escapeHtml(c.type || "") + '/' + escapeHtml(c.usage || "") + ')</span><span class="secret-dates">Expira: ' + fmtDateOnly(c.endDate) + '</span><span class="secret-status" style="color:' + cc + '">' + cl + '</span></div>';
        }).join("") + '</div>'
      : '<span style="color:#3a5068;font-size:12px">Nenhum certificado registrado</span>';

    // Atividade
    const recentLogs = (a._auditLogs || []).slice(0, 5);
    const auditHtml = recentLogs.length > 0
      ? '<div class="audit-wrap"><div class="audit-title">Atividade recente (ultimos 30 dias):</div>' + recentLogs.map(l => {
          const ad = l.isHuman ? escapeHtml(l.actor) : (formatActor(l.actor) || "Sistema");
          const ac = l.isHuman ? "#38bdf8" : "#3a5068";
          return '<div class="audit-item"><span class="audit-action">' + escapeHtml(l.action) + '</span><span class="audit-actor" style="color:' + ac + '">por ' + ad + '</span><span class="audit-time">' + fmtDate(l.timestamp) + '</span></div>';
        }).join("") + '</div>'
      : '<span style="color:#3a5068;font-size:12px">Nenhuma atividade nos ultimos 30 dias</span>';

    // Último Uso
    const signIns = a._lastSignIn;
    let lastUsoHtml = "";
    if (signIns && signIns.length > 0) {
      const last = signIns[0];
      const daysAgo = Math.floor((Date.now() - new Date(last.createdDateTime).getTime()) / 86400000);
      const stColor = daysAgo > 90 ? "#ef4444" : daysAgo > 30 ? "#f59e0b" : "#4ade80";
      const stLabel = daysAgo === 0 ? "Hoje" : daysAgo === 1 ? "Ontem" : daysAgo + " dias atras";
      const isSP = !!(last.signInEventTypes && last.signInEventTypes.some(t => t === "servicePrincipal"));
      lastUsoHtml = '<div class="audit-wrap">' +
        '<div class="audit-item"><span class="audit-action" style="color:#c8d8e8;font-weight:600">Ultimo uso detectado</span><span style="color:' + stColor + ';font-size:11px">' + stLabel + '</span></div>' +
        '<div class="audit-item"><span class="audit-action">Data e hora exata</span><span class="audit-time">' + fmtDate(last.createdDateTime) + '</span></div>' +
        '<div class="audit-item"><span class="audit-action">Tipo</span><span style="color:#a78bfa;font-size:11px">' + (isSP ? "Service Principal" : "Sign-in de usuario") + '</span></div>' +
        (last.userDisplayName || last.userPrincipalName ? '<div class="audit-item"><span class="audit-action">Usuario</span><span style="color:#38bdf8;font-size:11px">' + escapeHtml(last.userDisplayName || last.userPrincipalName) + '</span></div>' : '') +
        '<div class="audit-item"><span class="audit-action">IP</span><span style="color:#94a3b8;font-size:11px;font-family:monospace">' + escapeHtml(last.ipAddress || "N/A") + '</span></div>' +
        (last.clientAppUsed ? '<div class="audit-item"><span class="audit-action">Cliente</span><span style="color:#94a3b8;font-size:11px">' + escapeHtml(last.clientAppUsed) + '</span></div>' : '') +
        '<div class="audit-item"><span class="audit-action">Recurso</span><span style="color:#94a3b8;font-size:11px">' + escapeHtml(last.resourceDisplayName || "N/A") + '</span></div>' +
        (last.location ? '<div class="audit-item"><span class="audit-action">Local</span><span style="color:#94a3b8;font-size:11px">' + escapeHtml((last.location.city || "") + (last.location.countryOrRegion ? ", " + last.location.countryOrRegion : "")) + '</span></div>' : '') +
        (signIns.length > 1 ? '<div class="audit-title" style="margin-top:10px">Acessos anteriores:</div>' + signIns.slice(1).map(si => { const siSP = !!(si.signInEventTypes && si.signInEventTypes.some(t => t === "servicePrincipal")); return '<div class="audit-item"><span class="audit-action">' + fmtDate(si.createdDateTime) + '</span><span style="color:#3a5068;font-size:10px">' + (siSP ? "SP" : escapeHtml(si.userDisplayName || si.userPrincipalName || "—")) + ' | ' + escapeHtml(si.ipAddress || "—") + '</span></div>'; }).join("") : '') +
        '</div>';
    } else {
      lastUsoHtml = '<div class="audit-wrap"><div class="audit-item"><span class="audit-action">Nenhum sign-in encontrado</span><span style="color:#ef4444;font-size:11px">App possivelmente inativo</span></div><div style="font-size:11px;color:#3a5068;padding:8px;line-height:1.6">Sign-ins client_credentials nao aparecem nos logs padrao.</div></div>';
    }

    // Owner detalhado
    let ownerHtml = "";
    if (ownerList.length === 0) {
      ownerHtml = '<div class="audit-wrap"><div class="audit-item" style="border-left:2px solid #ef4444;padding-left:10px"><span class="audit-action" style="color:#ef4444;font-weight:600">Nenhum owner cadastrado</span></div><div style="font-size:11px;color:#3a5068;padding:8px;line-height:1.6;background:#0a1525;border-radius:4px;margin-top:4px">Apps sem owner sao risco de seguranca. Adicione ao menos um responsavel.</div></div>';
    } else {
      const avatarColors = ["#0ea5e9","#38bdf8","#a78bfa","#4ade80","#f59e0b","#60a5fa"];
      ownerHtml = '<div class="audit-wrap"><div class="audit-title">' + ownerList.length + ' owner(s) cadastrado(s):</div>' +
        ownerList.map((o, idx) => {
          const name = o.displayName || o.userPrincipalName || o.mail || "Owner desconhecido";
          const email = o.mail || o.userPrincipalName || "";
          const initials = name.split(" ").map(w => w[0] || "").slice(0,2).join("").toUpperCase();
          const color = avatarColors[idx % avatarColors.length];
          return '<div class="owner-card"><div class="owner-avatar" style="background:' + color + '20;border:1px solid ' + color + '40;color:' + color + '">' + escapeHtml(initials || "?") + '</div><div class="owner-info"><div class="owner-name">' + escapeHtml(name) + '</div>' +
            (email ? '<div class="owner-detail"><span class="owner-label">E-mail</span><a href="mailto:' + escapeHtml(email) + '" style="color:#60a5fa;font-size:10px;text-decoration:none">' + escapeHtml(email) + '</a></div>' : '') +
            (o.jobTitle ? '<div class="owner-detail"><span class="owner-label">Cargo</span><span class="owner-value">' + escapeHtml(o.jobTitle) + '</span></div>' : '') +
            (o.department ? '<div class="owner-detail"><span class="owner-label">Depto</span><span class="owner-value">' + escapeHtml(o.department) + '</span></div>' : '') +
            (o.id ? '<div class="owner-detail"><span class="owner-label">Object ID</span><span style="color:#3a5068;font-size:9px;font-family:monospace">' + escapeHtml(o.id) + '</span></div>' : '') +
            '</div></div>';
        }).join("") +
        '<div class="audit-title" style="margin-top:10px">Boas praticas:</div>' +
        '<div class="audit-item"><span style="color:' + (ownerList.length >= 2 ? "#4ade80" : "#f59e0b") + ';font-size:10px">' + (ownerList.length >= 2 ? "&#10003; Multiplos owners — boa redundancia" : "&#9888; Apenas 1 owner — recomenda-se adicionar um segundo") + '</span></div>' +
        '</div>';
    }

    // Onde é usado
    const usage = a._usageAnalysis || { workloads: [] };
    const writeCatLabels = { groups:"Grupos", users:"Usuarios", email:"E-mail", files:"Arquivos/SharePoint", directory:"Diretorio", apps:"Aplicacoes" };
    const usoHtml = '<div class="audit-wrap">' +
      '<div class="audit-title">Workloads identificados:</div>' +
      '<div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:14px">' + (usage.workloads.length > 0 ? usage.workloads.map(w => '<span class="wb">' + escapeHtml(w) + '</span>').join("") : '<span style="color:#3a5068">Nenhum workload identificado</span>') + '</div>' +
      '<div class="audit-title">Categorias com escrita:</div>' +
      '<div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:14px">' + (writeCategories.length > 0 ? writeCategories.map(c => '<span class="wc-badge">' + (writeCatLabels[c] || c) + '</span>').join("") : '<span style="color:#4ade80;font-size:12px">Nenhuma escrita detectada</span>') + '</div>' +
      '<div class="audit-title">Permissoes de escrita:</div>' +
      (writePerms.length > 0 ? writePerms.map(p => { const risk = classifyPerm(p.name); return '<div class="audit-item"><span class="audit-action" style="color:' + riskColor[risk] + ';font-weight:600">&#9999; ' + escapeHtml(permLabel(p)) + '</span><span style="color:#3a5068;font-size:10px">' + escapeHtml(p.resource || "") + '</span></div>'; }).join("") : '<div class="audit-item"><span style="color:#4ade80">Nenhuma permissao de escrita</span></div>') +
      '</div>';

    // URLs
    const urlSections = [];
    if (a.web?.redirectUris?.length > 0) urlSections.push({ type: "Web", uris: a.web.redirectUris, logoutUrl: a.web.logoutUrl || null });
    if (a.spa?.redirectUris?.length > 0) urlSections.push({ type: "SPA", uris: a.spa.redirectUris, logoutUrl: null });
    if (a.publicClient?.redirectUris?.length > 0) urlSections.push({ type: "Mobile/Desktop", uris: a.publicClient.redirectUris, logoutUrl: null });
    const urlsHtml = urlSections.length === 0
      ? '<div class="audit-wrap"><div class="audit-item"><span class="audit-action">Nenhuma Redirect URI cadastrada</span></div></div>'
      : '<div class="audit-wrap">' + urlSections.map(sec =>
          '<div class="audit-title">' + escapeHtml(sec.type) + ':</div>' +
          sec.uris.map(uri => {
            const isHttp = uri.startsWith("http://") && !uri.includes("localhost") && !uri.includes("127.0.0.1");
            const uriColor = isHttp ? "#f59e0b" : "#60a5fa";
            return '<div class="audit-item"><span style="color:' + uriColor + ';font-size:10px;font-family:monospace;word-break:break-all">' + escapeHtml(uri) + '</span>' + (isHttp ? ' <span style="color:#f59e0b;font-size:9px">[HTTP-inseguro]</span>' : '') + '</div>';
          }).join("") +
          (sec.logoutUrl ? '<div class="audit-item"><span class="audit-action">Logout URL</span><span style="color:#94a3b8;font-size:10px;font-family:monospace">' + escapeHtml(sec.logoutUrl) + '</span></div>' : '')
        ).join("") + '</div>';

    // SSO
    const ssoModeLabels = { saml: "SAML 2.0", oidc: "OIDC / OAuth 2.0", password: "Password-based", linked: "Linked", none: "Nenhum", notSet: "Nao configurado" };
    const ssoLabel = a._ssoMode ? (ssoModeLabels[a._ssoMode] || a._ssoMode.toUpperCase()) : "Nao configurado";
    const ssoEnabled = a._ssoMode && a._ssoMode !== "none";
    const ssoHtml = '<div class="audit-wrap">' +
      '<div class="audit-item"><span class="audit-action" style="color:#c8d8e8;font-weight:600">Status SSO</span>' +
        (ssoEnabled ? '<span style="color:#4ade80;font-weight:700">&#10003; Habilitado</span>' : '<span style="color:#3a5068">Nao configurado</span>') +
      '</div>' +
      '<div class="audit-item"><span class="audit-action">Tipo</span><span style="color:' + (ssoEnabled ? "#a78bfa" : "#3a5068") + ';font-weight:' + (ssoEnabled ? "700" : "normal") + '">' + escapeHtml(ssoLabel) + '</span></div>' +
      (a._loginUrl ? '<div class="audit-item"><span class="audit-action">Sign-on URL</span><span style="color:#60a5fa;font-size:10px;font-family:monospace;word-break:break-all">' + escapeHtml(a._loginUrl) + '</span></div>' : '') +
      (a._logoutUrl ? '<div class="audit-item"><span class="audit-action">Logout URL</span><span style="color:#60a5fa;font-size:10px;font-family:monospace;word-break:break-all">' + escapeHtml(a._logoutUrl) + '</span></div>' : '') +
      (a._spReplyUrls && a._spReplyUrls.length > 0 ? '<div class="audit-title" style="margin-top:8px">Reply URLs:</div>' + a._spReplyUrls.map(u => '<div class="audit-item"><span style="color:#60a5fa;font-size:10px;font-family:monospace;word-break:break-all">' + escapeHtml(u) + '</span></div>').join("") : '') +
      (a._ssoMode === "saml" && a._ssoSettings ? '<div class="audit-title" style="margin-top:8px">SAML Settings:</div><div class="audit-item"><span class="audit-action">Entity ID</span><span style="color:#94a3b8;font-size:10px;font-family:monospace">' + escapeHtml(a._ssoSettings.relayState || "—") + '</span></div>' : '') +
      (!ssoEnabled ? '<div style="margin-top:10px;padding:10px;background:#0a1525;border-radius:6px;font-size:11px;color:#3a5068;line-height:1.6">Para configurar SSO, acesse o portal Entra ID > Enterprise Applications > este app > Single sign-on.</div>' : '') +
      '</div>';

    // Detalhes do app
    const sp = a._servicePrincipal;
    const statusColor = a._status === "active" ? "#4ade80" : a._status === "disabled" ? "#f59e0b" : "#ef4444";
    const detailsHtml = '<div class="audit-wrap">' +
      '<div class="audit-title">Identificacao:</div>' +
      '<div class="audit-item"><span class="audit-action">Nome</span><span style="color:#c8d8e8;font-weight:600">' + escapeHtml(a.displayName || "—") + '</span></div>' +
      '<div class="audit-item"><span class="audit-action">Application ID</span><span style="color:#60a5fa;font-size:10px;font-family:monospace">' + escapeHtml(a.appId || "—") + '</span></div>' +
      '<div class="audit-item"><span class="audit-action">Object ID</span><span style="color:#94a3b8;font-size:10px;font-family:monospace">' + escapeHtml(a.id || "—") + '</span></div>' +
      '<div class="audit-item"><span class="audit-action">Tenant</span><span style="color:#94a3b8;font-size:10px;font-family:monospace">' + escapeHtml(session.tenantId || "—") + '</span></div>' +
      '<div class="audit-item"><span class="audit-action">Publisher</span><span style="color:#94a3b8">' + escapeHtml(a._publisherName || a.verifiedPublisher?.displayName || a.publisherDomain || "—") + '</span></div>' +
      '<div class="audit-item"><span class="audit-action">Tipo SP</span><span style="color:#94a3b8">' + escapeHtml(sp?.servicePrincipalType || "—") + '</span></div>' +
      '<div class="audit-item"><span class="audit-action">Sign-in Audience</span><span style="color:#94a3b8">' + escapeHtml(a.signInAudience || "—") + '</span></div>' +
      '<div class="audit-item"><span class="audit-action">Criado em</span><span style="color:#94a3b8">' + fmtDate(a.createdDateTime) + '</span></div>' +
      (a.tags && a.tags.length > 0 ? '<div class="audit-item"><span class="audit-action">Tags</span><div style="display:flex;flex-wrap:wrap;gap:4px">' + a.tags.map(t => '<span style="background:#1a2840;color:#94a3b8;padding:1px 6px;border-radius:4px;font-size:9px">' + escapeHtml(t) + '</span>').join("") + '</div></div>' : '') +
      '<div class="audit-title" style="margin-top:10px">Status:</div>' +
      '<div class="audit-item"><span class="audit-action">Estado</span><span style="color:' + statusColor + ';font-weight:700">' + escapeHtml(a._status === "active" ? "Ativo" : a._status === "disabled" ? "Desabilitado" : "Sem Service Principal") + '</span></div>' +
      '<div class="audit-item"><span class="audit-action">Ultimo sign-in</span><span style="color:' + lastUsed.color + '">' + lastUsed.text + '</span></div>' +
      '<div class="audit-title" style="margin-top:10px">Seguranca:</div>' +
      '<div class="audit-item"><span class="audit-action">Secrets</span><span style="color:' + ((a.secrets||[]).some(s=>s.status==="expirada"||s.status==="expirando") ? "#ef4444" : "#4ade80") + '">' + (a.secrets||[]).length + ' secret(s)' + ((a.secrets||[]).some(s=>s.status==="expirada"||s.status==="expirando") ? " &#9888; expirando" : "") + '</span></div>' +
      '<div class="audit-item"><span class="audit-action">Certificados</span><span style="color:' + ((a.certs||[]).some(c=>c.status==="expirado"||c.status==="expirando") ? "#ef4444" : "#4ade80") + '">' + (a.certs||[]).length + ' cert(s)' + ((a.certs||[]).some(c=>c.status==="expirado"||c.status==="expirando") ? " &#9888; expirando" : "") + '</span></div>' +
      '<div class="audit-item"><span class="audit-action">Owners</span><span style="color:' + (ownerList.length === 0 ? "#ef4444" : "#4ade80") + '">' + (ownerList.length === 0 ? "Sem owner (+risco)" : ownerList.length + " owner(s)") + '</span></div>' +
      '<div class="audit-item"><span class="audit-action">Nivel de Risco</span><span style="color:' + riskBadgeColor + ';font-weight:700">' + a._riskLevel + '</span></div>' +
      '</div>';

    // Risco
    const riscoHtml = '<div class="audit-wrap">' +
      '<div class="audit-item"><span class="audit-action" style="color:#c8d8e8;font-weight:600">Classificacao</span><span style="color:' + riskBadgeColor + ';font-family:\'JetBrains Mono\',monospace;font-weight:700;font-size:14px">' + a._riskLevel + '</span></div>' +
      '<div class="audit-item"><span class="audit-action">Write permissions</span><span style="color:' + (writePerms.length > 0 ? "#f59e0b" : "#4ade80") + '">' + writePerms.length + ' permissao(oes)</span></div>' +
      '<div class="audit-item"><span class="audit-action">Owner</span><span style="color:' + (ownerList.length === 0 ? "#ef4444" : "#4ade80") + '">' + (ownerList.length === 0 ? "Sem owner (+20pts)" : ownerList.length + " owner(s)") + '</span></div>' +
      '<div class="audit-item"><span class="audit-action">Status</span><span style="color:' + (a._status === "disabled" ? "#f59e0b" : "#4ade80") + '">' + (a._status === "active" ? "Ativo" : "Desabilitado (+5pts)") + '</span></div>' +
      '<div class="audit-item"><span class="audit-action">Ultimo uso</span><span style="color:' + lastUsed.color + '">' + lastUsed.text + (lastUsed.full !== "Nenhum sign-in detectado" ? " — " + lastUsed.full : "") + '</span></div>' +
      (writePerms.length > 0 ? '<div class="audit-title" style="margin-top:10px">Permissoes criticas:</div>' + writePerms.map(p => { const risk = classifyPerm(p.name); return '<div class="audit-item"><span style="color:' + riskColor[risk] + ';font-weight:600">' + escapeHtml(permLabel(p)) + '</span><span style="color:#3a5068;font-size:10px">' + escapeHtml(getPermTooltip(p.name, p.description, risk).substring(0, 70)) + '...</span></div>'; }).join("") : '<div class="audit-item"><span style="color:#4ade80">Nenhuma permissao critica</span></div>') +
      '</div>';

    return '<tr class="ar' + (isRisky ? " risky" : "") + '" onclick="toggle(\'rx-' + uid + '\')">' +
      '<td><div class="app-name">' + escapeHtml(a.displayName || "—") +
        statusBadge + ssoBadge +
        (isRisky ? '<span class="risk-badge">App Perm</span>' : '') +
        (writePerms.length > 0 ? '<span class="write-badge">W</span>' : '') +
        (writeCategories.includes("groups") ? '<span class="wcat-badge">Groups</span>' : '') +
        (writeCategories.includes("users") ? '<span class="wcat-badge">Users</span>' : '') +
        (writeCategories.includes("email") ? '<span class="wcat-badge">Mail</span>' : '') +
        (writeCategories.includes("files") ? '<span class="wcat-badge">Files</span>' : '') +
        ((a.secrets && a.secrets.length > 0) ? '<span class="secret-badge">' + a.secrets.length + 's</span>' : '') +
        (a.notes ? '<span class="notes-badge">n</span>' : '') +
        (redirectUris.length > 0 ? '<span class="url-badge" title="' + escapeHtml(redirectUris.join(", ")) + '">' + redirectUris.length + 'URL</span>' : '') +
        '<span class="rl-badge" style="border-color:' + riskBadgeColor + ';color:' + riskBadgeColor + '">' + a._riskLevel + '</span>' +
      '</div></td>' +
      '<td>' + fmtDate(a.createdDateTime) + '</td>' +
      '<td>' + lastUsedCell + '</td>' +
      '<td>' + createdBy + '</td>' +
      '<td>' + ownersStr + '</td>' +
      '<td style="text-align:center"><span style="color:#f59e0b">' + (a.appRoles || []).length + '</span>/<span style="color:#60a5fa">' + (a.delegated || []).length + '</span></td>' +
      '</tr>' +
      '<tr id="rx-' + uid + '" style="display:none"><td colspan="6" class="expand-cell">' +
        notesHtml +
        '<div class="expand-tabs">' +
          '<div class="etab active" onclick="etab(this,\'edt-' + uid + '\')">&#128196; Detalhes</div>' +
          '<div class="etab" onclick="etab(this,\'epp-' + uid + '\')">Permissoes</div>' +
          '<div class="etab" onclick="etab(this,\'esg-' + uid + '\')">Sugestoes' + (sugg.add.length + sugg.remove.length > 0 ? ' <span class="sugg-count">' + (sugg.add.length + sugg.remove.length) + '</span>' : '') + '</div>' +
          '<div class="etab" onclick="etab(this,\'esr-' + uid + '\')">Secrets</div>' +
          '<div class="etab" onclick="etab(this,\'ecr-' + uid + '\')">Certificados</div>' +
          '<div class="etab" onclick="etab(this,\'eat-' + uid + '\')">Atividade</div>' +
          '<div class="etab" onclick="etab(this,\'eow-' + uid + '\')" style="' + (ownerList.length === 0 ? 'color:#ef4444;border-color:#ef444440' : '') + '">Owner (' + ownerList.length + ')</div>' +
          '<div class="etab" onclick="etab(this,\'els-' + uid + '\')">Ultimo Uso</div>' +
          '<div class="etab" onclick="etab(this,\'eus-' + uid + '\')">Onde e Usado</div>' +
          '<div class="etab" onclick="etab(this,\'eur-' + uid + '\')" style="color:#60a5fa;border-color:#3b82f640">URLs (' + redirectUris.length + ')</div>' +
          '<div class="etab" onclick="etab(this,\'esso-' + uid + '\')" style="color:' + (ssoEnabled ? "#a78bfa" : "#3a5068") + ';border-color:' + (ssoEnabled ? "#a78bfa40" : "#1a2840") + '">SSO' + (ssoEnabled ? " &#10003;" : "") + '</div>' +
          '<div class="etab" onclick="etab(this,\'erk-' + uid + '\')" style="color:' + riskBadgeColor + ';border-color:' + riskBadgeColor + '40">Risco (' + a._riskLevel + ')</div>' +
        '</div>' +
        '<div id="edt-' + uid + '" class="epanel active">' + detailsHtml + '</div>' +
        '<div id="epp-' + uid + '" class="epanel" style="display:none"><div class="perm-wrap">' + permsHtml + '</div></div>' +
        '<div id="esg-' + uid + '" class="epanel" style="display:none"><div class="sugg-wrap">' + suggHtml + '</div></div>' +
        '<div id="esr-' + uid + '" class="epanel" style="display:none">' + secretsHtml + '</div>' +
        '<div id="ecr-' + uid + '" class="epanel" style="display:none">' + certsHtml + '</div>' +
        '<div id="eat-' + uid + '" class="epanel" style="display:none">' + auditHtml + '</div>' +
        '<div id="eow-' + uid + '" class="epanel" style="display:none">' + ownerHtml + '</div>' +
        '<div id="els-' + uid + '" class="epanel" style="display:none">' + lastUsoHtml + '</div>' +
        '<div id="eus-' + uid + '" class="epanel" style="display:none">' + usoHtml + '</div>' +
        '<div id="eur-' + uid + '" class="epanel" style="display:none">' + urlsHtml + '</div>' +
        '<div id="esso-' + uid + '" class="epanel" style="display:none">' + ssoHtml + '</div>' +
        '<div id="erk-' + uid + '" class="epanel" style="display:none">' + riscoHtml + '</div>' +
      '</td></tr>';
  }

  function buildTabTable(list, emptyMsg, tabPrefix, isDeleted = false) {
    if (list.length === 0) return '<div class="empty-tab">' + emptyMsg + '</div>';
    if (isDeleted) {
      return '<table><thead><tr><th>Nome</th><th>Criado em</th><th>Excluido em</th><th>App ID</th><th>Audience</th><th>Tags</th></tr></thead><tbody>' +
        list.map(a => buildAppRow(a, tabPrefix || "deleted")).join("") + '</tbody></table>';
    }
    return '<table><thead><tr><th>Nome</th><th>Criado em</th><th>Ultimo Uso</th><th>Criado por</th><th>Owner(s)</th><th>Perms</th></tr></thead><tbody>' +
      list.map(a => buildAppRow(a, tabPrefix || "all")).join("") + '</tbody></table>';
  }

  const changesHtml = changes24h.length === 0
    ? '<div class="no-changes">Nenhuma mudanca nas ultimas 24 horas</div>'
    : changes24h.slice().reverse().map(c => {
        const icon = c.severity === "critico" ? "[!!]" : c.severity === "aviso" ? "[!]" : c.type === "removido" ? "[-]" : c.type === "novo" ? "[+]" : "[ok]";
        const color = c.severity === "critico" ? "#ef4444" : c.severity === "aviso" ? "#f59e0b" : c.severity === "melhora" ? "#4ade80" : "#60a5fa";
        let pd = "";
        if (c.permChanges?.length > 0) pd = '<div class="perm-changes">' + c.permChanges.map(pc => { const pcc = pc.action === "adicionada" ? (pc.severity === "critico" ? "#ef4444" : "#f59e0b") : "#4ade80"; return '<span class="pc" style="color:' + pcc + '">' + (pc.action === "adicionada" ? "+" : "-") + ' [' + escapeHtml(pc.type) + '] ' + escapeHtml(pc.name) + '</span>'; }).join("") + '</div>';
        return '<div class="change-item" style="border-left-color:' + color + '"><div class="change-top"><span style="color:' + color + ';font-weight:700;font-size:12px">' + icon + '</span><span class="change-msg">' + escapeHtml(c.message) + '</span><span class="change-time">' + fmtDate(c.detectedAt) + '</span></div>' + pd + '</div>';
      }).join("");

  const initChangesJson = safeJson(changes24h.filter(c => (Date.now() - new Date(c.detectedAt).getTime()) < 300000));

  const allSecretIssues = [];
  for (const a of apps) {
    for (const s of (a.secrets || [])) { if (s.status === "expirada" || s.status === "expirando") allSecretIssues.push({ appName: a.displayName, secret: s }); }
    for (const c of (a.certs || [])) { if (c.status === "expirado" || c.status === "expirando") allSecretIssues.push({ appName: a.displayName, secret: { ...c, displayName: "CERT: " + c.displayName, hint: "" } }); }
  }
  const secretAlertsHtml = allSecretIssues.length === 0
    ? '<div class="no-changes">Nenhuma credencial expirando</div>'
    : allSecretIssues.map(item => {
        const color = (item.secret.status === "expirada" || item.secret.status === "expirado") ? "#ef4444" : "#f59e0b";
        const label = (item.secret.status === "expirada" || item.secret.status === "expirado") ? "EXPIRADA" : "EXPIRA EM " + item.secret.daysToExp + "d";
        return '<div class="change-item" style="border-left-color:' + color + '"><div class="change-top"><span style="color:' + color + ';font-weight:700">[!]</span><span class="change-msg"><strong>' + escapeHtml(item.appName) + '</strong> — ' + escapeHtml(item.secret.displayName) + '</span><span class="change-time" style="color:' + color + '">' + label + '</span></div></div>';
      }).join("");

  const datasetsJson = safeJson(appDatasets);

  const exportFnJs = `
function buildExcelRows(dataset) {
  return dataset.map(function(a) {
    var owners=(a._owners||[]).map(function(o){return o.displayName||o.userPrincipalName||o.mail||"";}).join("; ");
    var appPerms=(a.appRoles||[]).map(function(p){return p.name||p.id;}).join("; ");
    var delPerms=(a.delegated||[]).map(function(p){return p.name||p.id;}).join("; ");
    var writePerms=(a._writePermissions||[]).map(function(p){return p.name||p.id;}).join("; ");
    var workloads=((a._usageAnalysis&&a._usageAnalysis.workloads)||[]).join("; ");
    var secrets=(a.secrets||[]).map(function(s){return s.displayName+"("+s.status+")";}).join("; ");
    var lastSignIn=a._lastSignIn&&a._lastSignIn.length>0?new Date(a._lastSignIn[0].createdDateTime).toLocaleString("pt-BR"):"";
    var lastUser=a._lastSignIn&&a._lastSignIn.length>0?(a._lastSignIn[0].userDisplayName||a._lastSignIn[0].userPrincipalName||""):"";
    var statusLabel=a._status==="active"?"Ativo":a._status==="disabled"?"Desabilitado":a._status==="deleted"?"Excluido":"Sem SP";
    var ssoMode=a._ssoMode||"";
    return {
      "Nome":a.displayName||"","App ID":a.appId||"","Object ID":a.id||"",
      "Status":statusLabel,"SSO":ssoMode,
      "Criado em":a.createdDateTime?new Date(a.createdDateTime).toLocaleString("pt-BR"):"",
      "Criado por":a._createdBy||"","Owner(s)":owners,
      "Risco":a._riskLevel||"","Ultimo Uso":lastSignIn,"Ultimo Usuario":lastUser,
      "Sign-in Audience":a.signInAudience||"","Publisher":a._publisherName||"",
      "App Permissions":appPerms,"Delegated Permissions":delPerms,
      "Write Permissions":writePerms,
      "Write Groups":(a._writePermissions||[]).some(function(p){return(p.name||"").startsWith("Group.")})?"Sim":"Nao",
      "Write Users":(a._writePermissions||[]).some(function(p){return(p.name||"").startsWith("User.")})?"Sim":"Nao",
      "Write E-mail":(a._writePermissions||[]).some(function(p){return(p.name||"").startsWith("Mail.")||(p.name||"").startsWith("MailboxSettings.")})?"Sim":"Nao",
      "Write Files":(a._writePermissions||[]).some(function(p){return(p.name||"").startsWith("Files.")||(p.name||"").startsWith("Sites.")})?"Sim":"Nao",
      "Workloads":workloads,"Secrets":secrets,
      "Redirect URIs Web":(a.web&&a.web.redirectUris||[]).join("; "),
      "Redirect URIs SPA":(a.spa&&a.spa.redirectUris||[]).join("; "),
      "Redirect URIs Mobile":(a.publicClient&&a.publicClient.redirectUris||[]).join("; "),
      "Login URL":a._loginUrl||"","Logout URL":a._logoutUrl||"","Notas":a.notes||""
    };
  });
}
var COL_WIDTHS=[{wch:40},{wch:38},{wch:38},{wch:12},{wch:12},{wch:20},{wch:25},{wch:30},{wch:10},{wch:20},{wch:25},{wch:18},{wch:20},{wch:60},{wch:60},{wch:50},{wch:10},{wch:10},{wch:10},{wch:10},{wch:50},{wch:50},{wch:50},{wch:50},{wch:50},{wch:40},{wch:30}];
var TAB_LABELS={all:"Todas",active:"Ativos",disabled:"Desabilitados",deleted:"Excluidos",risky:"App_Permissions",write:"Write",writegroups:"Write_Groups",writeusers:"Write_Users",writeemail:"Write_Email",writefiles:"Write_Files",critical:"Critical",recent:"Criados_30d",noowner:"Sem_Owner",secrets:"Com_Secrets",expsecrets:"Exp_Secrets",sso:"Com_SSO"};
var TAB_LABELS_FULL={all:"Todas",active:"Ativos",disabled:"Desabilitados",deleted:"Excluidos",risky:"App Permissions",write:"Write",writegroups:"Write Groups",writeusers:"Write Users",writeemail:"Write E-mail",writefiles:"Write Files",critical:"Critical",recent:"Criados 30d",noowner:"Sem Owner",secrets:"Com Secrets",expsecrets:"Exp. Secrets",sso:"Com SSO"};
var TAB_ORDER=["all","active","disabled","deleted","risky","write","writegroups","writeusers","writeemail","writefiles","critical","recent","noowner","secrets","expsecrets","sso"];

function exportExcel(){
  if(typeof XLSX==="undefined"){alert("SheetJS nao carregado.");return;}
  var dataset=DATASETS[currentTab]||[];
  if(dataset.length===0){alert("Nenhum dado para exportar.");return;}
  var wb=XLSX.utils.book_new();
  var ws=XLSX.utils.json_to_sheet(buildExcelRows(dataset));
  ws["!cols"]=COL_WIDTHS;
  XLSX.utils.book_append_sheet(wb,ws,"Apps");
  var summary=[
    ["Enterprise Applications Monitor"],
    ["Tenant ID","${session.tenantId}"],
    ["Gerado em",new Date().toLocaleString("pt-BR")],
    ["Aba",TAB_LABELS_FULL[currentTab]||currentTab],
    ["Total",dataset.length],[]
  ];
  var wsSummary=XLSX.utils.aoa_to_sheet(summary);
  wsSummary["!cols"]=[{wch:30},{wch:45}];
  XLSX.utils.book_append_sheet(wb,wsSummary,"Resumo");
  XLSX.writeFile(wb,"EnterpriseApps_"+(TAB_LABELS[currentTab]||currentTab)+"_"+new Date().toISOString().slice(0,10)+".xlsx");
}

function exportAllExcel(){
  if(typeof XLSX==="undefined"){alert("SheetJS nao carregado.");return;}
  var wb=XLSX.utils.book_new();
  TAB_ORDER.forEach(function(tab){
    var dataset=DATASETS[tab]||[];
    var rows=buildExcelRows(dataset);
    var ws=rows.length>0?XLSX.utils.json_to_sheet(rows):XLSX.utils.json_to_sheet([{"Info":"Sem dados"}]);
    ws["!cols"]=COL_WIDTHS;
    XLSX.utils.book_append_sheet(wb,ws,TAB_LABELS[tab]||tab);
  });
  var summary=[["Relatorio Completo"],["Tenant ID","${session.tenantId}"],["Gerado em",new Date().toLocaleString("pt-BR")],[]];
  TAB_ORDER.forEach(function(tab){summary.push([TAB_LABELS_FULL[tab]||tab,(DATASETS[tab]||[]).length]);});
  var wsSummary=XLSX.utils.aoa_to_sheet(summary);
  wsSummary["!cols"]=[{wch:30},{wch:15}];
  XLSX.utils.book_append_sheet(wb,wsSummary,"Resumo");
  XLSX.writeFile(wb,"EnterpriseApps_COMPLETO_"+new Date().toISOString().slice(0,10)+".xlsx");
}
`;

  // Cards de métricas principais
  const metricsHtml =
    '<div class="metrics-grid">' +
    '<div class="metric-card metric-total"><div class="metric-num">' + allApps.length + '</div><div class="metric-label">Total de Apps</div></div>' +
    '<div class="metric-card metric-active"><div class="metric-num" style="color:#4ade80">' + activeApps.length + '</div><div class="metric-label">Ativos</div></div>' +
    '<div class="metric-card metric-disabled"><div class="metric-num" style="color:#f59e0b">' + disabledApps.length + '</div><div class="metric-label">Desabilitados</div></div>' +
    '<div class="metric-card metric-deleted"><div class="metric-num" style="color:#ef4444">' + deleted.length + '</div><div class="metric-label">Excluidos</div></div>' +
    '<div class="metric-card"><div class="metric-num" style="color:#ef4444">' + criticalApps.length + '</div><div class="metric-label">Risco Critical</div></div>' +
    '<div class="metric-card"><div class="metric-num" style="color:#a78bfa">' + ssoApps.length + '</div><div class="metric-label">Com SSO</div></div>' +
    '<div class="metric-card"><div class="metric-num" style="color:#f59e0b">' + allSecretIssues.length + '</div><div class="metric-label">Cred. Expirando</div></div>' +
    '<div class="metric-card"><div class="metric-num" style="color:#ef4444">' + noOwnerApps.length + '</div><div class="metric-label">Sem Owner</div></div>' +
    '</div>';

  return `<!DOCTYPE html><html lang="pt-BR"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Enterprise Applications Monitor</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"><\/script>
<style>
@import url("https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600&display=swap");
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:"Inter",sans-serif;background:#060a0f;color:#c8d8e8;min-height:100vh}
.hdr{background:#0a1220;border-bottom:1px solid #1a2840;padding:12px 28px;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:200}
.hdr-brand h1{font-family:"JetBrains Mono",monospace;font-size:13px;color:#38bdf8;letter-spacing:2px;text-transform:uppercase}
.tid{font-size:10px;color:#2a4060;margin-top:2px;font-family:"JetBrains Mono",monospace}
.hdr-right{display:flex;align-items:center;gap:10px}
.live{display:flex;align-items:center;gap:5px;font-size:11px;color:#4ade80;background:#0a1f10;padding:4px 10px;border-radius:20px;border:1px solid #166534;font-family:"JetBrains Mono",monospace}
.dot{width:6px;height:6px;background:#4ade80;border-radius:50%;animation:pulse 2s infinite}@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.cd{font-size:11px;color:#2a4060;font-family:"JetBrains Mono",monospace}
.ri{font-size:16px;cursor:pointer;color:#2a4060;transition:color .2s}.ri:hover{color:#38bdf8}
.refresh-spin{animation:spin .8s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}
.upd{font-size:11px;color:#2a4060}
.wrap{max-width:1600px;margin:0 auto;padding:16px}
/* Métricas */
.metrics-grid{display:grid;grid-template-columns:repeat(8,1fr);gap:8px;margin-bottom:14px}
.metric-card{background:#0d1520;border:1px solid #1a2840;border-radius:10px;padding:12px 8px;text-align:center}
.metric-num{font-size:24px;font-weight:700;font-family:"JetBrains Mono",monospace;color:#c8d8e8}
.metric-label{font-size:9px;color:#3a5068;margin-top:3px;text-transform:uppercase;letter-spacing:.5px}
/* Abas principais */
.main-tabs{display:flex;gap:4px;margin-bottom:12px;flex-wrap:wrap}
.main-tab{padding:6px 14px;border-radius:6px;cursor:pointer;font-size:10px;font-family:"JetBrains Mono",monospace;background:#0d1520;border:1px solid #1a2840;color:#3a5068;transition:all .2s;white-space:nowrap}
.main-tab:hover{border-color:#38bdf8;color:#38bdf8}
.main-tab.active{background:#061828;border-color:#0ea5e9;color:#38bdf8}
.main-tab.tab-active-status{border-color:#4ade8040;color:#4ade80}
.main-tab.tab-active-status.active{background:#061a10;border-color:#4ade80}
.main-tab.tab-disabled-status{border-color:#f59e0b40;color:#f59e0b}
.main-tab.tab-disabled-status.active{background:#1a1200;border-color:#f59e0b}
.main-tab.tab-deleted-status{border-color:#ef444440;color:#ef4444}
.main-tab.tab-deleted-status.active{background:#1a0600;border-color:#ef4444}
.main-tab.tab-critical{border-color:#ef444430;color:#ef4444}
.main-tab.tab-sso{border-color:#a78bfa40;color:#a78bfa}
/* Layout */
.layout{display:grid;grid-template-columns:1fr 290px;gap:12px;align-items:start}
.card{background:#0d1520;border:1px solid #1a2840;border-radius:12px;padding:14px;margin-bottom:10px}
.card-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;flex-wrap:wrap;gap:6px}
.card-title{font-family:"JetBrains Mono",monospace;font-size:10px;color:#3a5068;text-transform:uppercase;letter-spacing:2px}
/* Botões Excel */
.btn-excel{display:inline-flex;align-items:center;gap:4px;padding:4px 10px;background:#166534;border:1px solid #22c55e40;border-radius:5px;color:#4ade80;font-size:9px;font-family:"JetBrains Mono",monospace;cursor:pointer;transition:all .2s;text-transform:uppercase;letter-spacing:1px;white-space:nowrap}
.btn-excel:hover{background:#15803d;border-color:#22c55e}
.btn-excel-all{display:inline-flex;align-items:center;gap:4px;padding:4px 10px;background:#0f4c81;border:1px solid #3b82f640;border-radius:5px;color:#60a5fa;font-size:9px;font-family:"JetBrains Mono",monospace;cursor:pointer;transition:all .2s;text-transform:uppercase;letter-spacing:1px;white-space:nowrap}
.btn-excel-all:hover{background:#1e5fa3;border-color:#3b82f6}
/* Search */
.search-bar{width:100%;background:#060a0f;border:1px solid #1a2840;border-radius:6px;padding:7px 11px;color:#c8d8e8;font-size:12px;margin-bottom:8px;outline:none;font-family:"JetBrains Mono",monospace;transition:border-color .2s}
.search-bar:focus{border-color:#0ea5e9}
/* Tab panels */
.tab-panel{display:none}.tab-panel.active{display:block}
/* Tabela */
table{width:100%;border-collapse:collapse;font-size:11px}
th{text-align:left;padding:6px 8px;color:#2a4060;font-weight:600;font-size:9px;text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid #1a2840;font-family:"JetBrains Mono",monospace;white-space:nowrap}
td{padding:7px 8px;border-bottom:1px solid #0d1a2a;color:#94a3b8;vertical-align:middle}
.ar{cursor:pointer;transition:background .15s}.ar:hover td{background:#0a1525}
.ar.risky td:first-child{border-left:2px solid #f59e0b}
/* Nome e badges */
.app-name{display:flex;align-items:center;gap:3px;flex-wrap:wrap;color:#c8d8e8;font-weight:500}
.status-badge{font-size:8px;font-weight:700;padding:1px 5px;border-radius:8px;white-space:nowrap}
.status-active{background:#4ade8015;color:#4ade80;border:1px solid #4ade8030}
.status-disabled{background:#f59e0b15;color:#f59e0b;border:1px solid #f59e0b30}
.status-deleted{background:#ef444415;color:#ef4444;border:1px solid #ef444430}
.status-nosp{background:#3a506815;color:#3a5068;border:1px solid #3a506830}
.sso-badge{font-size:8px;font-weight:700;padding:1px 5px;border-radius:8px;background:#a78bfa15;color:#a78bfa;border:1px solid #a78bfa30;font-family:"JetBrains Mono",monospace;white-space:nowrap}
.risk-badge{font-size:8px;font-weight:700;padding:1px 5px;border-radius:8px;background:#f59e0b20;color:#f59e0b;border:1px solid #f59e0b40;font-family:"JetBrains Mono",monospace;white-space:nowrap}
.write-badge{font-size:8px;font-weight:700;padding:1px 5px;border-radius:8px;background:#ef444420;color:#ef4444;border:1px solid #ef444440;font-family:"JetBrains Mono",monospace}
.wcat-badge{font-size:8px;font-weight:700;padding:1px 5px;border-radius:8px;background:#f59e0b10;color:#f59e0b;border:1px solid #f59e0b30;font-family:"JetBrains Mono",monospace}
.secret-badge{font-size:8px;font-weight:700;padding:1px 5px;border-radius:8px;background:#60a5fa20;color:#60a5fa;border:1px solid #60a5fa40;font-family:"JetBrains Mono",monospace}
.notes-badge{font-size:8px;padding:1px 4px;border-radius:8px;background:#4ade8020;color:#4ade80;border:1px solid #4ade8040}
.url-badge{font-size:8px;font-weight:700;padding:1px 5px;border-radius:8px;background:#3b82f620;color:#60a5fa;border:1px solid #3b82f640;font-family:"JetBrains Mono",monospace;cursor:help}
.rl-badge{font-size:8px;font-weight:700;padding:1px 5px;border-radius:8px;border:1px solid;font-family:"JetBrains Mono",monospace;white-space:nowrap}
/* Expand */
.expand-cell{background:#060d16;padding:10px 12px;border-bottom:1px solid #1a2840}
.notes-box{background:#0a1f10;border:1px solid #166534;border-radius:5px;padding:7px 10px;margin-bottom:8px;font-size:11px;color:#86efac;line-height:1.5}
.notes-label{font-weight:700;margin-right:5px;font-family:"JetBrains Mono",monospace;font-size:9px;text-transform:uppercase;letter-spacing:1px}
/* Sugestões */
.sugg-wrap{display:flex;flex-direction:column;gap:7px}.sugg-ok{font-size:11px;color:#4ade80;padding:7px;background:#061a10;border-radius:5px;font-family:"JetBrains Mono",monospace}
.sugg-section{display:flex;flex-direction:column;gap:3px}.sugg-title{font-size:9px;font-weight:700;margin-bottom:3px;font-family:"JetBrains Mono",monospace;text-transform:uppercase;letter-spacing:1px}
.sugg-item{display:flex;align-items:flex-start;gap:7px;padding:5px 7px;border-radius:4px;background:#060a0f;font-size:11px}
.sugg-item code{font-family:"JetBrains Mono",monospace;font-size:10px;flex-shrink:0;padding:1px 3px;border-radius:3px;background:#0a1525}
.sugg-remove code{color:#ef4444;border:1px solid #ef444430}.sugg-add code{color:#4ade80;border:1px solid #4ade8030}.sugg-item span{color:#94a3b8;line-height:1.4}
.sugg-count{display:inline-flex;align-items:center;justify-content:center;width:13px;height:13px;background:#f59e0b;color:#000;border-radius:50%;font-size:8px;font-weight:700;margin-left:3px}
/* Etabs */
.expand-tabs{display:flex;gap:3px;margin-bottom:8px;flex-wrap:wrap}
.etab{font-size:9px;padding:3px 7px;border-radius:4px;cursor:pointer;background:transparent;color:#3a5068;border:1px solid #1a2840;font-family:"JetBrains Mono",monospace;transition:all .2s;white-space:nowrap}
.etab:hover{border-color:#38bdf8;color:#38bdf8}.etab.active{background:#061828;border-color:#0ea5e9;color:#38bdf8}
.epanel{display:none}.epanel.active{display:block}
/* Permissões */
.perm-wrap{display:flex;flex-wrap:wrap;gap:3px}
.pb{display:inline-flex;align-items:center;gap:2px;font-size:9px;padding:2px 5px;border-radius:4px;border:1px solid;font-family:"JetBrains Mono",monospace}
.pt{font-size:7px;font-weight:700;opacity:.6}
.pb-wrap{position:relative;display:inline-block;margin:2px}
.pb-tooltip{display:none;position:absolute;bottom:calc(100% + 5px);left:50%;transform:translateX(-50%);background:#0a1a2a;border:1px solid #1e4060;border-radius:6px;padding:7px 10px;font-size:10px;color:#c8d8e8;white-space:pre-wrap;max-width:250px;min-width:150px;z-index:9999;box-shadow:0 8px 24px rgba(0,0,0,.8);line-height:1.5;pointer-events:none}
.pb-wrap:hover .pb-tooltip{display:block}
.leg{display:flex;gap:7px;font-size:9px;color:#2a4060;margin-bottom:7px;flex-wrap:wrap;font-family:"JetBrains Mono",monospace}
/* Secrets / certs */
.secrets-wrap{display:flex;flex-direction:column;gap:5px}
.secret-item{display:flex;align-items:center;gap:8px;padding:6px 8px;background:#0a1525;border-radius:5px;flex-wrap:wrap}
.secret-name{font-size:10px;color:#c8d8e8;font-family:"JetBrains Mono",monospace;flex:1}.secret-dates{font-size:9px;color:#3a5068}.secret-status{font-size:9px;font-weight:700;font-family:"JetBrains Mono",monospace}
/* Audit */
.audit-wrap{display:flex;flex-direction:column;gap:3px}
.audit-title{font-size:9px;color:#3a5068;margin-bottom:4px;font-family:"JetBrains Mono",monospace;text-transform:uppercase;letter-spacing:1px}
.audit-item{display:flex;align-items:flex-start;gap:7px;padding:4px 7px;background:#0a1525;border-radius:4px;flex-wrap:wrap}
.audit-action{font-size:10px;color:#c8d8e8;flex:1;min-width:90px}.audit-actor{font-size:9px;color:#38bdf8;font-family:"JetBrains Mono",monospace}.audit-time{font-size:9px;color:#3a5068}
/* Workloads e escritas */
.wb{display:inline-flex;align-items:center;font-size:10px;padding:2px 7px;border-radius:4px;background:#0a1f30;border:1px solid #1e4060;color:#38bdf8;font-family:"JetBrains Mono",monospace}
.wc-badge{display:inline-flex;align-items:center;font-size:10px;padding:2px 7px;border-radius:4px;background:#1a0f00;border:1px solid #f59e0b40;color:#f59e0b;font-family:"JetBrains Mono",monospace}
/* Owner cards */
.owner-card{display:flex;gap:10px;padding:9px;background:#0a1525;border-radius:7px;margin-bottom:7px;align-items:flex-start}
.owner-avatar{display:flex;align-items:center;justify-content:center;width:34px;height:34px;border-radius:50%;font-weight:700;font-size:12px;flex-shrink:0;font-family:"JetBrains Mono",monospace}
.owner-info{display:flex;flex-direction:column;gap:3px;flex:1;min-width:0}
.owner-name{font-size:12px;font-weight:600;color:#c8d8e8}
.owner-detail{display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.owner-label{font-size:9px;color:#3a5068;font-family:"JetBrains Mono",monospace;text-transform:uppercase;letter-spacing:.5px;min-width:65px;flex-shrink:0}
.owner-value{font-size:10px;color:#94a3b8}
/* Painel lateral */
.side-card{background:#0d1520;border:1px solid #1a2840;border-radius:10px;padding:12px;margin-bottom:10px}
.side-title{font-family:"JetBrains Mono",monospace;font-size:9px;color:#3a5068;text-transform:uppercase;letter-spacing:2px;margin-bottom:8px;display:flex;align-items:center;justify-content:space-between}
.change-item{padding:6px 7px;border-left:2px solid #1a2840;background:#060d16;border-radius:0 5px 5px 0;margin-bottom:4px}
.change-top{display:flex;align-items:center;gap:5px;flex-wrap:wrap}.change-msg{font-size:10px;color:#c8d8e8;flex:1}.change-time{font-size:9px;color:#3a5068;white-space:nowrap;font-family:"JetBrains Mono",monospace}
.perm-changes{display:flex;flex-wrap:wrap;gap:3px;margin-top:4px;padding-top:4px;border-top:1px solid #1a2840}
.pc{font-size:9px;font-weight:600;padding:1px 4px;background:#060a0f;border-radius:3px;font-family:"JetBrains Mono",monospace}
.no-changes{font-size:10px;color:#2a4060;text-align:center;padding:14px 0;font-family:"JetBrains Mono",monospace}
.empty-tab{font-size:11px;color:#2a4060;text-align:center;padding:28px 0;font-family:"JetBrains Mono",monospace}
/* Toast */
#toast-area{position:fixed;bottom:14px;right:14px;z-index:999;display:flex;flex-direction:column;gap:5px;max-width:340px}
.toast{background:#0d1520;border:1px solid #1a2840;border-radius:8px;padding:8px 12px;font-size:11px;display:flex;align-items:flex-start;gap:6px;box-shadow:0 6px 24px rgba(0,0,0,.6);animation:slideUp .3s ease}
.toast.critico{border-color:#ef4444;background:#1a0808}.toast.aviso{border-color:#f59e0b;background:#1a1208}.toast.melhora{border-color:#4ade80;background:#081a10}.toast.info{border-color:#60a5fa;background:#08101a}
.tc{margin-left:auto;color:#2a4060;cursor:pointer;font-size:13px}
@keyframes slideUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
.foot{text-align:center;padding:16px;color:#2a4060;font-size:10px;font-family:"JetBrains Mono",monospace}.foot a{color:#0ea5e9;text-decoration:none}
</style></head><body>

<div id="toast-area"></div>
<div class="hdr">
  <div class="hdr-brand"><div><h1>ENTERPRISE APPLICATIONS MONITOR</h1><div class="tid">${session.tenantId}</div></div></div>
  <div class="hdr-right">
    <div class="live"><div class="dot"></div>LIVE</div>
    <div class="cd" id="cd">NEXT: <strong id="timer">5:00</strong></div>
    <div class="ri" id="ri" title="Atualizar agora" onclick="forceRefresh()">&#8635;</div>
    <div class="upd">UPD: <span id="upd">agora</span></div>
  </div>
</div>

<div class="wrap">
  ${metricsHtml}

  <div class="main-tabs">
    <div class="main-tab active" id="mt-all" onclick="switchMainTab('all',this)">Todos (${allApps.length})</div>
    <div class="main-tab tab-active-status" id="mt-active" onclick="switchMainTab('active',this)">&#10003; Ativos (${activeApps.length})</div>
    <div class="main-tab tab-disabled-status" id="mt-disabled" onclick="switchMainTab('disabled',this)">&#9888; Desabilitados (${disabledApps.length})</div>
    <div class="main-tab tab-deleted-status" id="mt-deleted" onclick="switchMainTab('deleted',this)">&#10007; Excluidos (${deleted.length})</div>
    <div class="main-tab" id="mt-risky" onclick="switchMainTab('risky',this)">App Perm (${riskyApps.length})</div>
    <div class="main-tab" id="mt-write" onclick="switchMainTab('write',this)">Write (${writeApps.length})</div>
    <div class="main-tab" id="mt-writegroups" onclick="switchMainTab('writegroups',this)">W Groups (${writeGroupsApps.length})</div>
    <div class="main-tab" id="mt-writeusers" onclick="switchMainTab('writeusers',this)">W Users (${writeUsersApps.length})</div>
    <div class="main-tab" id="mt-writeemail" onclick="switchMainTab('writeemail',this)">W E-mail (${writeEmailApps.length})</div>
    <div class="main-tab" id="mt-writefiles" onclick="switchMainTab('writefiles',this)">W Files (${writeFilesApps.length})</div>
    <div class="main-tab tab-critical" id="mt-critical" onclick="switchMainTab('critical',this)">Critical (${criticalApps.length})</div>
    <div class="main-tab" id="mt-recent" onclick="switchMainTab('recent',this)">30 dias (${recentApps.length})</div>
    <div class="main-tab" id="mt-noowner" onclick="switchMainTab('noowner',this)">Sem Owner (${noOwnerApps.length})</div>
    <div class="main-tab" id="mt-secrets" onclick="switchMainTab('secrets',this)">Secrets (${appsWithSecrets.length})</div>
    <div class="main-tab" id="mt-expsecrets" onclick="switchMainTab('expsecrets',this)">Exp.Secrets (${expSecrets.length})</div>
    <div class="main-tab tab-sso" id="mt-sso" onclick="switchMainTab('sso',this)">Com SSO (${ssoApps.length})</div>
  </div>

  <div class="layout"><div><div class="card">
    <div class="card-header">
      <div class="card-title" id="tabLabel">Todas as Aplicacoes (${allApps.length})</div>
      <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">
        <div class="leg" style="margin:0"><span style="color:#ef4444">&#9632; Critico</span><span style="color:#f59e0b">&#9632; Alto</span><span style="color:#4ade80">&#9632; Normal</span></div>
        <button class="btn-excel" onclick="exportExcel()" title="Exportar aba atual">&#8595; Aba atual</button>
        <button class="btn-excel-all" onclick="exportAllExcel()" title="Exportar todas as abas">&#8595; Exportar tudo</button>
      </div>
    </div>
    <input class="search-bar" id="search" type="text" placeholder="Buscar nome, owner, permissao, status, SSO, App ID..." oninput="filterTable()">

    <div id="tp-all" class="tab-panel active"><table><thead><tr><th>Nome</th><th>Criado em</th><th>Ultimo Uso</th><th>Criado por</th><th>Owner(s)</th><th>Perms</th></tr></thead><tbody>${allApps.map(a => buildAppRow(a, "all")).join("")}</tbody></table></div>
    <div id="tp-active" class="tab-panel">${buildTabTable(activeApps, "Nenhum app ativo", "active")}</div>
    <div id="tp-disabled" class="tab-panel">${buildTabTable(disabledApps, "Nenhum app desabilitado", "disabled")}</div>
    <div id="tp-deleted" class="tab-panel">${buildTabTable(deleted, "Nenhum app excluido encontrado", "deleted", true)}</div>
    <div id="tp-risky" class="tab-panel">${buildTabTable(riskyApps, "Nenhum app com Application Permission", "risky")}</div>
    <div id="tp-write" class="tab-panel">${buildTabTable(writeApps, "Nenhum app com permissoes de escrita", "write")}</div>
    <div id="tp-writegroups" class="tab-panel">${buildTabTable(writeGroupsApps, "Nenhum app com Write em Groups", "writegroups")}</div>
    <div id="tp-writeusers" class="tab-panel">${buildTabTable(writeUsersApps, "Nenhum app com Write em Users", "writeusers")}</div>
    <div id="tp-writeemail" class="tab-panel">${buildTabTable(writeEmailApps, "Nenhum app com Write em E-mail", "writeemail")}</div>
    <div id="tp-writefiles" class="tab-panel">${buildTabTable(writeFilesApps, "Nenhum app com Write em Files", "writefiles")}</div>
    <div id="tp-critical" class="tab-panel">${buildTabTable(criticalApps, "Nenhum app com risco Critical", "critical")}</div>
    <div id="tp-recent" class="tab-panel">${buildTabTable(recentApps, "Nenhum app criado nos ultimos 30 dias", "recent")}</div>
    <div id="tp-noowner" class="tab-panel">${buildTabTable(noOwnerApps, "Todos os apps possuem owner", "noowner")}</div>
    <div id="tp-secrets" class="tab-panel">${buildTabTable(appsWithSecrets, "Nenhum app com secrets", "secrets")}</div>
    <div id="tp-expsecrets" class="tab-panel">${buildTabTable(expSecrets, "Nenhuma secret/cert expirada ou expirando", "expsecrets")}</div>
    <div id="tp-sso" class="tab-panel">${buildTabTable(ssoApps, "Nenhum app com SSO configurado", "sso")}</div>
  </div></div>

  <div>
    <div class="side-card">
      <div class="side-title"><span>Mudancas (24h)</span><span style="color:#2a4060">${changes24h.length}</span></div>
      <div id="changesPanel">${changesHtml}</div>
    </div>
    <div class="side-card">
      <div class="side-title"><span>Credenciais Expirando</span><span style="color:#2a4060">${allSecretIssues.length}</span></div>
      <div id="secretAlertsPanel">${secretAlertsHtml}</div>
    </div>
    <div class="side-card">
      <div class="side-title">Inventario</div>
      <div class="audit-item"><span class="audit-action">Total apps</span><span style="color:#c8d8e8">${allApps.length}</span></div>
      <div class="audit-item"><span class="audit-action">Ativos</span><span style="color:#4ade80">${activeApps.length}</span></div>
      <div class="audit-item"><span class="audit-action">Desabilitados</span><span style="color:#f59e0b">${disabledApps.length}</span></div>
      <div class="audit-item"><span class="audit-action">Excluidos</span><span style="color:#ef4444">${deleted.length}</span></div>
      <div class="audit-item"><span class="audit-action">Com SSO</span><span style="color:#a78bfa">${ssoApps.length}</span></div>
      <div class="audit-item"><span class="audit-action">Com Write Perm</span><span style="color:#f59e0b">${writeApps.length}</span></div>
      <div class="audit-item"><span class="audit-action">Risco Critical</span><span style="color:#ef4444">${criticalApps.length}</span></div>
      <div class="audit-item"><span class="audit-action">Sem Owner</span><span style="color:#ef4444">${noOwnerApps.length}</span></div>
      <div class="audit-item"><span class="audit-action">Criados 30d</span><span style="color:#60a5fa">${recentApps.length}</span></div>
      <div style="font-size:9px;color:#2a4060;margin-top:8px;font-family:'JetBrains Mono',monospace">Atualizado: ${fmtDate(session.lastUpdated)}</div>
    </div>
  </div>
  </div>
</div>
<div class="foot"><a href="/">Nova analise</a></div>

<script>
var SID="${sessionId}";var INTERVAL=5*60*1000;var next=Date.now()+INTERVAL;var busy=false;var currentTab="all";
var initChanges=${initChangesJson};
if(initChanges&&initChanges.length>0){setTimeout(function(){initChanges.forEach(showToast);},700);}
var DATASETS=${datasetsJson};

${exportFnJs}

setInterval(function(){if(busy)return;var r=Math.max(0,next-Date.now());var m=Math.floor(r/60000),s=Math.floor((r%60000)/1000);document.getElementById("timer").textContent=m+":"+(s<10?"0":"")+s;if(r<=0)doRefresh();},1000);
function forceRefresh(){next=Date.now();}

function switchMainTab(name,el){
  currentTab=name;
  document.querySelectorAll(".main-tab").forEach(function(e){e.classList.remove("active");});
  el.classList.add("active");
  document.querySelectorAll(".tab-panel").forEach(function(e){e.classList.remove("active");e.style.display="none";});
  var panel=document.getElementById("tp-"+name);if(panel){panel.classList.add("active");panel.style.display="block";}
  var counts={all:"${allApps.length}",active:"${activeApps.length}",disabled:"${disabledApps.length}",deleted:"${deleted.length}",risky:"${riskyApps.length}",write:"${writeApps.length}",writegroups:"${writeGroupsApps.length}",writeusers:"${writeUsersApps.length}",writeemail:"${writeEmailApps.length}",writefiles:"${writeFilesApps.length}",critical:"${criticalApps.length}",recent:"${recentApps.length}",noowner:"${noOwnerApps.length}",secrets:"${appsWithSecrets.length}",expsecrets:"${expSecrets.length}",sso:"${ssoApps.length}"};
  var labels={all:"Todas",active:"Ativos",disabled:"Desabilitados",deleted:"Excluidos",risky:"App Permissions",write:"Write",writegroups:"Write Groups",writeusers:"Write Users",writeemail:"Write E-mail",writefiles:"Write Files",critical:"Critical",recent:"Criados 30d",noowner:"Sem Owner",secrets:"Com Secrets",expsecrets:"Exp. Secrets",sso:"Com SSO"};
  document.getElementById("tabLabel").textContent=(labels[name]||name)+" ("+(counts[name]||"?")+")";
  document.getElementById("search").value="";
}

function filterTable(){
  var q=document.getElementById("search").value.toLowerCase();
  var rows=document.querySelectorAll("#tp-"+currentTab+" tr.ar");
  rows.forEach(function(row){
    var show=q===""||row.textContent.toLowerCase().includes(q);
    row.style.display=show?"":"none";
    var onclick=row.getAttribute("onclick")||"";
    var match=onclick.match(/toggle\\('([^']+)'\\)/);
    if(match){var exp=document.getElementById(match[1]);if(exp&&!show)exp.style.display="none";}
  });
}

function toggle(id){var r=document.getElementById(id);if(r)r.style.display=r.style.display==="none"?"table-row":"none";}
function etab(el,panelId){var expand=el.closest(".expand-cell");expand.querySelectorAll(".etab").forEach(function(e){e.classList.remove("active");});expand.querySelectorAll(".epanel").forEach(function(e){e.style.display="none";});el.classList.add("active");var p=document.getElementById(panelId);if(p){p.style.display="block";}}
function upd(id,v){var el=document.getElementById(id);if(el&&el.textContent!=String(v)){el.textContent=v;}}
function esc(s){return String(s==null?"":s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");}

function doRefresh(){
  if(busy)return;busy=true;next=Date.now()+INTERVAL;
  var ri=document.getElementById("ri");ri.classList.add("refresh-spin");
  document.getElementById("cd").innerHTML="ATUALIZANDO...";
  fetch("/refresh/"+SID).then(function(r){return r.json();}).then(function(data){
    if(data.error){showToast({severity:"critico",message:"Erro: "+data.error});return;}
    var apps=data.apps||[];
    DATASETS.all=apps;
    DATASETS.active=apps.filter(function(a){return a._status==="active";});
    DATASETS.disabled=apps.filter(function(a){return a._status==="disabled";});
    DATASETS.deleted=data.deleted||[];
    DATASETS.risky=apps.filter(function(a){return a.appRoles&&a.appRoles.length>0;});
    DATASETS.write=apps.filter(function(a){return a._writePermissions&&a._writePermissions.length>0;});
    DATASETS.critical=apps.filter(function(a){return a._riskLevel==="Critical";});
    DATASETS.recent=apps.filter(function(a){return a.createdDateTime&&(Date.now()-new Date(a.createdDateTime).getTime())/86400000<=30;});
    DATASETS.noowner=apps.filter(function(a){return !a._owners||a._owners.length===0;});
    DATASETS.secrets=apps.filter(function(a){return a.secrets&&a.secrets.length>0;});
    DATASETS.expsecrets=apps.filter(function(a){return(a.secrets||[]).some(function(s){return s.status==="expirada"||s.status==="expirando";});});
    DATASETS.sso=apps.filter(function(a){return a._ssoMode&&a._ssoMode!=="none";});
    if(data.changesLast24h){
      var ch=data.changesLast24h;var panel=document.getElementById("changesPanel");
      if(ch.length===0){panel.innerHTML='<div class="no-changes">Nenhuma mudanca nas ultimas 24 horas</div>';}
      else{panel.innerHTML=ch.slice().reverse().map(function(c){var icon=c.severity==="critico"?"[!!]":c.severity==="aviso"?"[!]":c.type==="removido"?"[-]":c.type==="novo"?"[+]":"[ok]";var color=c.severity==="critico"?"#ef4444":c.severity==="aviso"?"#f59e0b":c.severity==="melhora"?"#4ade80":"#60a5fa";var pd="";if(c.permChanges&&c.permChanges.length>0){pd='<div class="perm-changes">'+c.permChanges.map(function(pc){var pcc=pc.action==="adicionada"?(pc.severity==="critico"?"#ef4444":"#f59e0b"):"#4ade80";return'<span class="pc" style="color:'+pcc+'">'+( pc.action==="adicionada"?"+":"-")+' ['+esc(pc.type)+'] '+esc(pc.name)+'</span>';}).join("")+'</div>';}return'<div class="change-item" style="border-left-color:'+color+'"><div class="change-top"><span style="color:'+color+';font-weight:700;font-size:10px">'+icon+'</span><span class="change-msg">'+esc(c.message)+'</span><span class="change-time">'+new Date(c.detectedAt).toLocaleString("pt-BR")+'</span></div>'+pd+'</div>';}).join("");}
      if(data.newChanges&&data.newChanges.length>0){data.newChanges.forEach(showToast);}
    }
    document.getElementById("upd").textContent=new Date().toLocaleTimeString("pt-BR");
  }).catch(function(e){showToast({severity:"critico",message:"Falha: "+e.message});})
  .finally(function(){busy=false;document.getElementById("ri").classList.remove("refresh-spin");document.getElementById("cd").innerHTML='NEXT: <strong id="timer">5:00</strong>';});
}

function showToast(c){var area=document.getElementById("toast-area");var icons={critico:"[!!]",aviso:"[!]",melhora:"[ok]",info:"[i]"};var t=document.createElement("div");t.className="toast "+(c.severity||"info");t.innerHTML='<span style="font-weight:700">'+(icons[c.severity]||"[i]")+'</span><span>'+esc(c.message)+'</span><span class="tc" onclick="this.parentElement.remove()">x</span>';area.appendChild(t);setTimeout(function(){if(t.parentElement)t.remove();},10000);}
document.querySelectorAll(".tab-panel").forEach(function(e){if(!e.classList.contains("active"))e.style.display="none";});
</script></body></html>`;
}

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log("App Monitor rodando na porta " + PORT));
