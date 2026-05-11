require("dotenv").config();
const express = require("express");
const { ConfidentialClientApplication } = require("@azure/msal-node");

const app = express();
const REDIRECT_URI = "http://localhost:3000/callback";

const cca = new ConfidentialClientApplication({
  auth: {
    clientId: process.env.CLIENT_ID,
    authority: "https://login.microsoftonline.com/common",
    clientSecret: process.env.CLIENT_SECRET,
  },
});

const sessions = {};

// ─── Graph helpers ────────────────────────────────────────────────────────────

async function graphGet(token, path) {
  const res = await fetch("https://graph.microsoft.com/v1.0" + path, {
    headers: { Authorization: "Bearer " + token },
  });
  if (!res.ok) throw new Error("Graph error " + res.status + " on " + path);
  return res.json();
}

async function graphGetAll(token, path) {
  let results = [];
  let url = "https://graph.microsoft.com/v1.0" + path;
  while (url) {
    const res = await fetch(url, { headers: { Authorization: "Bearer " + token } });
    if (!res.ok) throw new Error("Graph error " + res.status);
    const data = await res.json();
    results = results.concat(data.value || []);
    url = data["@odata.nextLink"] || null;
  }
  return results;
}

// ─── Data collection ──────────────────────────────────────────────────────────

async function collectApps(token) {
  const [apps, servicePrincipals, auditLogs] = await Promise.all([
    graphGetAll(token, "/applications?$select=id,appId,displayName,createdDateTime,signInAudience,requiredResourceAccess,owners,web,spa,publicClient,notes,description"),
    graphGetAll(token, "/servicePrincipals?$select=appId,displayName,appRoles,oauth2PermissionScopes"),
    fetchAuditLogs(token),
  ]);

  // Build SP map for permission name resolution
  const spMap = {};
  for (const sp of servicePrincipals) {
    spMap[sp.appId] = sp;
  }

  // Build creator map from audit logs
  const creatorMap = {};
  for (const log of auditLogs) {
    if (log.operationType === "Add" && log.category === "Application" && log.targetResources) {
      for (const target of log.targetResources) {
        if (target.type === "Application" && !creatorMap[target.id]) {
          creatorMap[target.id] = {
            name: log.initiatedBy?.user?.displayName || log.initiatedBy?.app?.displayName || "Desconhecido",
            email: log.initiatedBy?.user?.userPrincipalName || null,
            date: log.activityDateTime,
          };
        }
      }
    }
  }

  // Fetch owners for each app (parallel, capped)
  const ownerPromises = apps.map((a) =>
    graphGet(token, "/applications/" + a.id + "/owners?$select=displayName,userPrincipalName,id")
      .then((r) => ({ appId: a.id, owners: r.value || [] }))
      .catch(() => ({ appId: a.id, owners: [] }))
  );
  const ownersResults = await Promise.all(ownerPromises);
  const ownerMap = {};
  for (const o of ownersResults) ownerMap[o.appId] = o.owners;

  // Resolve permissions
  const enriched = apps.map((app) => {
    const appRoles = [];
    const delegated = [];

    for (const resource of app.requiredResourceAccess || []) {
      const sp = spMap[resource.resourceAppId];
      const resourceName = sp ? sp.displayName : resource.resourceAppId;

      for (const acc of resource.resourceAccess || []) {
        if (acc.type === "Role") {
          const def = sp?.appRoles?.find((r) => r.id === acc.id);
          appRoles.push({
            id: acc.id,
            name: def?.value || null,
            description: def?.displayName || null,
            resource: resourceName,
          });
        } else if (acc.type === "Scope") {
          const def = sp?.oauth2PermissionScopes?.find((s) => s.id === acc.id);
          delegated.push({
            id: acc.id,
            name: def?.value || null,
            description: def?.adminConsentDisplayName || null,
            resource: resourceName,
          });
        }
      }
    }

    const creator = creatorMap[app.id] || null;
    const owners = ownerMap[app.id] || [];
    const riskScore = calcRisk(appRoles, delegated);

    return {
      ...app,
      appRoles,
      delegated,
      creator,
      owners,
      riskScore,
      riskLevel: riskScore >= 70 ? "critical" : riskScore >= 40 ? "high" : riskScore >= 10 ? "medium" : "low",
    };
  });

  enriched.sort((a, b) => b.riskScore - a.riskScore);
  return enriched;
}

async function fetchAuditLogs(token) {
  try {
    const data = await graphGet(
      token,
      "/auditLogs/directoryAudits?$filter=category eq 'Application' and operationType eq 'Add'&$top=200&$select=activityDateTime,operationType,category,initiatedBy,targetResources"
    );
    return data.value || [];
  } catch {
    return [];
  }
}

function calcRisk(appRoles, delegated) {
  const criticalPerms = [
    "Mail.ReadWrite", "Mail.Send", "Files.ReadWrite.All", "Directory.ReadWrite.All",
    "User.ReadWrite.All", "RoleManagement.ReadWrite.Directory", "Application.ReadWrite.All",
    "Group.ReadWrite.All", "full_access_as_app", "Exchange.ManageAsApp",
  ];
  const highPerms = [
    "Mail.Read", "Files.Read.All", "User.Read.All", "Directory.Read.All",
    "AuditLog.Read.All", "Policy.Read.All", "IdentityRiskyUser.Read.All",
    "Sites.Read.All", "Calendars.ReadWrite",
  ];

  let score = 0;
  const all = [...appRoles, ...delegated];
  for (const p of all) {
    if (!p.name) continue;
    if (criticalPerms.some((c) => p.name.includes(c))) score += 30;
    else if (highPerms.some((h) => p.name.includes(h))) score += 15;
    else score += 5;
  }
  // App permissions are riskier than delegated
  score += appRoles.length * 10;
  return Math.min(100, score);
}

// ─── Auth routes ──────────────────────────────────────────────────────────────

app.get("/", async (req, res) => {
  const authUrl = await cca.getAuthCodeUrl({
    scopes: ["User.Read", "Directory.Read.All", "Application.Read.All", "AuditLog.Read.All"],
    redirectUri: REDIRECT_URI,
    prompt: "select_account",
  });
  res.send(buildLoginPage(authUrl));
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
    };

    res.send(buildLoadingPage(sessionId, tokenResponse.tenantId));
  } catch (err) {
    console.error(err);
    res.status(500).send("<h2>Erro de autenticacao</h2><pre>" + err.message + "</pre><a href='/'>Tentar novamente</a>");
  }
});

// ─── SSE progress ─────────────────────────────────────────────────────────────

app.get("/progress/:sessionId", (req, res) => {
  const session = sessions[req.params.sessionId];
  if (!session) return res.status(404).end();

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();

  const send = (data) => res.write("data: " + JSON.stringify(data) + "\n\n");

  (async () => {
    try {
      send({ type: "step", label: "Conectando ao tenant " + session.tenantId + "..." });
      await new Promise((r) => setTimeout(r, 300));

      send({ type: "step", label: "Buscando App Registrations..." });
      const apps = await collectApps(session.token);
      session.apps = apps;

      send({ type: "step", label: apps.length + " apps encontrados. Resolvendo permissoes..." });
      await new Promise((r) => setTimeout(r, 200));

      const critical = apps.filter((a) => a.riskLevel === "critical").length;
      const high = apps.filter((a) => a.riskLevel === "high").length;
      send({ type: "step", label: critical + " criticos · " + high + " alto risco · Pronto!" });
      send({ type: "done", count: apps.length });
    } catch (err) {
      send({ type: "error", message: err.message });
    }
    res.end();
  })();
});

// ─── Data endpoints ───────────────────────────────────────────────────────────

app.get("/apps/:sessionId", (req, res) => {
  const session = sessions[req.params.sessionId];
  if (!session?.apps) return res.status(404).json({ error: "Dados nao encontrados" });
  res.json(session.apps);
});

app.get("/refresh/:sessionId", async (req, res) => {
  const session = sessions[req.params.sessionId];
  if (!session) return res.status(404).json({ error: "Sessao nao encontrada" });
  try {
    session.apps = await collectApps(session.token);
    res.json({ count: session.apps.length, updatedAt: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/dashboard/:sessionId", (req, res) => {
  const session = sessions[req.params.sessionId];
  if (!session) return res.status(404).send("Sessao nao encontrada.");
  res.send(buildDashboard(req.params.sessionId, session.tenantId));
});

// ─── Pages ────────────────────────────────────────────────────────────────────

function buildLoginPage(authUrl) {
  return `<!DOCTYPE html><html lang="pt-BR"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>App Registrations · Entra ID</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:"Syne",sans-serif;background:#060912;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center;overflow:hidden}
.bg{position:fixed;inset:0;background:radial-gradient(ellipse 80% 60% at 50% -10%,#1a2744 0%,transparent 70%),radial-gradient(ellipse 40% 40% at 80% 80%,#0f1f44 0%,transparent 60%);pointer-events:none}
.grid{position:fixed;inset:0;background-image:linear-gradient(rgba(59,130,246,.04) 1px,transparent 1px),linear-gradient(90deg,rgba(59,130,246,.04) 1px,transparent 1px);background-size:40px 40px;pointer-events:none}
.card{position:relative;z-index:1;text-align:center;padding:64px 56px;max-width:480px;width:100%}
.icon{font-size:48px;margin-bottom:24px;filter:drop-shadow(0 0 20px rgba(59,130,246,.5))}
h1{font-size:32px;font-weight:800;color:#f1f5f9;margin-bottom:8px;letter-spacing:-1px}
p{color:#64748b;font-size:14px;margin-bottom:40px;line-height:1.6}
.btn{display:inline-flex;align-items:center;gap:10px;background:linear-gradient(135deg,#2563eb,#4f46e5);color:#fff;padding:16px 36px;border-radius:12px;text-decoration:none;font-weight:700;font-size:14px;font-family:"Syne",sans-serif;letter-spacing:.5px;transition:all .2s;box-shadow:0 0 40px rgba(59,130,246,.3)}
.btn:hover{transform:translateY(-2px);box-shadow:0 0 60px rgba(59,130,246,.5)}
.scopes{margin-top:32px;background:rgba(15,23,42,.8);border:1px solid #1e293b;border-radius:10px;padding:16px;text-align:left}
.scopes-title{font-size:11px;color:#475569;font-family:"JetBrains Mono",monospace;margin-bottom:8px;text-transform:uppercase;letter-spacing:.1em}
.scope{font-size:11px;color:#60a5fa;font-family:"JetBrains Mono",monospace;padding:3px 0;display:flex;align-items:center;gap:6px}
.scope::before{content:"→";color:#1d4ed8}
</style></head><body>
<div class="bg"></div><div class="grid"></div>
<div class="card">
  <div class="icon">🔐</div>
  <h1>App Registrations</h1>
  <p>Auditoria completa dos aplicativos registrados no seu tenant Entra ID — permissões, criadores e riscos.</p>
  <a href="${authUrl}" class="btn">↗ Conectar com Microsoft</a>
  <div class="scopes">
    <div class="scopes-title">Permissões solicitadas (read-only)</div>
    <div class="scope">Directory.Read.All</div>
    <div class="scope">Application.Read.All</div>
    <div class="scope">AuditLog.Read.All</div>
  </div>
</div>
</body></html>`;
}

function buildLoadingPage(sessionId, tenantId) {
  return `<!DOCTYPE html><html lang="pt-BR"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Carregando...</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:"Syne",sans-serif;background:#060912;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.bg{position:fixed;inset:0;background:radial-gradient(ellipse 80% 60% at 50% -10%,#1a2744 0%,transparent 70%);pointer-events:none}
.card{position:relative;z-index:1;max-width:520px;width:100%;padding:20px}
h2{font-size:20px;font-weight:800;color:#f1f5f9;margin-bottom:4px}
.tid{font-size:11px;color:#334155;font-family:"JetBrains Mono",monospace;margin-bottom:28px}
.bar-wrap{height:3px;background:#0f172a;border-radius:2px;margin-bottom:28px}
.bar{height:100%;background:linear-gradient(90deg,#2563eb,#7c3aed);border-radius:2px;width:0;transition:width .5s ease}
.steps{display:flex;flex-direction:column;gap:6px}
.step{font-family:"JetBrains Mono",monospace;font-size:12px;padding:10px 14px;border-radius:8px;background:#0a0f1e;border:1px solid #0f172a;color:#475569;display:flex;align-items:center;gap:10px}
.step.active{border-color:#1e3a5f;background:#060d1e;color:#60a5fa}
.step.done{border-color:#14532d;background:#030f05;color:#4ade80}
.spinner{width:12px;height:12px;border:2px solid #1e293b;border-top-color:#3b82f6;border-radius:50%;animation:spin .6s linear infinite;flex-shrink:0}
@keyframes spin{to{transform:rotate(360deg)}}
.reveal{text-align:center;margin-top:36px;display:none}
.count-big{font-size:72px;font-weight:800;color:#3b82f6;line-height:1}
.count-sub{font-size:13px;color:#475569;margin-top:6px;font-family:"JetBrains Mono",monospace}
.btn{display:inline-block;margin-top:24px;padding:14px 36px;background:linear-gradient(135deg,#2563eb,#4f46e5);color:#fff;border-radius:10px;text-decoration:none;font-weight:700;font-family:"Syne",sans-serif}
</style></head><body>
<div class="bg"></div>
<div class="card">
  <h2>Carregando tenant</h2>
  <div class="tid">${tenantId}</div>
  <div class="bar-wrap"><div class="bar" id="bar"></div></div>
  <div class="steps" id="steps"></div>
  <div class="reveal" id="reveal">
    <div class="count-big" id="countBig">—</div>
    <div class="count-sub">apps encontrados</div>
    <a class="btn" href="/dashboard/${sessionId}">Abrir dashboard →</a>
  </div>
</div>
<script>
var steps=document.getElementById("steps"),bar=document.getElementById("bar"),stepCount=0;
var es=new EventSource("/progress/${sessionId}");
es.onmessage=function(e){
  var d=JSON.parse(e.data);
  if(d.type==="step"){
    var el=document.createElement("div");
    el.className="step active";
    el.innerHTML='<div class="spinner"></div><span>'+d.label+'</span>';
    steps.appendChild(el);
    el.scrollIntoView({behavior:"smooth"});
    stepCount++;bar.style.width=Math.min(85,stepCount*25)+"%";
  }
  if(d.type==="done"){
    document.querySelectorAll(".step").forEach(function(s){s.className="step done";s.querySelector(".spinner").style.display="none";});
    bar.style.width="100%";es.close();
    document.getElementById("countBig").textContent=d.count;
    document.getElementById("reveal").style.display="block";
  }
  if(d.type==="error"){
    var err=document.createElement("div");err.className="step";err.style.borderColor="#7f1d1d";err.style.color="#f87171";
    err.innerHTML='<span>✗ '+d.message+'</span>';steps.appendChild(err);es.close();
  }
};
</script></body></html>`;
}

function buildDashboard(sessionId, tenantId) {
  return `<!DOCTYPE html><html lang="pt-BR"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>App Registrations · ${tenantId}</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#060912;--surface:#0c1220;--surface2:#111827;--border:#1a2540;--text:#e2e8f0;--muted:#475569;--accent:#3b82f6;--critical:#ef4444;--high:#f97316;--medium:#eab308;--low:#22c55e;--mono:"JetBrains Mono",monospace;--sans:"Syne",sans-serif}
body{font-family:var(--sans);background:var(--bg);color:var(--text);min-height:100vh}
.bg{position:fixed;inset:0;background:radial-gradient(ellipse 60% 40% at 10% 0%,#101d3d 0%,transparent 60%),radial-gradient(ellipse 40% 40% at 90% 100%,#0d1a35 0%,transparent 60%);pointer-events:none;z-index:0}

/* Header */
.hdr{position:sticky;top:0;z-index:100;background:rgba(6,9,18,.92);backdrop-filter:blur(12px);border-bottom:1px solid var(--border);padding:0 28px;height:60px;display:flex;align-items:center;gap:20px}
.hdr-logo{font-size:16px;font-weight:800;color:#f1f5f9;letter-spacing:-0.5px;display:flex;align-items:center;gap:8px}
.hdr-logo span{color:var(--accent)}
.hdr-tid{font-size:11px;color:var(--muted);font-family:var(--mono);border-left:1px solid var(--border);padding-left:16px}
.hdr-actions{margin-left:auto;display:flex;align-items:center;gap:12px}
.hdr-refresh{background:none;border:1px solid var(--border);color:var(--muted);padding:6px 14px;border-radius:6px;font-family:var(--sans);font-size:12px;cursor:pointer;transition:all .2s;display:flex;align-items:center;gap:6px}
.hdr-refresh:hover{border-color:var(--accent);color:var(--accent)}
.live{display:flex;align-items:center;gap:6px;font-size:11px;color:#22c55e;font-family:var(--mono)}
.live-dot{width:6px;height:6px;background:#22c55e;border-radius:50%;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}

/* Layout */
.wrap{position:relative;z-index:1;max-width:1400px;margin:0 auto;padding:28px 20px}

/* Stats row */
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:24px}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:20px;text-align:center}
.stat-n{font-size:40px;font-weight:800;color:#f1f5f9;line-height:1}
.stat-l{font-size:11px;color:var(--muted);margin-top:4px;font-family:var(--mono)}
.stat-n.c{color:var(--critical)}
.stat-n.h{color:var(--high)}
.stat-n.m{color:var(--medium)}
.stat-n.ok{color:var(--low)}

/* Filters */
.filters{display:flex;gap:10px;margin-bottom:20px;flex-wrap:wrap;align-items:center}
.filter-input{background:var(--surface);border:1px solid var(--border);color:var(--text);padding:9px 14px;border-radius:8px;font-family:var(--mono);font-size:12px;flex:1;min-width:200px;outline:none;transition:border-color .2s}
.filter-input:focus{border-color:var(--accent)}
.filter-input::placeholder{color:var(--muted)}
.filter-btn{background:var(--surface);border:1px solid var(--border);color:var(--muted);padding:9px 16px;border-radius:8px;font-family:var(--sans);font-size:12px;cursor:pointer;transition:all .2s;white-space:nowrap}
.filter-btn:hover,.filter-btn.active{background:rgba(59,130,246,.1);border-color:var(--accent);color:var(--accent)}
.filter-btn.active.c{background:rgba(239,68,68,.1);border-color:var(--critical);color:var(--critical)}
.filter-btn.active.h{background:rgba(249,115,22,.1);border-color:var(--high);color:var(--high)}
.filter-btn.active.m{background:rgba(234,179,8,.1);border-color:var(--medium);color:var(--medium)}
.filter-btn.active.ok2{background:rgba(34,197,94,.1);border-color:var(--low);color:var(--low)}
.sort-select{background:var(--surface);border:1px solid var(--border);color:var(--text);padding:9px 12px;border-radius:8px;font-family:var(--mono);font-size:12px;outline:none;cursor:pointer}

/* App cards */
.apps-grid{display:flex;flex-direction:column;gap:8px}
.app-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;overflow:hidden;transition:border-color .2s}
.app-card:hover{border-color:#2a3d5f}
.app-card.critical{border-left:3px solid var(--critical)}
.app-card.high{border-left:3px solid var(--high)}
.app-card.medium{border-left:3px solid var(--medium)}
.app-card.low{border-left:3px solid var(--border)}

.app-header{display:flex;align-items:center;gap:16px;padding:16px 20px;cursor:pointer;user-select:none}
.app-header:hover .app-name{color:#93c5fd}
.app-avatar{width:36px;height:36px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:700;flex-shrink:0;font-family:var(--mono)}
.app-info{flex:1;min-width:0}
.app-name{font-size:14px;font-weight:700;color:#f1f5f9;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;transition:color .2s}
.app-meta{font-size:11px;color:var(--muted);font-family:var(--mono);margin-top:2px;display:flex;gap:10px;flex-wrap:wrap}
.app-badges{display:flex;align-items:center;gap:8px;flex-shrink:0}
.risk-badge{font-size:10px;font-weight:700;padding:3px 10px;border-radius:20px;font-family:var(--mono);letter-spacing:.05em}
.rb-critical{background:rgba(239,68,68,.15);color:var(--critical);border:1px solid rgba(239,68,68,.3)}
.rb-high{background:rgba(249,115,22,.15);color:var(--high);border:1px solid rgba(249,115,22,.3)}
.rb-medium{background:rgba(234,179,8,.15);color:var(--medium);border:1px solid rgba(234,179,8,.3)}
.rb-low{background:rgba(34,197,94,.15);color:var(--low);border:1px solid rgba(34,197,94,.3)}
.perm-count{font-size:11px;color:var(--muted);font-family:var(--mono)}
.chevron{color:var(--muted);font-size:12px;transition:transform .2s;flex-shrink:0}
.app-card.open .chevron{transform:rotate(180deg)}

/* App detail */
.app-detail{display:none;border-top:1px solid var(--border)}
.app-card.open .app-detail{display:block}
.detail-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:1px;background:var(--border)}
.detail-section{background:var(--surface2);padding:20px}
.ds-title{font-size:10px;color:var(--muted);font-family:var(--mono);text-transform:uppercase;letter-spacing:.1em;margin-bottom:12px;font-weight:700}
.ds-row{display:flex;flex-direction:column;gap:2px;margin-bottom:10px}
.ds-label{font-size:10px;color:var(--muted);font-family:var(--mono)}
.ds-value{font-size:13px;color:#cbd5e1;word-break:break-all}
.ds-value a{color:var(--accent);text-decoration:none}
.perms-section{background:var(--surface2);padding:20px;border-top:1px solid var(--border)}
.perm-group{margin-bottom:16px}
.pg-title{font-size:10px;color:var(--muted);font-family:var(--mono);text-transform:uppercase;letter-spacing:.1em;margin-bottom:8px;display:flex;align-items:center;gap:6px}
.pg-count{background:var(--surface);border:1px solid var(--border);padding:1px 6px;border-radius:10px;font-size:10px}
.perm-list{display:flex;flex-wrap:wrap;gap:6px}
.perm{display:inline-flex;align-items:center;gap:5px;font-size:11px;padding:4px 10px;border-radius:6px;border:1px solid;font-family:var(--mono);cursor:help;position:relative}
.perm-critical{border-color:rgba(239,68,68,.4);color:var(--critical);background:rgba(239,68,68,.08)}
.perm-high{border-color:rgba(249,115,22,.4);color:var(--high);background:rgba(249,115,22,.08)}
.perm-low{border-color:rgba(30,41,59,.8);color:#64748b;background:rgba(15,23,42,.5)}
.perm-type{font-size:8px;opacity:.6;font-weight:700}
.owners-list{display:flex;flex-direction:column;gap:6px}
.owner{display:flex;align-items:center;gap:8px;font-size:12px}
.owner-av{width:24px;height:24px;border-radius:50%;background:linear-gradient(135deg,#1d4ed8,#7c3aed);display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;flex-shrink:0}
.owner-info{font-family:var(--mono)}
.owner-name{color:#94a3b8;font-size:11px}
.owner-email{color:var(--muted);font-size:10px}
.creator-row{display:flex;align-items:center;gap:10px;padding:12px;background:rgba(59,130,246,.05);border:1px solid rgba(59,130,246,.15);border-radius:8px;margin-top:8px}
.creator-icon{font-size:20px}
.creator-name{font-size:13px;color:#93c5fd;font-weight:600}
.creator-email{font-size:11px;color:var(--muted);font-family:var(--mono)}
.creator-date{font-size:10px;color:var(--muted);font-family:var(--mono);margin-top:2px}
.no-data{font-size:12px;color:var(--muted);font-style:italic;font-family:var(--mono)}

/* Empty state */
.empty{text-align:center;padding:60px;color:var(--muted);font-family:var(--mono);font-size:13px}
.empty-icon{font-size:40px;margin-bottom:16px}

/* Spinner anim */
@keyframes spin2{to{transform:rotate(360deg)}}
.spinning{animation:spin2 .8s linear infinite;display:inline-block}

/* Responsive */
@media(max-width:900px){.stats{grid-template-columns:repeat(3,1fr)}.detail-grid{grid-template-columns:1fr}}
@media(max-width:600px){.stats{grid-template-columns:repeat(2,1fr)}}
</style></head><body>
<div class="bg"></div>

<div class="hdr">
  <div class="hdr-logo">🔑 <span>AppReg</span> Audit</div>
  <div class="hdr-tid">${tenantId}</div>
  <div class="hdr-actions">
    <div class="live"><div class="live-dot"></div>LIVE</div>
    <button class="hdr-refresh" id="refreshBtn" onclick="refresh()">↻ Atualizar</button>
    <a href="/" style="font-size:12px;color:var(--muted);text-decoration:none">← Nova sessão</a>
  </div>
</div>

<div class="wrap">
  <div class="stats" id="statsRow">
    <div class="stat"><div class="stat-n" id="sTotal">—</div><div class="stat-l">Total Apps</div></div>
    <div class="stat"><div class="stat-n c" id="sCritical">—</div><div class="stat-l">Críticos</div></div>
    <div class="stat"><div class="stat-n h" id="sHigh">—</div><div class="stat-l">Alto Risco</div></div>
    <div class="stat"><div class="stat-n m" id="sMedium">—</div><div class="stat-l">Médio Risco</div></div>
    <div class="stat"><div class="stat-n ok" id="sLow">—</div><div class="stat-l">Baixo Risco</div></div>
  </div>

  <div class="filters">
    <input class="filter-input" id="searchInput" type="text" placeholder="🔍  Buscar por nome, criador ou permissão..." oninput="render()">
    <button class="filter-btn" id="fb-all" onclick="setFilter('all')">Todos</button>
    <button class="filter-btn c" id="fb-critical" onclick="setFilter('critical')">⚠ Críticos</button>
    <button class="filter-btn h" id="fb-high" onclick="setFilter('high')">▲ Alto</button>
    <button class="filter-btn m" id="fb-medium" onclick="setFilter('medium')">◆ Médio</button>
    <button class="filter-btn ok2" id="fb-low" onclick="setFilter('low')">✓ Baixo</button>
    <select class="sort-select" id="sortSelect" onchange="render()">
      <option value="risk">Ordenar: Risco</option>
      <option value="name">Ordenar: Nome</option>
      <option value="date">Ordenar: Data criação</option>
      <option value="perms">Ordenar: Nº permissões</option>
    </select>
  </div>

  <div id="appsList" class="apps-grid">
    <div class="empty"><div class="empty-icon">⏳</div>Carregando apps...</div>
  </div>
</div>

<script>
var SESSION="${sessionId}";
var allApps=[];
var currentFilter="all";

function fmt(dt){
  if(!dt)return"—";
  return new Date(dt).toLocaleDateString("pt-BR",{day:"2-digit",month:"short",year:"numeric"});
}

function classifyPerm(name){
  if(!name)return"low";
  var crit=["Mail.ReadWrite","Mail.Send","Files.ReadWrite.All","Directory.ReadWrite.All","User.ReadWrite.All","RoleManagement.ReadWrite.Directory","Application.ReadWrite.All","Group.ReadWrite.All","full_access_as_app","Exchange.ManageAsApp"];
  var high=["Mail.Read","Files.Read.All","User.Read.All","Directory.Read.All","AuditLog.Read.All","Policy.Read.All","Sites.Read.All","Calendars.ReadWrite","IdentityRiskyUser.Read.All"];
  if(crit.some(function(c){return name.includes(c);}))return"critical";
  if(high.some(function(h){return name.includes(h);}))return"high";
  return"low";
}

function initials(name){
  if(!name)return"?";
  return name.split(" ").map(function(w){return w[0]||"";}).slice(0,2).join("").toUpperCase();
}

function avatarColor(level){
  return{critical:"background:linear-gradient(135deg,#7f1d1d,#ef4444)",high:"background:linear-gradient(135deg,#7c2d12,#f97316)",medium:"background:linear-gradient(135deg,#713f12,#eab308)",low:"background:linear-gradient(135deg,#14532d,#22c55e)"}[level]||"background:linear-gradient(135deg,#1e3a5f,#3b82f6)";
}

function setFilter(f){
  currentFilter=f;
  document.querySelectorAll(".filter-btn").forEach(function(b){b.classList.remove("active");});
  var btn=document.getElementById("fb-"+f);
  if(btn)btn.classList.add("active");
  render();
}

function render(){
  var q=(document.getElementById("searchInput").value||"").toLowerCase();
  var sort=document.getElementById("sortSelect").value;

  var filtered=allApps.filter(function(a){
    if(currentFilter!=="all"&&a.riskLevel!==currentFilter)return false;
    if(!q)return true;
    var haystack=(a.displayName||"").toLowerCase()+" "+
      (a.creator?a.creator.name+" "+a.creator.email:"").toLowerCase()+" "+
      (a.owners||[]).map(function(o){return o.displayName+" "+o.userPrincipalName;}).join(" ").toLowerCase()+" "+
      (a.appRoles||[]).map(function(p){return p.name||"";}).join(" ").toLowerCase()+" "+
      (a.delegated||[]).map(function(p){return p.name||"";}).join(" ").toLowerCase();
    return haystack.includes(q);
  });

  filtered.sort(function(a,b){
    if(sort==="name")return(a.displayName||"").localeCompare(b.displayName||"");
    if(sort==="date")return new Date(b.createdDateTime||0)-new Date(a.createdDateTime||0);
    if(sort==="perms")return((b.appRoles||[]).length+(b.delegated||[]).length)-((a.appRoles||[]).length+(a.delegated||[]).length);
    return b.riskScore-a.riskScore;
  });

  var container=document.getElementById("appsList");

  if(!filtered.length){
    container.innerHTML='<div class="empty"><div class="empty-icon">🔍</div>Nenhum app encontrado</div>';
    return;
  }

  container.innerHTML=filtered.map(function(a){
    var totalPerms=(a.appRoles||[]).length+(a.delegated||[]).length;
    var rbClass="rb-"+a.riskLevel;
    var riskLabel={critical:"CRÍTICO",high:"ALTO",medium:"MÉDIO",low:"BAIXO"}[a.riskLevel]||"—";

    return '<div class="app-card '+a.riskLevel+'" id="card-'+a.appId+'">'+
      '<div class="app-header" onclick="toggle(\''+a.appId+'\')">'+
        '<div class="app-avatar" style="'+avatarColor(a.riskLevel)+'">'+initials(a.displayName)+'</div>'+
        '<div class="app-info">'+
          '<div class="app-name">'+esc(a.displayName||"—")+'</div>'+
          '<div class="app-meta">'+
            '<span>'+a.appId+'</span>'+
            (a.creator?'<span>criado por '+esc(a.creator.name)+'</span>':'<span>criador desconhecido</span>')+
            '<span>'+fmt(a.createdDateTime)+'</span>'+
            (a.signInAudience?'<span>'+esc(a.signInAudience)+'</span>':'')+
          '</div>'+
        '</div>'+
        '<div class="app-badges">'+
          '<span class="risk-badge '+rbClass+'">'+riskLabel+'</span>'+
          '<span class="perm-count">'+totalPerms+' perm'+(totalPerms!==1?'s':'')+'</span>'+
          '<span class="chevron">▼</span>'+
        '</div>'+
      '</div>'+
      '<div class="app-detail" id="detail-'+a.appId+'">'+buildDetail(a)+'</div>'+
    '</div>';
  }).join("");
}

function buildDetail(a){
  var appRoles=a.appRoles||[];
  var delegated=a.delegated||[];
  var owners=a.owners||[];

  // Info section
  var infoHtml='<div class="detail-section">'+
    '<div class="ds-title">Informações do App</div>'+
    '<div class="ds-row"><div class="ds-label">App ID</div><div class="ds-value" style="font-family:var(--mono);font-size:11px">'+esc(a.appId)+'</div></div>'+
    '<div class="ds-row"><div class="ds-label">Object ID</div><div class="ds-value" style="font-family:var(--mono);font-size:11px">'+esc(a.id)+'</div></div>'+
    '<div class="ds-row"><div class="ds-label">Criado em</div><div class="ds-value">'+fmt(a.createdDateTime)+'</div></div>'+
    '<div class="ds-row"><div class="ds-label">Audiência</div><div class="ds-value">'+esc(a.signInAudience||"—")+'</div></div>'+
    (a.description?'<div class="ds-row"><div class="ds-label">Descrição</div><div class="ds-value">'+esc(a.description)+'</div></div>':'')+
    (a.notes?'<div class="ds-row"><div class="ds-label">Notas</div><div class="ds-value">'+esc(a.notes)+'</div></div>':'')+
    '<div class="ds-row"><div class="ds-label">Risk Score</div><div class="ds-value" style="font-family:var(--mono);font-size:20px;font-weight:700;color:'+riskColor(a.riskLevel)+'">'+a.riskScore+'/100</div></div>'+
  '</div>';

  // Creator + owners
  var creatorHtml='<div class="detail-section">'+
    '<div class="ds-title">Criador & Responsáveis</div>';

  if(a.creator){
    creatorHtml+='<div class="creator-row">'+
      '<div class="creator-icon">👤</div>'+
      '<div>'+
        '<div class="creator-name">'+esc(a.creator.name)+'</div>'+
        (a.creator.email?'<div class="creator-email">'+esc(a.creator.email)+'</div>':'')+
        '<div class="creator-date">Criou em '+fmt(a.creator.date)+'</div>'+
      '</div>'+
    '</div>';
  } else {
    creatorHtml+='<div class="no-data">Criador não encontrado nos audit logs</div>';
  }

  if(owners.length){
    creatorHtml+='<div class="ds-title" style="margin-top:16px">Owners ('+owners.length+')</div><div class="owners-list">';
    creatorHtml+=owners.map(function(o){
      return '<div class="owner">'+
        '<div class="owner-av">'+initials(o.displayName)+'</div>'+
        '<div class="owner-info"><div class="owner-name">'+esc(o.displayName||"—")+'</div><div class="owner-email">'+esc(o.userPrincipalName||"")+'</div></div>'+
      '</div>';
    }).join("");
    creatorHtml+='</div>';
  } else {
    creatorHtml+='<div class="ds-title" style="margin-top:16px">Owners</div><div class="no-data">Sem owners configurados</div>';
  }

  creatorHtml+='</div>';

  // Redirect URIs
  var uris=[];
  if(a.web&&a.web.redirectUris)uris=uris.concat(a.web.redirectUris);
  if(a.spa&&a.spa.redirectUris)uris=uris.concat(a.spa.redirectUris);
  if(a.publicClient&&a.publicClient.redirectUris)uris=uris.concat(a.publicClient.redirectUris);
  var uriHtml='<div class="detail-section">'+
    '<div class="ds-title">Redirect URIs ('+uris.length+')</div>';
  if(uris.length){
    uriHtml+=uris.map(function(u){return'<div class="ds-row"><div class="ds-value" style="font-family:var(--mono);font-size:11px;word-break:break-all">'+esc(u)+'</div></div>';}).join("");
  } else {
    uriHtml+='<div class="no-data">Nenhum redirect URI</div>';
  }
  uriHtml+='</div>';

  // Permissions
  var permsHtml='<div class="perms-section">';

  if(appRoles.length){
    permsHtml+='<div class="perm-group">'+
      '<div class="pg-title">Application Permissions <span class="pg-count">'+appRoles.length+'</span> <span style="font-size:9px;opacity:.5">Não requerem usuário — maior risco</span></div>'+
      '<div class="perm-list">'+
        appRoles.map(function(p){
          var cls="perm-"+classifyPerm(p.name);
          var label=p.name||("["+p.id.substring(0,8)+"...]");
          var tip=p.description||(p.resource+" · "+label);
          return'<span class="perm '+cls+'" title="'+esc(tip)+'"><span class="perm-type">APP</span>'+esc(label)+'</span>';
        }).join("")+
      '</div>'+
    '</div>';
  }

  if(delegated.length){
    permsHtml+='<div class="perm-group">'+
      '<div class="pg-title">Delegated Permissions <span class="pg-count">'+delegated.length+'</span></div>'+
      '<div class="perm-list">'+
        delegated.map(function(p){
          var cls="perm-"+classifyPerm(p.name);
          var label=p.name||("["+p.id.substring(0,8)+"...]");
          var tip=p.description||(p.resource+" · "+label);
          return'<span class="perm '+cls+'" title="'+esc(tip)+'"><span class="perm-type">DEL</span>'+esc(label)+'</span>';
        }).join("")+
      '</div>'+
    '</div>';
  }

  if(!appRoles.length&&!delegated.length){
    permsHtml+='<div class="no-data">Sem permissões registradas</div>';
  }

  permsHtml+='</div>';

  return'<div class="detail-grid">'+infoHtml+creatorHtml+uriHtml+'</div>'+permsHtml;
}

function riskColor(level){
  return{critical:"var(--critical)",high:"var(--high)",medium:"var(--medium)",low:"var(--low)"}[level]||"var(--muted)";
}

function esc(s){
  if(!s)return"";
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

function toggle(appId){
  var card=document.getElementById("card-"+appId);
  card.classList.toggle("open");
}

function updateStats(apps){
  document.getElementById("sTotal").textContent=apps.length;
  document.getElementById("sCritical").textContent=apps.filter(function(a){return a.riskLevel==="critical";}).length;
  document.getElementById("sHigh").textContent=apps.filter(function(a){return a.riskLevel==="high";}).length;
  document.getElementById("sMedium").textContent=apps.filter(function(a){return a.riskLevel==="medium";}).length;
  document.getElementById("sLow").textContent=apps.filter(function(a){return a.riskLevel==="low";}).length;
}

function refresh(){
  var btn=document.getElementById("refreshBtn");
  btn.innerHTML='<span class="spinning">↻</span> Atualizando...';
  btn.disabled=true;
  fetch("/refresh/"+SESSION)
    .then(function(r){return r.json();})
    .then(function(){return fetch("/apps/"+SESSION);})
    .then(function(r){return r.json();})
    .then(function(data){
      allApps=data;
      updateStats(data);
      render();
    })
    .catch(function(err){alert("Erro: "+err.message);})
    .finally(function(){btn.innerHTML="↻ Atualizar";btn.disabled=false;});
}

// Initial load
document.getElementById("fb-all").classList.add("active");
fetch("/apps/"+SESSION)
  .then(function(r){return r.json();})
  .then(function(data){
    allApps=data;
    updateStats(data);
    render();
  })
  .catch(function(err){
    document.getElementById("appsList").innerHTML='<div class="empty"><div class="empty-icon">❌</div>Erro ao carregar: '+err.message+'</div>';
  });
</script></body></html>`;
}

app.listen(3000, () => console.log("🔑 App Registrations Audit rodando em http://localhost:3000"));