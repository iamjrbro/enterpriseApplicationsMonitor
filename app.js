require("dotenv").config();

const express = require("express");
const session = require("express-session");
const { ConfidentialClientApplication } = require("@azure/msal-node");
const axios = require("axios");

const app = express();

app.set("trust proxy", 1);

app.use(
  session({
    secret: process.env.SESSION_SECRET || "super-secret-key",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: true,
      sameSite: "none",
    },
  })
);

const PORT = process.env.PORT || 3001;

const REDIRECT_URI =
  process.env.REDIRECT_URI ||
  "https://enterprise-applications-monitor.onrender.com/callback";

const cca = new ConfidentialClientApplication({
  auth: {
    clientId: process.env.CLIENT_ID,
    authority:
      "https://login.microsoftonline.com/organizations",
    clientSecret: process.env.CLIENT_SECRET,
  },
});

// ─────────────────────────────────────────────────────────────
// SUGESTÕES DE PERMISSÕES
// ─────────────────────────────────────────────────────────────

const RECOMMENDED_PERMISSIONS = {
  "Microsoft Graph": {
    delegated: ["User.Read"],
    app: [],
  },

  "Office 365 Exchange Online": {
    delegated: [],
    app: [],
  },
};

const HIGH_RISK_PERMISSIONS = [
  "Directory.ReadWrite.All",
  "Directory.AccessAsUser.All",
  "RoleManagement.ReadWrite.Directory",
  "Application.ReadWrite.All",
  "AppRoleAssignment.ReadWrite.All",
  "User.ReadWrite.All",
  "Group.ReadWrite.All",
  "Files.ReadWrite.All",
  "Files.ReadWrite",
  "Mail.ReadWrite",
  "Mail.Send",
  "full_access_as_app",
];

function generatePermissionSuggestions(application) {
  const suggestions = {
    recommended: [],
    removable: [],
    warnings: [],
  };

  const delegated = (application.delegated || []).map(
    p => ({
      resource: p.resource,
      name: p.name,
    })
  );

  const appPerms = (application.appRoles || []).map(
    p => ({
      resource: p.resource,
      name: p.name,
    })
  );

  Object.keys(RECOMMENDED_PERMISSIONS).forEach(
    resource => {
      const currentDelegated = delegated
        .filter(p => p.resource === resource)
        .map(p => p.name);

      const currentApp = appPerms
        .filter(p => p.resource === resource)
        .map(p => p.name);

      const expectedDelegated =
        RECOMMENDED_PERMISSIONS[resource]
          .delegated;

      const expectedApp =
        RECOMMENDED_PERMISSIONS[resource].app;

      expectedDelegated.forEach(p => {
        if (!currentDelegated.includes(p)) {
          suggestions.recommended.push({
            type: "Delegated",
            permission: p,
            resource,
          });
        }
      });

      expectedApp.forEach(p => {
        if (!currentApp.includes(p)) {
          suggestions.recommended.push({
            type: "Application",
            permission: p,
            resource,
          });
        }
      });
    }
  );

  delegated.forEach(p => {
    if (HIGH_RISK_PERMISSIONS.includes(p.name)) {
      suggestions.removable.push({
        type: "Delegated",
        permission: p.name,
        resource: p.resource,
        reason:
          "Permissão considerada de alto privilégio",
      });
    }
  });

  appPerms.forEach(p => {
    if (HIGH_RISK_PERMISSIONS.includes(p.name)) {
      suggestions.removable.push({
        type: "Application",
        permission: p.name,
        resource: p.resource,
        reason:
          "Permissão considerada de alto privilégio",
      });
    }
  });

  if ((application.appRoles || []).length > 0) {
    suggestions.warnings.push(
      "Aplicação possui Application Permissions (acesso sem usuário)"
    );
  }

  if (
    !application._owners ||
    application._owners.length === 0
  ) {
    suggestions.warnings.push(
      "Aplicação sem owner definido"
    );
  }

  return suggestions;
}

// ─────────────────────────────────────────────────────────────
// GRAPH HELPERS
// ─────────────────────────────────────────────────────────────

async function graphGet(url, token) {
  const res = await axios.get(
    "https://graph.microsoft.com/v1.0" + url,
    {
      headers: {
        Authorization: "Bearer " + token,
      },
    }
  );

  return res.data;
}

async function graphPaged(url, token, limit) {
  limit = limit || 10000;

  let results = [];
  let nextUrl =
    "https://graph.microsoft.com/v1.0" + url;

  while (nextUrl && results.length < limit) {
    const res = await axios.get(nextUrl, {
      headers: {
        Authorization: "Bearer " + token,
      },
    });

    const data = res.data;

    if (data.value) {
      results = results.concat(data.value);
    }

    nextUrl = data["@odata.nextLink"] || null;

    if (results.length >= limit) {
      results = results.slice(0, limit);
      break;
    }
  }

  return {
    value: results,
  };
}

// ─────────────────────────────────────────────────────────────
// APPS
// ─────────────────────────────────────────────────────────────

async function getApps(token) {
  return graphPaged(
    "/applications?$select=displayName,appId,id,requiredResourceAccess,createdDateTime,signInAudience,notes,tags,passwordCredentials&$top=999",
    token,
    10000
  );
}

async function getAppOwners(appObjectId, token) {
  try {
    const res = await graphGet(
      "/applications/" +
        appObjectId +
        "/owners?$select=displayName,userPrincipalName,mail",
      token
    );

    return res.value || [];
  } catch (e) {
    return [];
  }
}

async function getAuditLogs(token) {
  try {
    const since = new Date(
      Date.now() - 30 * 24 * 60 * 60 * 1000
    ).toISOString();

    const res = await graphPaged(
      "/auditLogs/directoryAudits?$filter=category eq 'ApplicationManagement' and activityDateTime ge " +
        since +
        "&$select=activityDateTime,activityDisplayName,initiatedBy,targetResources,result&$top=999",
      token,
      5000
    );

    return res.value || [];
  } catch (e) {
    console.error("Erro audit logs:", e.message);
    return [];
  }
}

function resolveActor(log) {
  const ib = log.initiatedBy;

  if (!ib) return null;

  if (ib.user) {
    const u = ib.user;

    return (
      u.displayName ||
      u.userPrincipalName ||
      u.id ||
      "Usuário desconhecido"
    );
  }

  if (ib.app) {
    const a = ib.app;

    return (
      (a.displayName || a.appId || "App desconhecido") +
      " [app]"
    );
  }

  return "Sistema";
}

async function getAllSPs(token) {
  return graphPaged(
    "/servicePrincipals?$select=displayName,appId,oauth2PermissionScopes,appRoles&$top=999",
    token,
    10000
  );
}

async function getSpecificSP(appId, token) {
  try {
    const res = await graphGet(
      "/servicePrincipals?$filter=appId eq '" +
        appId +
        "'&$select=displayName,appId,oauth2PermissionScopes,appRoles",
      token
    );

    return res.value || [];
  } catch (e) {
    return [];
  }
}

// ─────────────────────────────────────────────────────────────
// COLETA
// ─────────────────────────────────────────────────────────────

async function collectApps(token) {
  const [
    appsData,
    allSPs,
    msGraphSPs,
    exchangeSPs,
    auditLogs,
  ] = await Promise.all([
    getApps(token),
    getAllSPs(token),
    getSpecificSP(
      "00000003-0000-0000-c000-000000000000",
      token
    ),
    getSpecificSP(
      "00000002-0000-0ff1-ce00-000000000000",
      token
    ),
    getAuditLogs(token),
  ]);

  const spMap = {};

  for (const sp of allSPs.value) {
    spMap[sp.appId] = sp;
  }

  for (const sp of [
    ...msGraphSPs,
    ...exchangeSPs,
  ]) {
    spMap[sp.appId] = sp;
  }

  const apps = appsData.value;
  const appsEnriched = [];

  for (const application of apps) {
    application._owners = await getAppOwners(
      application.id,
      token
    );

    const appRoles = [];
    const delegated = [];

    if (application.requiredResourceAccess) {
      for (const resource of application.requiredResourceAccess) {
        const resourceSp =
          spMap[resource.resourceAppId];

        for (const access of resource.resourceAccess) {
          if (access.type === "Role") {
            const roleDef =
              resourceSp &&
              resourceSp.appRoles &&
              resourceSp.appRoles.find(
                r => r.id === access.id
              );

            appRoles.push({
              id: access.id,
              name: roleDef
                ? roleDef.value
                : null,
              description: roleDef
                ? roleDef.displayName
                : null,
              resource: resourceSp
                ? resourceSp.displayName
                : resource.resourceAppId,
            });
          } else {
            const scopeDef =
              resourceSp &&
              resourceSp.oauth2PermissionScopes &&
              resourceSp.oauth2PermissionScopes.find(
                s => s.id === access.id
              );

            delegated.push({
              id: access.id,
              name: scopeDef
                ? scopeDef.value
                : null,
              description: scopeDef
                ? scopeDef.adminConsentDisplayName
                : null,
              resource: resourceSp
                ? resourceSp.displayName
                : resource.resourceAppId,
            });
          }
        }
      }
    }

    const secrets = (
      application.passwordCredentials || []
    ).map(cred => {
      const now = Date.now();

      const expDate = cred.endDateTime
        ? new Date(cred.endDateTime)
        : null;

      const daysToExp = expDate
        ? Math.ceil(
            (expDate.getTime() - now) /
              86400000
          )
        : null;

      let status = "ativa";

      if (!expDate) {
        status = "sem-expiracao";
      } else if (daysToExp < 0) {
        status = "expirada";
      } else if (daysToExp <= 30) {
        status = "expirando";
      }

      return {
        hint: cred.hint || "***",
        displayName:
          cred.displayName || "Secret",
        startDate: cred.startDateTime,
        endDate: cred.endDateTime,
        daysToExp,
        status,
      };
    });

    application.appRoles = appRoles;
    application.delegated = delegated;
    application.secrets = secrets;

    application.internalNotes =
      application.notes ||
      "Sem notas internas";

    application.suggestions =
      generatePermissionSuggestions(
        application
      );

    appsEnriched.push(application);
  }

  return appsEnriched;
}

// ─────────────────────────────────────────────────────────────
// AUTH
// ─────────────────────────────────────────────────────────────

app.get("/", async (req, res) => {
  try {
    req.session.destroy(() => {});

    const authUrl = await cca.getAuthCodeUrl({
      scopes: [
        "User.Read",
        "Directory.Read.All",
        "Application.Read.All",
        "AuditLog.Read.All",
      ],

      redirectUri: REDIRECT_URI,

      prompt: "select_account",
    });

    res.redirect(authUrl);
  } catch (err) {
    console.error(err);

    res.status(500).send(err.message);
  }
});

app.get("/callback", async (req, res) => {
  try {
    if (!req.query.code) {
      return res
        .status(400)
        .send("Código OAuth não encontrado.");
    }

    if (req.session.authenticated) {
      return res.redirect("/dashboard");
    }

    const tokenResponse =
      await cca.acquireTokenByCode({
        code: req.query.code,

        scopes: [
          "User.Read",
          "Directory.Read.All",
          "Application.Read.All",
          "AuditLog.Read.All",
        ],

        redirectUri: REDIRECT_URI,
      });

    req.session.authenticated = true;

    req.session.accessToken =
      tokenResponse.accessToken;

    const apps = await collectApps(
      tokenResponse.accessToken
    );

    req.session.apps = apps;

    res.redirect("/dashboard");
  } catch (err) {
    console.error(err);

    res.status(500).send(`
      <h2>Erro OAuth</h2>
      <pre>${err.message}</pre>
    `);
  }
});

// ─────────────────────────────────────────────────────────────
// DASHBOARD
// ─────────────────────────────────────────────────────────────

app.get("/dashboard", async (req, res) => {
  if (!req.session.apps) {
    return res.redirect("/");
  }

  const apps = req.session.apps;

  let html = `
  <html>
  <head>
    <title>Enterprise App Monitor</title>

    <style>

      body{
        background:#081018;
        color:#fff;
        font-family:Arial;
        padding:20px;
      }

      h1{
        margin-bottom:30px;
      }

      .card{
        background:#0f172a;
        border:1px solid #1e293b;
        border-radius:12px;
        padding:20px;
        margin-bottom:20px;
      }

      .perm{
        display:inline-block;
        padding:5px 10px;
        border-radius:6px;
        margin:4px;
        background:#1e293b;
        font-size:12px;
      }

      .danger{
        color:#ef4444;
      }

      .warn{
        color:#f59e0b;
      }

      .ok{
        color:#4ade80;
      }

      pre{
        white-space:pre-wrap;
      }

      hr{
        border:0;
        border-top:1px solid #1e293b;
        margin:20px 0;
      }

    </style>
  </head>

  <body>

    <h1>Enterprise App Monitor</h1>
  `;

  for (const appData of apps) {
    html += `
      <div class="card">

        <h2>
          ${appData.displayName || "Sem nome"}
        </h2>

        <p>
          <strong>App ID:</strong>
          ${appData.appId}
        </p>

        <p>
          <strong>Internal Notes:</strong>
        </p>

        <pre>${appData.internalNotes}</pre>

        <hr>

        <h3>Permissões</h3>

        ${(appData.appRoles || [])
          .map(
            p =>
              `<span class="perm">${p.name}</span>`
          )
          .join("")}

        ${(appData.delegated || [])
          .map(
            p =>
              `<span class="perm">${p.name}</span>`
          )
          .join("")}

        <hr>

        <h3>Sugestões</h3>

        <h4 class="ok">
          Permissões recomendadas ausentes
        </h4>

        ${
          appData.suggestions.recommended
            .length === 0
            ? "<p>Nenhuma</p>"
            : appData.suggestions.recommended
                .map(
                  s =>
                    `<div class="ok">
                      + ${s.permission}
                      (${s.type})
                    </div>`
                )
                .join("")
        }

        <h4 class="warn">
          Permissões possivelmente removíveis
        </h4>

        ${
          appData.suggestions.removable
            .length === 0
            ? "<p>Nenhuma</p>"
            : appData.suggestions.removable
                .map(
                  s =>
                    `<div class="warn">
                      - ${s.permission}
                      (${s.type})
                    </div>`
                )
                .join("")
        }

        <h4 class="danger">
          Alertas
        </h4>

        ${
          appData.suggestions.warnings
            .length === 0
            ? "<p>Nenhum</p>"
            : appData.suggestions.warnings
                .map(
                  w =>
                    `<div class="danger">
                      ${w}
                    </div>`
                )
                .join("")
        }

      </div>
    `;
  }

  html += `
    </body>
    </html>
  `;

  res.send(html);
});

// ─────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(
    "📦 App Monitor rodando na porta " +
      PORT
  );
});