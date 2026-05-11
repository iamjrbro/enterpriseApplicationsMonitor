const axios = require("axios");

const graphRequest = async (url, accessToken) => {
  try {
    const response = await axios.get(`https://graph.microsoft.com/v1.0${url}`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    return response.data;
  } catch (error) {
    console.error("Erro no Graph:", error.response?.data || error.message);
    throw error;
  }
};

const graphRequestPaged = async (url, accessToken, limit = 10000) => {
  let results = [];
  let nextUrl = `https://graph.microsoft.com/v1.0${url}`;

  while (nextUrl && results.length < limit) {
    try {
      const response = await axios.get(nextUrl, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      const data = response.data;
      if (data.value) results = results.concat(data.value);
      nextUrl = data["@odata.nextLink"] || null;
      if (results.length >= limit) { results = results.slice(0, limit); break; }
    } catch (error) {
      console.error("Erro no Graph (paged):", error.response?.data || error.message);
      throw error;
    }
  }

  return { value: results };
};

const getUsers = (token) => graphRequestPaged(
  "/users?$select=displayName,userPrincipalName,accountEnabled,userType,createdDateTime,lastPasswordChangeDateTime&$top=999",
  token, 10000
);

const getApps = (token) => graphRequestPaged(
  "/applications?$select=displayName,appId,requiredResourceAccess,createdDateTime,signInAudience&$top=999",
  token, 10000
);

// Busca TODOS os service principals para resolver nomes de permissoes
const getServicePrincipals = (token) => graphRequestPaged(
  "/servicePrincipals?$select=displayName,appId,oauth2PermissionScopes,appRoles&$top=999",
  token, 10000
);

// Busca o SP do Microsoft Graph diretamente pelo appId oficial
// Esse e o SP que contem a maioria das permissoes (Mail.Read, User.Read.All, etc)
const getMicrosoftGraphSP = async (token) => {
  try {
    // AppId fixo do Microsoft Graph em todos os tenants
    const GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000";
    return await graphRequest(
      `/servicePrincipals?$filter=appId eq '${GRAPH_APP_ID}'&$select=displayName,appId,oauth2PermissionScopes,appRoles`,
      token
    );
  } catch (e) {
    console.error("Erro ao buscar SP do Microsoft Graph:", e.message);
    return { value: [] };
  }
};

// Busca SP do Exchange Online
const getExchangeSP = async (token) => {
  try {
    const EXCHANGE_APP_ID = "00000002-0000-0ff1-ce00-000000000000";
    return await graphRequest(
      `/servicePrincipals?$filter=appId eq '${EXCHANGE_APP_ID}'&$select=displayName,appId,oauth2PermissionScopes,appRoles`,
      token
    );
  } catch (e) {
    return { value: [] };
  }
};

// Busca SP do SharePoint
const getSharePointSP = async (token) => {
  try {
    const SP_APP_ID = "00000003-0000-0ff1-ce00-000000000000";
    return await graphRequest(
      `/servicePrincipals?$filter=appId eq '${SP_APP_ID}'&$select=displayName,appId,oauth2PermissionScopes,appRoles`,
      token
    );
  } catch (e) {
    return { value: [] };
  }
};

const getConditionalAccess = (token) => graphRequest("/identity/conditionalAccess/policies", token);
const getDirectoryRoles    = (token) => graphRequest("/directoryRoles", token);
const getRoleMembers       = (roleId, token) => graphRequest(`/directoryRoles/${roleId}/members?$select=displayName,userPrincipalName`, token);

module.exports = {
  getUsers,
  getConditionalAccess,
  getDirectoryRoles,
  getRoleMembers,
  getApps,
  getServicePrincipals,
  getMicrosoftGraphSP,
  getExchangeSP,
  getSharePointSP,
};