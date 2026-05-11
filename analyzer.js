const analyze = async (data) => {
  const findings = [];
  const recommendations = [];
  let score = 100;

  const activeUsers    = data.users.filter(u => u.accountEnabled && u.userType !== "Guest");
  const disabledUsers  = data.users.filter(u => !u.accountEnabled);
  const guestUsers     = data.users.filter(u => u.userType === "Guest");
  const activePolicies = data.policies.filter(p => p.state === "enabled");

  // 1. Global Admins
  if (data.globalAdmins.length > 3) {
    score -= 20;
    findings.push({
      type: "critical",
      category: "Identidade",
      text: `${data.globalAdmins.length} Global Administrators (max recomendado: 3)`,
      items: data.globalAdmins.map(u => u.displayName || u.userPrincipalName),
    });
    recommendations.push({ severity: "alta", text: "Reduza o numero de Global Admins para no maximo 3. Use roles especificas como User Administrator, Exchange Administrator ou Security Administrator." });
  } else {
    findings.push({
      type: "ok",
      category: "Identidade",
      text: `Global Admins OK (${data.globalAdmins.length})`,
      items: data.globalAdmins.map(u => u.displayName || u.userPrincipalName),
    });
  }

  // 2. MFA
  const hasMfaPolicy = data.policies.some(p =>
    JSON.stringify(p).toLowerCase().includes("mfa") ||
    JSON.stringify(p).toLowerCase().includes("multifactor")
  );
  if (!hasMfaPolicy) {
    score -= 25;
    findings.push({ type: "critical", category: "MFA", text: "Nenhuma politica de MFA detectada no Conditional Access", items: [] });
    recommendations.push({ severity: "alta", text: "Crie imediatamente uma politica de Conditional Access exigindo MFA para todos os usuarios. Use Security Defaults se nao tiver licenca P1/P2." });
  } else {
    findings.push({ type: "ok", category: "MFA", text: "Politica de MFA detectada", items: [] });
  }

  // 3. Usuarios desabilitados — SEM LIMITE
  if (disabledUsers.length > 0) {
    score -= 10;
    findings.push({
      type: "warning",
      category: "Usuarios",
      text: `${disabledUsers.length} usuarios desabilitados (contas zumbi)`,
      items: disabledUsers.map(u => u.userPrincipalName), // todos, sem slice
    });
    recommendations.push({ severity: "media", text: "Revise e remova usuarios desabilitados. Contas inativas podem manter permissoes residuais em sistemas integrados e ser reativadas por atacantes." });
  }

  // 4. Guests — SEM LIMITE
  if (guestUsers.length > 5) {
    score -= 10;
    findings.push({
      type: "warning",
      category: "Usuarios",
      text: `${guestUsers.length} usuarios Guest no tenant`,
      items: guestUsers.map(u => u.userPrincipalName), // todos, sem slice
    });
    recommendations.push({ severity: "media", text: "Implemente revisoes periodicas de acesso (Access Reviews) para usuarios Guest. Remova guests que nao acessam ha mais de 90 dias." });
  } else if (guestUsers.length > 0) {
    findings.push({
      type: "info",
      category: "Usuarios",
      text: `${guestUsers.length} usuarios Guest (dentro do limite)`,
      items: guestUsers.map(u => u.userPrincipalName),
    });
  }

  // 5. Apps com Application permissions — SEM LIMITE
  const riskyApps = (data.apps || []).filter(app =>
    app.requiredResourceAccess?.some(r => r.resourceAccess?.some(a => a.type === "Role"))
  );
  if (riskyApps.length > 0) {
    score -= 15;
    findings.push({
      type: "warning",
      category: "Aplicacoes",
      text: `${riskyApps.length} apps com Application permissions (acesso sem usuario)`,
      items: riskyApps.map(a => a.displayName).filter(Boolean), // todos, sem slice
    });
    recommendations.push({ severity: "alta", text: "Audite cada aplicacao com Application permissions. Essas apps acessam dados sem interacao do usuario — um vazamento de secret e critico." });
  } else {
    findings.push({ type: "ok", category: "Aplicacoes", text: "Nenhum app com permissoes excessivas detectado", items: [] });
  }

  // 6. Apps criados recentemente (ultimos 30 dias) — SEM LIMITE
  const recentApps = (data.apps || []).filter(a => {
    if (!a.createdDateTime) return false;
    return (Date.now() - new Date(a.createdDateTime).getTime()) / (1000*60*60*24) <= 30;
  });
  if (recentApps.length > 0) {
    findings.push({
      type: "info",
      category: "Aplicacoes",
      text: `${recentApps.length} app(s) criado(s) nos ultimos 30 dias`,
      items: recentApps.map(a => a.displayName).filter(Boolean), // todos, sem slice
    });
    recommendations.push({ severity: "baixa", text: "Revise apps criados recentemente para garantir que sao legitimos e seguem o processo de aprovacao da organizacao." });
  }

  // 7. Conditional Access
  if (activePolicies.length < 2) {
    score -= 10;
    findings.push({
      type: "warning",
      category: "Conditional Access",
      text: `Apenas ${activePolicies.length} politica(s) ativa(s) de Conditional Access`,
      items: activePolicies.map(p => p.displayName),
    });
    recommendations.push({ severity: "alta", text: "Implemente ao menos 3 politicas: (1) MFA para todos, (2) Bloquear paises nao utilizados, (3) Exigir dispositivo gerenciado para dados sensiveis." });
  } else {
    findings.push({
      type: "ok",
      category: "Conditional Access",
      text: `${activePolicies.length} politicas de Conditional Access ativas`,
      items: activePolicies.map(p => p.displayName),
    });
  }

  // 8. Senhas antigas (mais de 90 dias) — SEM LIMITE
  const oldPassword = data.users.filter(u => {
    if (!u.lastPasswordChangeDateTime || !u.accountEnabled) return false;
    return (Date.now() - new Date(u.lastPasswordChangeDateTime).getTime()) / (1000*60*60*24) > 90;
  });
  if (oldPassword.length > 0) {
    score -= 5;
    findings.push({
      type: "warning",
      category: "Senhas",
      text: `${oldPassword.length} usuarios sem alterar senha ha mais de 90 dias`,
      items: oldPassword.map(u => u.userPrincipalName), // todos, sem slice
    });
    recommendations.push({ severity: "media", text: "Force a troca de senha para usuarios com senhas antigas, especialmente admins. Configure politicas de expiracao de senha no Entra ID." });
  }

  // 9. Total de usuarios ativos
  findings.push({
    type: "info",
    category: "Usuarios",
    text: `${activeUsers.length} usuarios ativos no tenant`,
    items: [],
  });

  score = Math.max(0, score);

  return {
    score,
    findings,
    recommendations,
    stats: {
      totalUsers:     data.users.length,
      activeUsers:    activeUsers.length,
      disabledUsers:  disabledUsers.length,
      guestUsers:     guestUsers.length,
      globalAdmins:   data.globalAdmins.length,
      totalApps:      (data.apps || []).length,
      riskyApps:      riskyApps.length,
      activePolicies: activePolicies.length,
    },
    rawData: {
      users:       data.users,
      apps:        data.apps || [],
      globalAdmins: data.globalAdmins,
      policies:    activePolicies,
    }
  };
};

module.exports = { analyze };