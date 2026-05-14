# Enterprise Applications Monitor

Pensando no controle das API Permissions atribuídas à Enterprise Application no Entra ID, desenvolvi um dashboard que centraliza todas as Enterprise Applications do ambiente e exibe detalhadamente as permissões concedidas a cada uma delas.

A solução utiliza Microsoft Graph API para coletar as informações dos aplicativos registrados no tenant, classificando automaticamente as permissões por nível de criticidade através de indicadores visuais por cores, facilitando a identificação rápida de permissões sensíveis ou excessivas.

Na aba “Sugestões”, o dashboard realiza uma análise automatizada baseada em boas práticas de segurança e princípios de least privilege, indicando permissões que potencialmente poderiam ser removidas para reduzir superfície de ataque e riscos de exposição. A ferramenta atua apenas de forma analítica, ou seja, não executa alterações diretamente nos aplicativos, mantendo o processo de revisão e remoção sob validação da equipe responsável.

Além das permissões, o painel também consolida informações relevantes de governança e auditoria, como data e horário de criação das aplicações, owners atribuídos e atividades registradas relacionadas aos aplicativos, permitindo maior rastreabilidade sobre alterações e movimentações realizadas no ambiente.

O objetivo da ferramenta é apoiar iniciativas de governança, revisão periódica de privilégios, hardening de aplicações corporativas e fortalecimento da postura de segurança do tenant Microsoft Entra ID.


# Como configurar?

Antes de iniciar, certifique-se de possuir o Node.js instalado na máquina.
Crie o projeto:

```bash
npm init -y
```

Instale todas as dependências necessárias:

```bash
npm install express axios 
```

```bash
npm install axios 
```

```bash
npm install dotenv 
```

```bash
npm install @azure/msal-node
```

Bibliotecas utilizadas no projeto:

| Biblioteca | Função |
|---|---|
| express | Responsável pelo servidor web e rotas da aplicação |
| axios | Realiza chamadas HTTP para APIs |
| dotenv | Carrega variáveis de ambiente do arquivo `.env` |
| @azure/msal-node | Responsável pela autenticação Microsoft OAuth e obtenção de tokens |

---

# Estrutura necessária do projeto

Para o funcionamento correto da aplicação, é necessária a criação prévia de uma App Registration no Microsoft Entra ID contendo uma Client Secret válida, permissão Delegated da Microsoft Graph API - User.Read, Application.Read.All e AuditLog.Read.All — além da configuração do Redirect URI correspondente à URL onde o dashboard será executado.

Também é necessário definir o tipo de Supported Account de acordo com as políticas de segurança da organização. Por boas práticas, recomenda-se utilizar o modelo “Single Tenant Only”, restringindo a autenticação exclusivamente a usuários pertencentes ao tenant corporativo.

A aplicação utilizará essa identidade para autenticar-se no Microsoft Graph API via OAuth 2.0 e realizar a coleta das informações do ambiente, incluindo Enterprise Applications, App Registrations, permissões atribuídas, owners, auditorias e demais dados relacionados à governança do tenant Microsoft Entra ID.

---

# Estrutura do projeto

Além do `package.json`, o projeto deve possuir a seguinte estrutura:

```txt
project/
│
├── .env
├── .gitignore
├── analyzer.js
├── app.js
├── graph.js
├── package.json
└── node_modules/
```

---

# Arquivo `.env`

O arquivo `.env` é responsável por armazenar as credenciais da aplicação registradas no Azure.

Nele deverão ser configuradas:

```env
CLIENT_ID=
CLIENT_SECRET=
```

Descrição das variáveis:

| Variável | Função |
|---|---|
| CLIENT_ID | Application (Client) ID da Enterprise Application |
| CLIENT_SECRET | Secret gerada no portal Azure |
| TENANT_ID | ID do tenant Microsoft |

Exemplo:

```env
CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
CLIENT_SECRET=xxxxxxxxxxxxxxxxxxxxxxxx
TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

---

# Arquivo `.gitignore`

O `.gitignore` é obrigatório para proteger credenciais sensíveis e impedir o envio de arquivos privados ao GitHub.

Exemplo recomendado:

```gitignore
node_modules
.env
```

Isso evita exposição de:

- Client Secret
- Tokens
- Dependências locais
- Arquivos sensíveis do ambiente

---

# Arquivo `app.js`

O `app.js` é o ponto principal da aplicação.

Responsabilidades:

- Inicialização do servidor Express
- Rotas da aplicação
- Login Microsoft
- Renderização do dashboard
- Atualização automática dos dados
- Controle geral da interface

---

# Arquivo `graph.js`

O `graph.js` é responsável pela comunicação com o Microsoft Graph API.

Funções principais:

- Autenticação OAuth
- Obtenção de token
- Chamadas para o Graph API
- Coleta de:
  - aplicações
  - permissões
  - owners
  - audit logs
  - secrets
  - activities

Esse arquivo centraliza toda integração com a Microsoft.

---

# Arquivo `analyzer.js`

O `analyzer.js` é responsável pela análise inteligente dos dados coletados.

Funções principais:

- Classificação de risco
- Detecção de permissões perigosas
- Identificação de secrets expiradas
- Sugestões automáticas
- Comparação entre coletas
- Geração de alertas
- Validação de boas práticas

É nele que ocorre a lógica de governança e segurança do sistema.


# COMO O ENTERPRISE APPLICATIONS MONITOR FUNCIONA

## 1. Login e autenticação

Quando o usuário acessa o sistema, ele realiza login utilizando sua conta Microsoft.
Durante a autenticação, a Microsoft retorna um token de acesso OAuth 2.0 contendo permissões autorizadas para leitura do tenant.
Esse token é utilizado para acessar os recursos do ambiente de forma segura através do Microsoft Graph API.

---

## 2. Coleta de dados

Após o login, o sistema inicia automaticamente a coleta de informações utilizando o Microsoft Graph API, a API oficial da Microsoft responsável pelo acesso aos dados do Azure AD / Microsoft Entra ID. 
O sistema busca automaticamente:

- Todas as aplicações registradas
- Todas as Enterprise Applications
- Permissões de cada aplicação
- Owners responsáveis pelos aplicativos
- Secrets cadastradas
- Datas de expiração das credenciais
- Logs de auditoria
- Histórico de alterações
- Usuários responsáveis pelas mudanças
- Data e hora de criação dos aplicativos

Todas as informações são processadas em tempo real e organizadas internamente pelo sistema.

---

## 3. Dashboard visual

Após a coleta, os dados são convertidos em um dashboard visual e interativo.
O sistema organiza automaticamente:

- Aplicações críticas
- Apps sem owner
- Permissões perigosas
- Secrets expiradas
- Alterações recentes
- Alertas de segurança

Tudo é exibido através de tabelas dinâmicas, abas inteligentes, indicadores visuais e alertas automáticos.

---

## 4. Atualização automática

A cada 5 minutos o sistema executa uma nova coleta completa de dados.
Durante esse processo:

- O estado atual é comparado com a última varredura
- Novas permissões são detectadas
- Alterações em aplicativos são identificadas
- Novas secrets são monitoradas
- Remoções também são registradas

Caso alguma mudança seja encontrada, o sistema gera alertas automáticos diretamente na interface.

Exemplos:

- Novo aplicativo criado
- Permissão crítica adicionada
- Secret removida
- Secret expirada
- Alteração de owner
- Consentimento administrativo concedido

---

# Classificação de permissões

Ao dar hover encima da API Permission, o sistema mostra a função da mesma.

## 🔴 Vermelho — Alto risco

Permissões classificadas como vermelhas representam alto impacto de segurança.
Normalmente incluem:

- Controle total do tenant
- Permissões de escrita
- Controle de usuários
- Gerenciamento de diretório
- Controle de aplicações
- Leitura e escrita global

Caso um aplicativo com esse nível de acesso seja comprometido, o impacto pode afetar toda a organização.

---

## 🟡 Amarelo — Médio risco

Permissões amarelas geralmente possuem acesso amplo de leitura.
Essas permissões normalmente:

- Não alteram dados
- Não executam ações administrativas
- Mas permitem acesso massivo a informações organizacionais

Mesmo sem escrita, ainda representam risco de exposição de dados.

---

## 🟢 Verde — Baixo risco

Permissões verdes possuem escopo reduzido e baixo impacto operacional.
Normalmente são:

- Permissões limitadas
- Acessos específicos
- Escopos controlados
- Leituras restritas

São consideradas permissões de menor criticidade.

---

# Funcionamento das abas

Os cards localizados no topo do dashboard funcionam como filtros inteligentes.

Ao clicar em um card:

- A tabela é filtrada automaticamente
- Apenas os aplicativos daquele grupo são exibidos
- Os indicadores são recalculados em tempo real

Cada aplicação pode ser expandida individualmente.

Dentro de cada aplicativo existem 5 sub-abas principais:

- Notas Internas
- Permissões
- Sugestões
- Secrets
- Atividade

---

# O que são as Notas Internas?

A aba Notas Internas exibe informações armazenadas nos campos:

- Personalização
- Propriedades adicionais
- Observações internas

Esses dados ajudam equipes de governança a documentar:

- Finalidade do aplicativo
- Responsáveis
- Integrações
- Regras internas
- Observações técnicas

---

# O que são as Permissões?

A aba Permissões exibe todas as API Permissions associadas à:

- Enterprise Application
- Application Registration

O sistema mostra:

- Permissões delegadas
- Permissões de aplicação
- Tipo de consentimento
- Nível de criticidade
- Status administrativo
- Classificação de risco

---

# O que são as Sugestões?

A aba Sugestões utiliza análise automatizada baseada em boas práticas de segurança.

O sistema analisa:

- Nome da aplicação
- Categoria do app
- Permissões atuais
- Comportamento esperado

Com isso, consegue identificar excessos ou inconsistências.

Exemplos:

- "Esse aplicativo provavelmente não necessita dessa permissão crítica."
- "Aplicativo sem owner definido."
- "Secret próxima da expiração."
- "Permissão considerada excessiva para esse tipo de integração."

O objetivo é ajudar na aplicação do princípio do menor privilégio.

---

# O que são as Secrets?

A aba Secrets exibe todas as credenciais cadastradas na aplicação.
Inclui:

- Client Secrets
- Certificados
- Datas de criação
- Datas de expiração
- Status da credencial

O sistema destaca automaticamente:

- Secrets expiradas
- Secrets próximas do vencimento
- Credenciais antigas
- Ausência de rotação

---

# O que é Atividade?

A aba Atividade registra alterações realizadas na:

- Enterprise Application
- Application Registration

São exibidos eventos como:

- Criação do aplicativo
- Remoção do aplicativo
- Alteração de permissões
- Criação de secrets
- Exclusão de credenciais
- Alteração de owners
- Consentimentos administrativos
- Mudanças de configuração

Cada evento mostra:

- Usuário responsável
- Data
- Horário
- Tipo da alteração realizada

Isso permite auditoria completa e rastreabilidade operacional do ambiente.
