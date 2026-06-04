# Enterprise Applications Monitor

Pensando no controle das API Permissions atribuídas à Enterprise Application no Entra ID, desenvolvi um dashboard que centraliza todas as Enterprise Applications do ambiente e exibe detalhadamente as permissões concedidas a cada uma delas.

A solução utiliza Microsoft Graph API para coletar as informações dos aplicativos registrados no tenant, classificando automaticamente as permissões por nível de criticidade através de indicadores visuais por cores, facilitando a identificação rápida de permissões sensíveis ou excessivas.

Na aba “Sugestões”, o dashboard realiza uma análise automatizada baseada em boas práticas de segurança e princípios de least privilege, indicando permissões que potencialmente poderiam ser removidas para reduzir superfície de ataque e riscos de exposição. A ferramenta atua apenas de forma analítica, ou seja, não executa alterações diretamente nos aplicativos, mantendo o processo de revisão e remoção sob validação da equipe responsável.

Além das permissões, o painel também consolida informações relevantes de governança e auditoria, como data e horário de criação das aplicações, owners atribuídos e atividades registradas relacionadas aos aplicativos, permitindo maior rastreabilidade sobre alterações e movimentações realizadas no ambiente.

O objetivo da ferramenta é apoiar iniciativas de governança, revisão periódica de privilégios, hardening de aplicações corporativas e fortalecimento da postura de segurança do tenant Microsoft Entra ID.

-----

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

|Biblioteca      |Função                                                            |
|----------------|------------------------------------------------------------------|
|express         |Responsável pelo servidor web e rotas da aplicação                |
|axios           |Realiza chamadas HTTP para APIs                                   |
|dotenv          |Carrega variáveis de ambiente do arquivo `.env`                   |
|@azure/msal-node|Responsável pela autenticação Microsoft OAuth e obtenção de tokens|

-----

# Estrutura necessária do projeto

Para o funcionamento correto da aplicação, é necessária a criação prévia de uma App Registration no Microsoft Entra ID contendo uma Client Secret válida, permissão Delegated da Microsoft Graph API - User.Read, Application.Read.All e AuditLog.Read.All — além da configuração do Redirect URI correspondente à URL onde o dashboard será executado.

Também é necessário definir o tipo de Supported Account de acordo com as políticas de segurança da organização. Por boas práticas, recomenda-se utilizar o modelo “Single Tenant Only”, restringindo a autenticação exclusivamente a usuários pertencentes ao tenant corporativo.

A aplicação utilizará essa identidade para autenticar-se no Microsoft Graph API via OAuth 2.0 e realizar a coleta das informações do ambiente, incluindo Enterprise Applications, App Registrations, permissões atribuídas, owners, auditorias e demais dados relacionados à governança do tenant Microsoft Entra ID.

-----

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

-----

# Arquivo `.env`

O arquivo `.env` é responsável por armazenar as credenciais da aplicação registradas no Azure.

Nele deverão ser configuradas:

```env
CLIENT_ID=
CLIENT_SECRET=
```

Descrição das variáveis:

|Variável     |Função                                           |
|-------------|-------------------------------------------------|
|CLIENT_ID    |Application (Client) ID da Enterprise Application|
|CLIENT_SECRET|Secret gerada no portal Azure                    |

Exemplo:

```env
CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
CLIENT_SECRET=xxxxxxxxxxxxxxxxxxxxxxxx
```

-----

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

-----

# Arquivo `app.js`

O `app.js` é o ponto principal da aplicação.

Responsabilidades:

- Inicialização do servidor Express
- Rotas da aplicação
- Login Microsoft
- Renderização do dashboard
- Atualização automática dos dados
- Controle geral da interface

-----

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

-----

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

-----

# COMO O ENTERPRISE APPLICATIONS MONITOR FUNCIONA

## 1. Login e autenticação

Quando o usuário acessa o sistema, ele realiza login utilizando sua conta Microsoft.
Durante a autenticação, a Microsoft retorna um token de acesso OAuth 2.0 contendo permissões autorizadas para leitura do tenant.
Esse token é utilizado para acessar os recursos do ambiente de forma segura através do Microsoft Graph API.

-----

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

-----

## 3. Dashboard visual

Após a coleta, os dados são convertidos em um dashboard visual e interativo.
O sistema organiza automaticamente:

- Aplicações ativas
- Aplicações desabilitadas
- Aplicações excluídas
- Aplicações críticas
- Aplicações que possuam permissão de write, user.write, group.write, mail.write e files.write
- Apps sem owner
- Permissões perigosas (API Permissions)
- Alterações recentes
- Alertas de segurança
- Aplicações que possuam SSO
- Owners
- Sugestões sobre API Permissions
- URL redirect
- Secrets expiradas
- Certificados
- Atividade
- Local de uso
- Último uso


Tudo é exibido através de tabelas dinâmicas, abas inteligentes, indicadores visuais e alertas automáticos.

-----

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

-----

## 5. Export para Excel

O dashboard permite exportar os dados da aba ativa diretamente para um arquivo `.xlsx`, sem necessidade de ferramentas externas.

O botão **↓ Excel**, localizado no cabeçalho da tabela principal, gera automaticamente um relatório com duas planilhas:

**Planilha “Apps”** — contém uma linha por aplicativo com as seguintes colunas:

|Coluna                     |Descrição                                           |
|---------------------------|----------------------------------------------------|
|Nome                       |Nome de exibição da aplicação                       |
|App ID                     |Identificador único da aplicação                    |
|Criado em                  |Data e hora de criação                              |
|Criado por                 |Usuário responsável pela criação                    |
|Owner(s)                   |Owners atribuídos                                   |
|Risco                      |Classificação de risco (Critical, High, Medium, Low)|
|Ultimo Uso                 |Data e hora do último sign-in detectado             |
|Ultimo Usuario             |Usuário ou Service Principal do último acesso       |
|Sign-in Audience           |Tipo de conta suportada                             |
|App Permissions (APP)      |Permissões do tipo Application                      |
|Delegated Permissions (DEL)|Permissões do tipo Delegated                        |
|Write Permissions          |Permissões de escrita identificadas                 |
|Write em Groups            |Indica se possui escrita em grupos                  |
|Write em Users             |Indica se possui escrita em usuários                |
|Write em E-mail            |Indica se possui escrita em e-mail                  |
|Write em Files             |Indica se possui escrita em arquivos                |
|Workloads                  |Workloads Microsoft identificados pelo sistema      |
|Secrets                    |Secrets cadastradas com status e vencimento         |
|Notas                      |Observações internas da aplicação                   |

**Planilha “Resumo”** — contém um consolidado geral do ambiente com os totais por categoria (total de apps, com App Permission, com Write, sem owner, secrets expirando, etc.) e metadados do relatório como Tenant ID e data de geração.

O nome do arquivo exportado segue o padrão `EnterpriseApps_<Aba>_<Data>.xlsx`.

> O export sempre reflete os dados da aba atualmente selecionada no dashboard. Para exportar um grupo específico (ex: apenas apps sem owner), basta selecionar o card correspondente antes de clicar no botão.

-----

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

-----

## 🟡 Amarelo — Médio risco

Permissões amarelas geralmente possuem acesso amplo de leitura.
Essas permissões normalmente:

- Não alteram dados
- Não executam ações administrativas
- Mas permitem acesso massivo a informações organizacionais

Mesmo sem escrita, ainda representam risco de exposição de dados.

-----

## 🟢 Verde — Baixo risco

Permissões verdes possuem escopo reduzido e baixo impacto operacional.
Normalmente são:

- Permissões limitadas
- Acessos específicos
- Escopos controlados
- Leituras restritas

São consideradas permissões de menor criticidade.

-----

# Funcionamento das abas

Os cards localizados no topo do dashboard funcionam como filtros inteligentes.

Ao clicar em um card:

- A tabela é filtrada automaticamente
- Apenas os aplicativos daquele grupo são exibidos
- Os indicadores são recalculados em tempo real

Cada aplicação pode ser expandida individualmente.

Ao expandir uma aplicação, as **Notas Internas** são exibidas diretamente acima das sub-abas, quando existirem, sem necessidade de navegação adicional.

Dentro de cada aplicativo existem **7 sub-abas**:

- Permissões
- Sugestões
- Secrets
- Atividade
- Último Uso
- Onde é Usado
- Risco

-----

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

-----

# O que são as Sugestões?

A aba Sugestões utiliza análise automatizada baseada em boas práticas de segurança.

O sistema analisa:

- Nome da aplicação
- Categoria do app
- Permissões atuais
- Comportamento esperado

Com isso, consegue identificar excessos ou inconsistências.

Exemplos:

- “Esse aplicativo provavelmente não necessita dessa permissão crítica.”
- “Aplicativo sem owner definido.”
- “Secret próxima da expiração.”
- “Permissão considerada excessiva para esse tipo de integração.”

O objetivo é ajudar na aplicação do princípio do menor privilégio.

-----

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

-----

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

-----

# O que é Último Uso?

A aba Último Uso exibe informações detalhadas sobre o sign-in mais recente detectado para a aplicação.

São apresentados:

- Data e hora exata do último acesso
- Tipo de acesso (sign-in de usuário ou Service Principal)
- Usuário ou Service Principal responsável
- IP de origem
- Cliente utilizado
- Recurso acessado
- Localização geográfica

Quando detectados múltiplos acessos recentes, os anteriores são listados em sequência abaixo do último.

Caso nenhum sign-in seja encontrado, o sistema indica que o aplicativo pode estar inativo e orienta sobre a verificação via Azure Monitor Workbooks para cenários com client_credentials.

-----

# O que é Onde é Usado?

A aba Onde é Usado apresenta uma análise do contexto operacional do aplicativo, identificando automaticamente em quais workloads e recursos Microsoft ele provavelmente opera.

São exibidos:

- Workloads identificados com base nas permissões (ex: Exchange Online, SharePoint, Teams, Entra ID)
- Categorias com permissão de escrita (ex: Grupos, Usuários, E-mail, Arquivos)
- Detalhamento das permissões de escrita por nível de risco
- Informações do Service Principal vinculado, incluindo tipo, publisher, homepage e Reply URLs

-----

# O que é Risco?

A aba Risco apresenta a classificação de risco calculada automaticamente para o aplicativo, com base em um conjunto de critérios ponderados.

São considerados na pontuação:

- Presença e criticidade das permissões de escrita
- Ausência de owner atribuído
- Histórico de uso (sign-ins detectados)

A classificação final pode ser:

|Nível   |Critério              |
|--------|----------------------|
|Critical|Pontuação ≥ 80        |
|High    |Pontuação ≥ 50        |
|Medium  |Pontuação ≥ 25        |
|Low     |Pontuação abaixo de 25|

A aba também lista as permissões críticas identificadas com uma descrição resumida de cada uma, facilitando a priorização durante revisões de segurança.

-----

# Notas Internas

As Notas Internas, quando presentes, são exibidas automaticamente em destaque acima das sub-abas ao expandir um aplicativo, sem necessidade de navegação adicional.

Essas informações são originadas dos campos internos da aplicação no Entra ID e ajudam equipes de governança a documentar:

- Finalidade do aplicativo
- Responsáveis
- Integrações
- Regras internas
- Observações técnicas
