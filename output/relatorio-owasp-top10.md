# Relatório OWASP Top 10 (2021)

> **Nota (v1.1.0):** este relatório registra a auditoria da **v1.0.0** e não foi reescrito. Controles
> que mudaram depois: a *confirmação em três etapas* (caixa + digitação + diálogo) foi substituída por
> *diálogo final sempre* + *digitação do identificador só para discos de alto risco* (grandes, com dados);
> o filtro de discos passou a ser **somente USB** (sem `mmc`/removível genérico); toda gravação é
> **verificada por releitura antes do eject**; a senha de administrador é conferida **antes** de mexer no
> pendrive e não fica retida na memória. Detalhes: `CHANGELOG.md` e `SECURITY.md`.

**Projeto:** EPMA Windows 11 Creator USB
**Data:** 27 de julho de 2026

---

## Resumo em linguagem simples

**O que é o OWASP Top 10:** é a lista das 10 falhas de segurança mais comuns do mundo em aplicações, publicada por uma organização internacional sem fins lucrativos (OWASP). Funciona como uma checklist de referência: se um projeto passa bem nas 10, ele evitou os erros que mais causam incidentes reais.

**Um aviso necessário antes dos resultados.** A lista foi criada pensando em **aplicações web** — sites e serviços na internet, com login, banco de dados e servidor. Seu projeto é um **programa de desktop**: não tem login, não tem servidor, não tem banco de dados e não guarda dados de ninguém.

Por isso, **5 das 10 categorias simplesmente não se aplicam** ao seu projeto. Não é uma nota boa nem ruim — é como avaliar um carro pelo manual de manutenção de um avião: vários itens não existem.

Onde a categoria não se aplica, eu digo claramente e explico por quê, em vez de inventar um "Mitigado" que não significaria nada. E onde ela se aplica de forma adaptada, eu explico a adaptação.

### Resultado geral

| Status | Quantidade |
|---|---|
| **Mitigado** | 4 |
| **Parcial** | 1 |
| **Exposto** | 0 |
| **Não aplicável** | 5 |

**Nenhuma categoria ficou Exposta.** A única "Parcial" (A08 — integridade do software baixado) depende de uma ação do usuário que nenhum código consegue substituir, e está explicada em detalhe.

---

## Tabela resumida

| # | Categoria | Em português simples | Status |
|---|---|---|---|
| A01 | Broken Access Control | Controle de acesso quebrado | **Não aplicável** |
| A02 | Cryptographic Failures | Falhas de criptografia | **Mitigado** |
| A03 | Injection | Injeção de comandos | **Mitigado** |
| A04 | Insecure Design | Projeto inseguro | **Mitigado** |
| A05 | Security Misconfiguration | Configuração insegura | **Mitigado** |
| A06 | Vulnerable Components | Componentes vulneráveis | **Não aplicável** |
| A07 | Identification & Auth Failures | Falhas de identificação e autenticação | **Não aplicável** |
| A08 | Software & Data Integrity Failures | Falhas de integridade de software e dados | **Parcial** |
| A09 | Logging & Monitoring Failures | Falhas de registro e monitoramento | **Mitigado** |
| A10 | Server-Side Request Forgery | Requisição forjada no servidor | **Não aplicável** |

---

## Análise detalhada

### A01 — Broken Access Control (Controle de Acesso Quebrado) · **NÃO APLICÁVEL**

**O que é:** em um site, é quando um usuário comum consegue acessar áreas ou dados de outro usuário — por exemplo, trocar o número na barra de endereço e ver o pedido de outra pessoa.

**Por que não se aplica:** o programa **não tem usuários, não tem login, não tem perfis e não tem dados de terceiros**. Existe uma única pessoa: quem está sentado na frente do computador. Não há a quem restringir acesso.

**Evidência:** busca em todo o código por qualquer mecanismo de autorização, sessão ou perfil — nenhum encontrado. Não há servidor nem API.

**O controle de acesso que existe** (o `sudo` pedindo senha de administrador) é do sistema operacional, não do programa, e está avaliado em A07 e no relatório STRIDE.

---

### A02 — Cryptographic Failures (Falhas de Criptografia) · **MITIGADO**

**O que é:** dados sensíveis trafegando ou sendo guardados sem proteção adequada — como enviar uma senha por um canal que qualquer um pode ler no caminho.

**Situação antes:** o programa aceitava links `http://` (sem criptografia). Um download de 5 GB por HTTP num Wi-Fi público pode ser interceptado e substituído.

**Situação depois — Mitigado. Evidências:**

| Controle | Evidência |
|---|---|
| Somente HTTPS aceito | `validate_download_url()` recusa `http://`, `ftp://`, `file://`. Comprovado por 5 testes automatizados. |
| Certificado validado | Verificado na prática: `ssl.create_default_context().verify_mode` = `CERT_REQUIRED`. OpenSSL 3.6.3. |
| Sem rebaixamento por redirecionamento | O endereço final é revalidado após redirecionamentos. |
| Senha nunca em texto visível | Enviada só por `stdin`, nunca em argumento de processo (visível via `ps`) nem em log. |
| Arquivos com permissão restrita | Log de auditoria e download parcial criados com `0600`. Verificado: `-rw-------`. |
| Algoritmo de integridade adequado | SHA-256 (nada de MD5 ou SHA-1). |

**Observação:** o programa **não criptografa dados em repouso**, e isso está correto — ele não armazena nenhum dado sensível. A ISO do Windows é um arquivo público.

---

### A03 — Injection (Injeção) · **MITIGADO**

**O que é:** quando um dado fornecido pelo usuário é interpretado como *instrução* em vez de *informação*. O caso mais famoso é o SQL Injection, mas o princípio vale para qualquer linguagem de comando.

**Esta era a categoria mais grave do projeto.**

**Situação antes:** o nome do arquivo ISO era colado dentro do texto de um script executado **como administrador**. Um nome de arquivo preparado podia emendar comandos novos.

Prova obtida (montagem da string, sem execução):

```
mount -o loop,ro,uid=501,gid=20 "/tmp/Win11.iso" ; id > /tmp/PROVA_INJECAO.txt ; echo "" "/tmp/win11iso_x"
                                └─ comando 1 ──┘ └────── comando 2 (injetado) ──────┘
```

**Situação depois — Mitigado. Evidências:**

| Controle | Evidência |
|---|---|
| Separação de dados e comando | Valores passam como parâmetros posicionais (`"$1"`, `"$2"`), nunca colados no texto. É o mesmo princípio das *prepared statements* do SQL. |
| Teste comparativo executado | Padrão antigo: comando injetado **executou**. Padrão novo: tratado como texto, **não executou**. |
| Validação estrita de entrada | Identificadores de disco recusados se fugirem de `^disk[0-9]+$` / `^[a-zA-Z0-9_+-]{1,32}$`. 6 testes automatizados. |
| Lista de permissão para pacotes | Só ferramentas de `LINUX_REQUIRED_TOOLS` podem ser instaladas como administrador. |
| `set -eu` nos scripts privilegiados | Interrompe na primeira falha e em variável indefinida. |

**SQL / NoSQL Injection:** **inexistentes por construção** — o projeto não tem banco de dados, nenhuma consulta SQL, nenhum driver e nenhuma string de conexão. Confirmado por busca em todo o código.

---

### A04 — Insecure Design (Projeto Inseguro) · **MITIGADO**

**O que é:** falhas que não são erro de programação, mas de *concepção* — o sistema foi desenhado de um jeito que não tem como ficar seguro depois.

**Avaliação:** o desenho original já era, em vários pontos, melhor que a média:

| Decisão de projeto acertada | Por que importa |
|---|---|
| Só discos externos aparecem na lista | O usuário nunca é exposto à opção de apagar o disco do sistema |
| Confirmação em três etapas | Marcar a caixa + **digitar o identificador** + confirmar no diálogo. A digitação obriga o usuário a ler o que selecionou. |
| Zero dependências de terceiros | Elimina a via de ataque mais comum em software moderno |
| Senha por `stdin`, não por argumento | Já estava correto no código original |

**Falhas de desenho encontradas e corrigidas:**

| Falha | Correção |
|---|---|
| Verificações "falhavam abrindo" — quando não conseguiam confirmar que um disco era externo, mostravam mesmo assim | Agora **falham fechando**: na dúvida, o disco é ocultado |
| Sistema que inicializa por cartão SD (ex.: Raspberry Pi) teria o disco do sistema listado como removível | Discos com `/`, `/boot`, `/home`, `/usr`, `/var`, `/etc` são ocultados independentemente da flag |
| Verificação feita na listagem, mas não repetida na hora de apagar (janela TOCTOU) | `reverify_target_disk()` reconfere identificador e tamanho imediatamente antes de escrever |

---

### A05 — Security Misconfiguration (Configuração Insegura) · **MITIGADO**

**O que é:** o software está correto, mas está configurado de um jeito inseguro — senha padrão não trocada, modo de depuração ligado em produção, permissões largas demais.

**Situação — Mitigado. Evidências:**

| Item | Situação |
|---|---|
| Modo de depuração | Não existe. Nenhuma variável de debug, nenhum `print` de dados internos. |
| Credenciais padrão | Não existem. O programa não tem contas. |
| Permissões de arquivo | Explícitas e restritivas: `0600` para arquivos, `0700` para a pasta de log. Verificado. |
| Comandos privilegiados | Escopo mínimo e definido; nada roda como root sem necessidade. |
| Configuração insegura opcional | `WIN11USB_ALLOW_ANY_DOWNLOAD_HOST` existe, mas **é opcional, vem desligada por padrão e está documentada como redutora de segurança** em `SECURITY.md`. |
| Documentação de segurança | Criado `SECURITY.md` com modelo de ameaça, controles e variáveis. |

---

### A06 — Vulnerable and Outdated Components (Componentes Vulneráveis) · **NÃO APLICÁVEL**

**O que é:** usar bibliotecas de terceiros com falhas conhecidas e não atualizadas.

**Por que não se aplica:** o projeto **não usa nenhuma biblioteca de terceiros**. Zero. Apenas a biblioteca padrão do Python, mantida pela própria equipe do Python.

**Evidência:** todos os módulos importados (linhas 40–55) são da biblioteca padrão. Não existe `requirements.txt` com dependências, `pyproject.toml`, `Pipfile` ou `poetry.lock` — porque não há o que declarar.

**Cuidado importante:** o comando que lista bibliotecas instaladas **neste computador** mostra 28 pacotes (Flask, requests, cryptography...). **Nenhum deles é dependência deste projeto** — estão instalados na máquina para outros fins. Uma ferramenta de SCA mal configurada geraria dezenas de alertas falsos. Registrado no relatório SCA.

**Ação preventiva tomada:** criado `requirements.txt` documentando explicitamente a ausência de dependências, para que ferramentas automáticas não confundam "projeto sem dependências" com "projeto não analisado".

**Ressalva honesta:** as dependências de **sistema** (`parted`, `rsync`, `wimlib`) são código de terceiros, mas sua versão é definida pelo sistema operacional de cada usuário, não pelo projeto. A mitigação — manter o sistema atualizado — está documentada em `SECURITY.md` e fora do controle do código.

---

### A07 — Identification and Authentication Failures · **NÃO APLICÁVEL**

**O que é:** falhas em como o sistema confirma quem é o usuário — senhas fracas aceitas, sessão que não expira, força bruta sem bloqueio.

**Por que não se aplica:** o programa **não autentica ninguém**. Não tem login, cadastro, sessão, token ou recuperação de senha.

**A única senha envolvida** é a do administrador do sistema, e quem a valida é o `sudo` do sistema operacional — não o programa. O programa apenas repassa o que foi digitado.

**Evidência de que o repasse é feito corretamente** (isto está avaliado, mesmo a categoria não se aplicando):

- Senha enviada por `stdin`, nunca como argumento de processo (`ps` não a revela a outros usuários)
- Nunca gravada em log, em disco ou no registro de auditoria
- Removida da memória ao fim de cada operação (`clear_cached_password()`)
- Limite de 3 tentativas, abaixo do limite padrão do `sudo` (evita bloquear a conta do usuário)

---

### A08 — Software and Data Integrity Failures · **PARCIAL**

**O que é:** confiar em código ou dados vindos de fora sem verificar se foram adulterados no caminho.

**Esta é a categoria mais relevante do projeto e a única que não ficou totalmente resolvida.**

**Situação antes:** o programa baixava o que estivesse no endereço colado e gravava no pendrive, sem nenhuma verificação. O usuário instalaria esse conteúdo como **o sistema operacional do computador**.

**O que foi implementado:**

| Controle | Evidência |
|---|---|
| Somente HTTPS | Recusa esquemas inseguros; comprovado por teste |
| Aviso de servidor não reconhecido | Diálogo de confirmação explícito se o host não for da Microsoft |
| Impressão digital SHA-256 | Calculada durante o download e exibida ao final |
| Verificação bloqueante opcional | Se o usuário informar o valor esperado e não conferir, **o arquivo é apagado** |
| Download incompleto rejeitado | Comparação com o tamanho anunciado pelo servidor |
| Instalação de pacotes com lista fixa | Nada vindo da rede influencia o que é instalado como root |

**Por que continua PARCIAL, e não Mitigado:**

Se o usuário **não informar** um checksum esperado, a verificação não acontece — o programa mostra a impressão digital, mas não tem com o que compará-la.

Não é possível resolver isso apenas com código, e é importante entender o motivo: a Microsoft **atualiza a imagem do Windows 11 periodicamente e não publica os checksums de forma estável e automatizável**. Qualquer valor que eu embutisse no código estaria errado na próxima atualização — e um programa que rejeita a imagem legítima é pior do que um que avisa.

**O que você precisa fazer:** oriente quem usar o programa a baixar sempre pelo site oficial da Microsoft e, quando um checksum estiver publicado, colá-lo no campo antes de baixar.

---

### A09 — Security Logging and Monitoring Failures · **MITIGADO**

**O que é:** não registrar eventos importantes, de modo que um incidente passa despercebido ou não pode ser investigado depois.

**Situação antes: Exposto.** Um programa que apaga discos e roda comandos como administrador **não deixava nenhum registro permanente**. O log da tela desaparecia ao fechar a janela.

**Situação depois — Mitigado. Evidências:**

| Item | Implementação |
|---|---|
| Registro permanente | Arquivo em `~/.local/state/epma-win11-usb-creator/audit.log` |
| Permissões | `0600` (arquivo) e `0700` (pasta) — verificado: `-rw-------` |
| Eventos de operação destrutiva | Início, conclusão e falha, com identificador do disco |
| Eventos de segurança | Discos ocultados por não passarem na verificação, identificadores recusados, host de download e resultado da verificação de integridade |
| Data e hora | Em todos os registros |
| **Não registra dados sensíveis** | Senhas, conteúdo de arquivos e dados pessoais nunca são gravados — **coberto por teste automatizado** |
| Robustez | Se a pasta pessoal não for gravável, o log é desativado silenciosamente. **Falhar ao registrar nunca impede o usuário de criar seu pendrive.** |
| Controle do usuário | Desligável com `WIN11USB_DISABLE_AUDIT_LOG=1`; caminho ajustável com `WIN11USB_AUDIT_LOG` |

Exemplo real do registro produzido:

```
2026-07-27 01:59:07,583 INFO teste de evento de auditoria
2026-07-27 01:59:07,583 WARNING REJECTED invalid device identifier: 'sdb; rm -rf /'
```

**Limite honesto:** existe *registro*, mas não existe *monitoramento* — ninguém é alertado automaticamente. Para um programa de desktop de uso pontual, isso é adequado e proporcional.

---

### A10 — Server-Side Request Forgery (SSRF) · **NÃO APLICÁVEL**

**O que é:** enganar um **servidor** para que ele faça requisições a endereços internos que o atacante não alcançaria sozinho — por exemplo, fazer o servidor de um site consultar o painel interno da empresa.

**Por que não se aplica:** SSRF exige um servidor que receba pedidos de terceiros. **Não há servidor neste projeto.** O programa roda na máquina do usuário e só acessa o endereço que o próprio usuário digitou — ele não tem acesso a nada que o usuário já não tivesse.

**Ainda assim, o controle foi aplicado por precaução:** a validação de endereço bloqueia esquemas como `file://` (que permitiria ler arquivos locais) e restringe a HTTPS. Se o programa um dia ganhar um componente servidor, a proteção já existe.

---

## Itens de atenção

Pontos que não são falhas hoje, mas que merecem vigilância:

| Item | Por quê |
|---|---|
| **A08 depende de ação humana** | A verificação de integridade só é completa se o usuário colar o checksum. Reforce isso na orientação a quem usar o programa. |
| **A06 pode mudar de status a qualquer momento** | Hoje "não aplicável" porque não há dependências. **Adicionar uma única biblioteca muda isso permanentemente.** Avalie com cuidado antes de acrescentar qualquer uma. |
| **A02 depende do sistema atualizado** | A validação de certificados HTTPS depende dos certificados-raiz do sistema operacional. Um sistema desatualizado enfraquece essa proteção. |
| **A09 registra, mas não monitora** | Adequado hoje. Se o programa virar parte de um processo corporativo, considere centralizar os registros. |
| **A05 tem uma opção que reduz a segurança** | `WIN11USB_ALLOW_ANY_DOWNLOAD_HOST=1` desliga o aviso de servidor desconhecido. Não a use sem motivo claro. |

---

## Conclusão

O projeto **não está exposto a nenhuma das 10 categorias**. Das 5 que se aplicam, 4 estão mitigadas e 1 está parcial por um limite do mundo real, não por falha de implementação.

O ponto que merece sua atenção continuada é o **A08**: a autenticidade da imagem do Windows. O programa hoje faz tudo que pode — exige conexão criptografada, avisa sobre servidores desconhecidos, calcula a impressão digital e bloqueia o arquivo se ele não bater com o esperado. O elo final, comparar essa impressão com o valor oficial, depende de uma pessoa.
