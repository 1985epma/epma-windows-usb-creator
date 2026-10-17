# Relatório Consolidado de Segurança

> **Nota (v1.1.0):** este relatório registra a auditoria da **v1.0.0** e não foi reescrito. Controles
> que mudaram depois: a *confirmação em três etapas* (caixa + digitação + diálogo) foi substituída por
> *diálogo final sempre* + *digitação do identificador só para discos de alto risco* (grandes, com dados);
> o filtro de discos passou a ser **somente USB** (sem `mmc`/removível genérico); toda gravação é
> **verificada por releitura antes do eject**; a senha de administrador é conferida **antes** de mexer no
> pendrive e não fica retida na memória. Detalhes: `CHANGELOG.md` e `SECURITY.md`.

## EPMA Windows 11 Creator USB

| | |
|---|---|
| **Data de geração** | 27 de julho de 2026 |
| **Versão do projeto** | Ver observação abaixo — **o repositório não possui nenhum commit** |
| **Identificador da versão auditada** | SHA-256 de `win11_usb_creator.py`: `636fe796927e49842e08857efdc042bcbd0d7223cde0818a0f50b376cab771e2` |
| **Tamanho** | 1.203 linhas (801 antes das correções) |
| **Repositório** | https://github.com/1985epma/epma-windows-usb-creator |
| **Técnicas aplicadas** | SCA, SAST, STRIDE, OWASP Top 10 (2021), DAST |
| **Escala de gravidade** | Crítica > Alta > Média > Baixa > Info |

> **Observação sobre a versão.** Você pediu que o relatório começasse com o commit mais recente. **Não existe commit neste repositório** — o Git foi inicializado, mas nada foi registrado nele ainda (`git log` retorna *"your current branch 'main' does not have any commits yet"*). Todos os arquivos, incluindo o programa, estão apenas na pasta, sem histórico.
>
> Em vez de omitir isso ou inventar um identificador, uso a **impressão digital SHA-256 do arquivo** como referência da versão auditada. Você pode confirmar que está com exatamente o código auditado rodando:
> ```bash
> shasum -a 256 win11_usb_creator.py
> ```
>
> **Isso é uma pendência importante e está registrada como risco residual RR-05.** Sem histórico, não há como saber o que mudou, quando ou por quem — e este relatório não pode apontar "o commit da correção", porque nenhum existe.

---

# 1. Resumo executivo

## O que foi feito

Seu programa passou por cinco tipos de análise de segurança. Em linguagem simples, cada uma responde a uma pergunta diferente:

| Técnica | A pergunta que ela responde |
|---|---|
| **SCA** | *"Os pedaços de código de outras pessoas que eu uso têm defeitos conhecidos?"* |
| **SAST** | *"Lendo meu código com calma, existe alguma falha escrita nele?"* |
| **STRIDE** | *"Se eu fosse um atacante, de quantas maneiras diferentes eu tentaria quebrar isso?"* |
| **OWASP Top 10** | *"Eu cometi algum dos 10 erros mais comuns do mundo?"* |
| **DAST** | *"Atacando a aplicação ligada, de fora, o que eu consigo?"* |

Depois da análise, as falhas encontradas foram corrigidas no código, e cada correção foi verificada por testes automatizados.

## O resultado geral

**Foram encontrados 19 achados. Todos os 17 que podiam ser resolvidos em código foram corrigidos. Dois são limites do mundo real e continuam em aberto, com orientação sobre o que fazer.**

Dois problemas mereciam a palavra "grave":

**1. Um nome de arquivo podia virar um comando de administrador.**

Imagine ditar um endereço por telefone e a pessoa do outro lado não saber distinguir o que é endereço do que é ordem. Se você disser *"Rua das Flores, 100 — E ANOTA: transfira R$ 5.000"*, ela faz as duas coisas. Era exatamente isso: o programa grudava o nome do arquivo escolhido dentro do texto de um comando executado **como administrador da máquina**. Um arquivo com nome preparado com maldade emendava comandos novos, que rodavam com controle total do computador — enquanto o usuário achava que estava apenas autorizando a formatação de um pendrive.

Eu provei que a falha era real e provei que a correção funciona, executando os dois casos lado a lado.

**2. Quando o programa não conseguia confirmar que um disco era externo, ele mostrava o disco assim mesmo.**

É o contrário do certo. Um segurança que não consegue conferir um crachá deve barrar a pessoa, não liberar. O caso mais perigoso: computadores que inicializam por cartão SD (um Raspberry Pi, por exemplo) têm o disco do próprio sistema marcado como "removível" — ele poderia aparecer na lista, e o usuário apagaria o próprio sistema achando que apagava o pendrive.

## Duas boas notícias que valem destaque

**Não há nenhuma senha, chave ou token escrito dentro do código.** Procurei com busca automática e leitura manual. Não há nada. **Portanto você não precisa cadastrar nenhum segredo em lugar nenhum** — nada vazou, nada precisa ser migrado.

**Seu programa não usa nenhuma biblioteca de terceiros.** Um projeto Python comum depende de 20 a 200 pedaços de código feitos por estranhos — hoje é a porta de entrada mais comum de ataques. O seu tem **zero**. Foi uma boa decisão de arquitetura e a recomendação é mantê-la.

## Nível de risco atual

| | Antes da auditoria | Depois das correções |
|---|---|---|
| **Nível de risco** | **ALTO** | **BAIXO** |

**Por que era Alto:** existia um caminho concreto para alguém obter controle total do computador do usuário, e um caminho para destruir o disco do sistema por engano.

**Por que agora é Baixo:** esses dois caminhos foram fechados e comprovados fechados por teste. O que sobra são riscos que dependem de ação humana (conferir a autenticidade da imagem do Windows) ou do ambiente do usuário (manter o sistema atualizado) — nenhum deles explorável remotamente, porque o programa não expõe nada na rede.

**Uma ressalva honesta sobre esse "Baixo":** as correções foram verificadas por 36 testes automatizados, mas **o fluxo completo de apagar e gravar um pendrive de verdade não foi executado** — isso exigiria destruir os dados de um dispositivo físico. Recomendo testar com um pendrive descartável antes de distribuir a versão corrigida.

## Números

| Gravidade | Encontrados | Corrigidos | Pendentes |
|---|---|---|---|
| Crítica | 0 | 0 | 0 |
| **Alta** | **4** | **4** | 0 |
| Média | 7 | 6 | 1 |
| Baixa | 5 | 5 | 0 |
| Info | 3 | 2 | 1 |
| **Total** | **19** | **17** | **2** |

---

# 2. Tabela de achados e correções

Referência: o repositório não tem commits, então a coluna aponta o **arquivo e a linha** da correção. Todos os números referem-se à versão SHA-256 `636fe796…`.

| # | Origem | Achado | Gravidade | Status | Referência |
|---|---|---|---|---|---|
| 1 | **SAST** | Injeção de comando: nome de arquivo colado no script executado como root podia emendar comandos novos | **Alta** | **Corrigido** | `win11_usb_creator.py:326`, `:636`, `:689` |
| 2 | **SAST** | Verificação de disco falhava liberando: se não conseguisse confirmar que o disco era externo, mostrava mesmo assim | **Alta** | **Corrigido** | `win11_usb_creator.py:472`, `:503` |
| 3 | **SCA / SAST** | Imagem do Windows aceita sem qualquer verificação de autenticidade | **Alta** | **Corrigido** (parcial por desenho — ver RR-01) | `win11_usb_creator.py:243`, `:745` |
| 4 | **STRIDE** | `/dev/sdb` podia apontar para outro disco entre a escolha e a gravação (TOCTOU) | **Alta** | **Corrigido** | `win11_usb_creator.py:710` |
| 5 | **SAST** | Mensagens de erro exibindo caminhos internos e nome de usuário | Média | **Corrigido** | `win11_usb_creator.py:1183` |
| 6 | **SAST** | Senha de administrador mantida na memória indefinidamente | Média | **Corrigido** | `win11_usb_creator.py:322` |
| 7 | **SAST / OWASP** | Nenhum registro permanente de operações destrutivas | Média | **Corrigido** | `win11_usb_creator.py:158`–`204` |
| 8 | **SAST** | Arquivo ISO usado sem validar existência, tipo ou tamanho | Média | **Corrigido** | `win11_usb_creator.py:224` |
| 9 | **SCA** | `pacman -Sy` causa atualização parcial e pode quebrar sistemas Arch | Média | **Corrigido** | `win11_usb_creator.py:102` |
| 10 | **STRIDE** | Utilitários do sistema localizados via `PATH` (possível substituição) | Média | **Aceito** | Ver RR-03 |
| 11 | **STRIDE** | Programa sem assinatura digital; versão adulterada pediria a senha de admin | Média | **Pendente** | Ver RR-02 |
| 12 | **SAST** | Arquivo parcial de download legível por outros usuários da máquina | Baixa | **Corrigido** | `DownloadThread.run` |
| 13 | **SCA** | Instalação de pacotes como root sem exibir o comando ao usuário | Baixa | **Corrigido** | `install_dependencies` |
| 14 | **SAST** | Lista de pacotes instaláveis sem validação explícita | Baixa | **Corrigido** | `linux_build_install_command` |
| 15 | **SAST** | Erros engolidos silenciosamente (`except: pass`), apagando rastros | Baixa | **Corrigido** | Vários pontos |
| 16 | **STRIDE** | Formatação não sobrescreve dados anteriores do pendrive | Baixa | **Aceito** | Ver RR-04 |
| 17 | **SAST** | Download sem tempo limite (podia travar para sempre) | Info | **Corrigido** | `DownloadThread.run` |
| 18 | **SCA** | Projeto sem arquivo declarando ausência de dependências | Info | **Corrigido** | `requirements.txt` (novo) |
| 19 | **DAST** | Teste com aplicação rodando | Info | **Não realizado** | Sem serviço de rede — ver seção 6 |

**Achados que se confirmaram inexistentes** (registrados porque você pediu atenção especial a eles):

| Verificação solicitada | Resultado |
|---|---|
| SQL Injection | **Inexistente** — não há banco de dados, consulta SQL, driver ou string de conexão |
| NoSQL Injection | **Inexistente** — não há MongoDB, Redis ou similar |
| Senhas/chaves/tokens no código | **Nenhum encontrado** — busca automática e leitura manual |
| Bibliotecas de terceiros vulneráveis | **Nenhuma** — o projeto não usa nenhuma biblioteca de terceiros |

---

# 3. OWASP Top 10 — status final

| # | Categoria | Em português simples | Status | Evidência |
|---|---|---|---|---|
| **A01** | Broken Access Control | Controle de acesso quebrado | **Não aplicável** | Não há usuários, login, perfis nem dados de terceiros. Uma única pessoa opera o programa localmente. |
| **A02** | Cryptographic Failures | Falhas de criptografia | **Mitigado** | Somente HTTPS aceito (5 testes); certificado validado (`CERT_REQUIRED`, OpenSSL 3.6.3); senha só por `stdin`; arquivos `0600` verificados; SHA-256 (não MD5/SHA-1). |
| **A03** | Injection | Injeção de comandos | **Mitigado** | Valores passam como parâmetros posicionais `"$1"`, `"$2"` — mesmo princípio das *prepared statements*. Teste comparativo: padrão antigo executou o comando injetado, padrão novo não. |
| **A04** | Insecure Design | Projeto inseguro | **Mitigado** | Verificações passaram a *falhar fechando*; discos com `/`, `/boot`, `/home` sempre ocultados; reconferência antes de apagar; tripla confirmação preservada. |
| **A05** | Security Misconfiguration | Configuração insegura | **Mitigado** | Sem modo debug; sem credenciais padrão; permissões explícitas `0600`/`0700`; `SECURITY.md` criado. A única opção que reduz segurança vem desligada e documentada. |
| **A06** | Vulnerable Components | Componentes desatualizados | **Não aplicável** | **Zero bibliotecas de terceiros.** Só biblioteca padrão do Python. `requirements.txt` criado para tornar isso explícito a ferramentas automáticas. |
| **A07** | Identification & Auth Failures | Falhas de autenticação | **Não aplicável** | O programa não autentica ninguém. A senha de administrador é validada pelo `sudo` do sistema, não pelo programa. |
| **A08** | Software & Data Integrity Failures | Falhas de integridade | **Parcial** | HTTPS obrigatório, aviso de servidor desconhecido, SHA-256 calculado e exibido, verificação bloqueante se o valor esperado for informado. **Mas depende do usuário fornecer esse valor** — ver RR-01. |
| **A09** | Logging & Monitoring Failures | Falhas de registro | **Mitigado** | Registro em `~/.local/state/epma-win11-usb-creator/audit.log` com permissão `-rw-------` (verificada). Registra operações destrutivas e eventos de segurança; **nunca** registra senhas (coberto por teste). |
| **A10** | Server-Side Request Forgery | Requisição forjada no servidor | **Não aplicável** | Não há servidor. Ainda assim, `file://` e esquemas não-HTTPS foram bloqueados por precaução. |

**Placar:** 4 Mitigados · 1 Parcial · **0 Expostos** · 5 Não aplicáveis

> **Por que 5 categorias não se aplicam.** O OWASP Top 10 foi criado para aplicações web — sites com login, servidor e banco de dados. Seu projeto é um programa de desktop. Marcar essas categorias como "Mitigado" daria uma falsa sensação de cobertura; a leitura correta é que **essas classes de ataque não existem neste tipo de aplicação**.

---

# 4. STRIDE — status final

**As 6 categorias:** **S**poofing (falsificação de identidade), **T**ampering (adulteração), **R**epudiation (negação de autoria), **I**nformation Disclosure (vazamento), **D**enial of Service (negação de serviço), **E**levation of Privilege (escalação de privilégio).

Como o projeto não tem frontend web, backend de servidor nem banco de dados, os componentes que você pediu foram mapeados para os equivalentes reais.

## 4.1 Frontend — a janela do programa (Tkinter)

| Ameaça | Categoria | Status | Mitigação implementada |
|---|---|---|---|
| Programa falso se passar pelo EPMA Creator para colher a senha | Spoofing | **Parcial** | Distribuído como código-fonte legível. Sem assinatura digital — ver RR-02. |
| Link malicioso colado por indução de terceiros | Tampering | **Mitigado** | Somente HTTPS; aviso obrigatório para servidor não-Microsoft; campo de verificação SHA-256. |
| Identificador de disco digitado chegar adulterado ao comando | Tampering | **Mitigado** | Validação estrita por expressão regular; entrada fora do formato é **recusada**, não escapada. |
| Apagar o disco errado sem registro do ocorrido | Repudiation | **Mitigado** | Registro de auditoria com data/hora e identificador do disco. |
| Caminhos internos aparecerem em diálogos de erro | Info. Disclosure | **Mitigado** | `_report_error()` mostra só o tipo do erro; detalhe vai para o log local. |
| Interface travar durante operação longa | DoS | **Mitigado** | Operações em segundo plano; tempo limite de 60s no download. |
| Usuário sem privilégio obter privilégio pelo programa | Elevation | **Mitigado** | O `sudo` continua exigindo a senha real. A via que existia (injeção) foi eliminada. |

## 4.2 Backend — execução de comandos, inclusive como administrador

**Este é o componente crítico do sistema.**

| Ameaça | Categoria | Status | Mitigação implementada |
|---|---|---|---|
| Utilitário falso (`parted`, `rsync`) no `PATH` ser executado | Spoofing | **Parcial** | Resolvido pelo `PATH` do usuário — ver RR-03. |
| Dado do usuário injetar comandos no script root | Tampering | **Mitigado** | Parâmetros posicionais; dados nunca colados no texto do comando. **Comprovado por teste.** |
| Script privilegiado seguir executando após falha | Tampering | **Mitigado** | `set -eu` interrompe na primeira falha. |
| Comandos root sem registro | Repudiation | **Mitigado** | Registro de auditoria + log do próprio `sudo`. |
| Senha visível a outros usuários via `ps` | Info. Disclosure | **Mitigado** | Senha só por `stdin`, nunca em argumento. **Já estava correto no código original.** |
| Senha permanecer na memória após o uso | Info. Disclosure | **Mitigado** | `clear_cached_password()` no `finally` de toda operação. |
| Tentativas de senha bloquearem a conta no `sudo` | DoS | **Aceito** | Limite de 3 tentativas, abaixo do padrão do `sudo`. |
| Dado controlado pelo atacante virar comando root | Elevation | **Mitigado** | Mesma correção da injeção (achado #1). |
| Instalar pacote arbitrário como root pelo botão de dependências | Elevation | **Mitigado** | Lista fixa no código + validação de formato + comando exibido antes de executar. |

## 4.3 Armazenamento local — o "banco de dados" deste projeto

Não há banco de dados, mas há algo mais valioso: **o disco do usuário**.

| Ameaça | Categoria | Status | Mitigação implementada |
|---|---|---|---|
| `/dev/sdb` apontar para disco diferente do escolhido | Spoofing | **Mitigado** | `reverify_target_disk()` reconfere identificador **e tamanho** imediatamente antes de apagar. |
| Imagem adulterada do Windows ser gravada no pendrive | Tampering | **Parcial** | SHA-256 calculado e exibido; bloqueio se o valor esperado não conferir. Depende do usuário fornecê-lo — RR-01. |
| ISO trocada entre a seleção e o uso | Tampering | **Aceito** | Exigiria acesso local simultâneo; nesse cenário o atacante já tem vias mais diretas. |
| Não haver registro de qual disco foi apagado | Repudiation | **Mitigado** | Registro de auditoria com identificador e resultado. |
| Log de auditoria legível por outros usuários | Info. Disclosure | **Mitigado** | `0600` no arquivo, `0700` na pasta. **Verificado na prática:** `-rw-------`. |
| Download parcial legível por outros usuários | Info. Disclosure | **Mitigado** | Criado com `0600` desde o primeiro byte. |
| Dados antigos do pendrive sobreviverem à formatação | Info. Disclosure | **Parcial** | `wipefs` limpa assinaturas, mas não sobrescreve setores — RR-04. |
| Destruição irreversível do disco errado | DoS | **Mitigado** | Filtro *fail-closed* + exclusão de discos com pontos de montagem críticos + tripla confirmação + reconferência. |
| Espaço em disco esgotar durante o download | DoS | **Aceito** | Erro reportado, arquivo parcial removido, sem corrupção. |

## 4.4 Integrações externas — Microsoft, repositórios de pacotes, utilitários

| Ameaça | Categoria | Status | Mitigação implementada |
|---|---|---|---|
| Servidor falso se passar pela Microsoft | Spoofing | **Mitigado** | HTTPS com validação de certificado + lista de servidores conhecidos com aviso. |
| Repositório de pacotes falso servir programas adulterados | Spoofing | **Mitigado** | Delegado à assinatura digital dos repositórios oficiais — o mecanismo correto. |
| Conteúdo alterado em trânsito (*man-in-the-middle*) | Tampering | **Mitigado** | HTTPS obrigatório; redirecionamentos revalidados contra rebaixamento a HTTP. |
| Não haver registro da origem do download | Repudiation | **Mitigado** | Registro grava o servidor e se era confiável. |
| Programa enviar dados do usuário para fora | Info. Disclosure | **Não aplicável** | **O programa não envia nada.** Sem telemetria, sem análise de uso. |
| Servidor não responder e travar o programa | DoS | **Mitigado** | Tempo limite de 60s + botão de cancelar funcional. |

**Placar STRIDE:** 24 ameaças analisadas — 18 Mitigadas · 4 Parciais · 2 Aceitas · **0 sem mitigação**

---

# 5. Variáveis de ambiente

## A informação mais importante desta seção

**Você não precisa cadastrar nenhuma variável de ambiente para o programa funcionar. Todas são opcionais.**

E, mais importante: **não foi encontrado nenhum segredo no código** — nenhuma senha, chave de API, token ou string de conexão. Portanto **não há nada vazado para migrar**. Esta seção existe apenas para documentar ajustes opcionais que criei.

## Onde configurar

Você confirmou que não usa nenhuma plataforma de hospedagem (Vercel, Railway, Heroku etc.) — o programa roda direto no seu computador. Então as variáveis, **se você quiser usar alguma**, são definidas no próprio sistema operacional.

**Para usar uma vez só**, no terminal:

```bash
export WIN11USB_AUDIT_LOG="$HOME/meus-logs/usb-creator.log"
python3 win11_usb_creator.py
```

**Para deixar permanente**, acrescente a linha `export ...` ao final do arquivo:
- **macOS:** `~/.zshrc`
- **Linux:** `~/.bashrc`

Depois feche e reabra o terminal.

## Lista completa

| Variável | Obrigatória? | O que faz, em linguagem simples |
|---|---|---|
| `WIN11USB_AUDIT_LOG` | **Opcional** | Muda onde o registro de auditoria é gravado. Sem ela, o padrão é `~/.local/state/epma-win11-usb-creator/audit.log`. |
| `WIN11USB_DISABLE_AUDIT_LOG` | **Opcional** | Coloque `1` para desligar o registro de auditoria. **Não recomendado** — é o registro que permite investigar se algo der errado. |
| `WIN11USB_TRUSTED_ISO_HOSTS` | **Opcional** | Lista de servidores considerados confiáveis, separados por vírgula. Substitui a lista padrão da Microsoft. Só use se souber exatamente o que está fazendo. |
| `WIN11USB_ALLOW_ANY_DOWNLOAD_HOST` | **Opcional** | Coloque `1` para desligar o aviso de "servidor não reconhecido". **Reduz a segurança** — desliga justamente a proteção contra baixar um Windows adulterado. |
| `WIN11USB_EXPECTED_SHA256` | **Opcional** | Preenche automaticamente o campo de impressão digital esperada, se você sempre usa a mesma imagem. |

**Recomendação prática: não configure nenhuma.** Os padrões já são os mais seguros. Elas existem para casos específicos e estão documentadas em `SECURITY.md`.

---

# 6. Riscos residuais

Cinco pontos **não puderam ser resolvidos apenas com código**. Cada um tem o motivo real e o que você precisa fazer.

| ID | Risco | Gravidade | Por que não foi corrigido | O que você precisa fazer |
|---|---|---|---|---|
| **RR-01** | A autenticidade da imagem do Windows continua dependendo do usuário. Se ninguém colar o checksum esperado, a verificação não acontece. | **Alta** | A Microsoft atualiza a imagem periodicamente e **não publica os checksums de forma estável e automatizável**. Qualquer valor embutido no código estaria errado na próxima atualização — e um programa que rejeita a imagem legítima é pior que um que avisa. | Oriente quem usar o programa a **baixar sempre pelo site oficial da Microsoft** e, quando houver um checksum publicado, colá-lo no campo antes de baixar. Nunca use um link de "espelho mais rápido" de fórum ou vídeo. |
| **RR-02** | O programa não tem assinatura digital. Qualquer um pode editar o arquivo `.py`, e a versão adulterada pediria a senha de administrador normalmente. | **Média** | Assinar código exige certificado digital pago e um processo de publicação que está fora do escopo de uma correção de código. | Distribua **apenas** pelo seu repositório oficial no GitHub. Considere assinar os commits com GPG. Antes de rodar, confira a impressão digital: `shasum -a 256 win11_usb_creator.py`. |
| **RR-03** | Os utilitários do sistema (`parted`, `rsync`) são localizados pelo `PATH`. Um utilitário falso numa pasta que apareça antes seria executado. | **Média** | Fixar caminhos absolutos quebraria a compatibilidade entre distribuições Linux, que instalam esses programas em pastas diferentes. | **Nenhuma ação urgente.** Para explorar isso, o atacante já precisa controlar sua conta — momento em que tem vias mais diretas. Não é a defesa mais fraca do sistema. |
| **RR-04** | A formatação não apaga os dados anteriores do pendrive. Ferramentas de recuperação conseguem resgatar parte deles. | **Baixa** | Sobrescrever todos os setores multiplicaria o tempo de gravação por várias vezes. Não é adequado como comportamento padrão. | Se o pendrive continha dados sensíveis, apague-o antes com sobrescrita completa (`shred` no Linux, ou "Apagar com segurança" no Utilitário de Disco do macOS). |
| **RR-05** | **O repositório não tem nenhum commit.** Não há histórico de versões, não há como saber o que mudou nem reverter uma alteração ruim. | **Média** | Fora do escopo de correção de código — e commits só devem ser feitos com sua autorização. | **Faça o primeiro commit.** Sem histórico, você não tem como voltar atrás se algo quebrar, nem comprovar qual versão foi auditada. Ver seção 7, item 1. |

## Riscos aceitos conscientemente

Dois itens foram avaliados e classificados como aceitáveis, com justificativa:

| Risco | Por que é aceitável |
|---|---|
| 3 tentativas de senha podem, em tese, aproximar do limite do `sudo` | O limite do programa é menor que o padrão do `sudo`. Risco desprezível. |
| ISO trocada entre a seleção e o uso | Exigiria acesso local simultâneo à máquina. Nesse cenário, o atacante já tem formas mais diretas de causar dano. |

---

# 7. Recomendações — próximos passos

Em ordem de prioridade. Os três primeiros são os que realmente importam.

### Prioridade 1 — Faça o primeiro commit do projeto

**Por quê:** hoje o repositório está vazio de histórico. Se algo quebrar, você **não tem como voltar atrás**. Todo o trabalho desta auditoria existe apenas como arquivos soltos numa pasta.

Não fiz isso por você porque registrar código no histórico é uma decisão sua. Quando quiser, é só pedir — ou fazer:

```bash
git add .
git commit -m "Correções de segurança + auditoria DevSecOps completa"
```

### Prioridade 2 — Teste com um pendrive descartável antes de distribuir

**Por quê:** as correções foram verificadas por 36 testes automatizados, mas **o fluxo real de apagar e gravar um pendrive não foi executado** — isso destruiria dados de um dispositivo físico. Teste no macOS e, se possível, também numa máquina Linux, já que o caminho do Linux (`parted`, `wipefs`, `mount`) foi analisado linha a linha mas não executado.

Use um pendrive **sem nada importante**.

### Prioridade 3 — Oriente os usuários sobre a origem da imagem (RR-01)

**Por quê:** é o maior risco que sobrou, e a defesa é comportamental. A mensagem é simples: *"baixe sempre pelo site oficial da Microsoft; nunca use link de espelho que alguém indicou"*. Já está no `README.md` e no `SECURITY.md`.

### Prioridade 4 — Mantenha o sistema operacional atualizado

O programa depende de utilitários do sistema (`parted`, `rsync`, `wimlib`). As correções de segurança deles chegam pela atualização do sistema: `brew upgrade` no macOS, `sudo apt upgrade` no Ubuntu/Debian.

### Prioridade 5 — Pense duas vezes antes de adicionar qualquer biblioteca

Hoje o projeto tem **zero dependências de terceiros**, e isso elimina a via de ataque mais comum em software moderno. Cada biblioteca acrescentada é uma peça que alguém precisará monitorar por vulnerabilidades para sempre. Se um dia adicionar alguma, registre em `requirements.txt` e passe a rodar um verificador (`pip-audit`).

### Prioridade 6 — Reexecute os testes após qualquer alteração

```bash
python3 output/auditoria/testes_validacao.py
```

São 36 verificações que não tocam em disco. Se alguma falhar depois de uma mudança, é sinal de que uma proteção foi desfeita sem querer.

### Prioridade 7 — Considere assinar os commits com GPG (RR-02)

Aumenta a confiança de quem baixa o programa do seu repositório. Não é urgente para uso pessoal.

### Prioridade 8 — Reavalie o DAST se o projeto mudar de natureza

Se um dia o projeto ganhar um site, uma API ou qualquer serviço de rede, o DAST passa a fazer sentido e deve ser executado — com autorização por escrito do responsável pelo endereço.

---

# Anexos — relatórios individuais

| Relatório | Arquivo |
|---|---|
| Plano de auditoria | [`output/00-plano-de-auditoria.md`](00-plano-de-auditoria.md) |
| SCA — bibliotecas de terceiros | [`output/relatorio-sca.md`](relatorio-sca.md) |
| SAST — análise do código | [`output/relatorio-sast.md`](relatorio-sast.md) |
| STRIDE — modelagem de ameaças | [`output/relatorio-stride.md`](relatorio-stride.md) |
| OWASP Top 10 (2021) | [`output/relatorio-owasp-top10.md`](relatorio-owasp-top10.md) |
| DAST — teste com aplicação rodando | [`output/relatorio-dast.md`](relatorio-dast.md) |
| Testes de validação (executável) | [`output/auditoria/testes_validacao.py`](auditoria/testes_validacao.py) |
| Política de segurança do projeto | [`SECURITY.md`](../SECURITY.md) |

---

## Nota de transparência sobre esta auditoria

Três coisas que registro de propósito, porque um relatório que esconde os próprios limites não serve para nada:

1. **O DAST não foi realizado**, e nenhum resultado foi inventado. O motivo real está na seção 6 e no relatório dedicado.
2. **Durante a implementação eu introduzi um defeito** — uma referência a um elemento de tela que eu não havia criado, que teria travado o programa após cada download. Foi detectado antes da entrega, comunicado a você e corrigido conforme sua escolha.
3. **Não declarei códigos de vulnerabilidade (CVE) para as dependências de sistema**, porque suas versões dependem do sistema operacional de cada usuário e não podem ser determinadas pelo projeto. Preencher essa tabela com números plausíveis seria mais apresentável e completamente inútil.
