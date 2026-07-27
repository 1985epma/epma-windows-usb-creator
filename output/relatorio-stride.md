# Relatório STRIDE — Modelagem de Ameaças

**Projeto:** EPMA Windows 11 Creator USB
**Data:** 27 de julho de 2026

---

## Resumo em linguagem simples

**O que é STRIDE:** é um método para imaginar, de forma organizada, todas as maneiras de atacar cada peça de um sistema — usando uma lista de 6 tipos de ameaça, para não esquecer nenhuma categoria.

O nome é uma sigla das 6 categorias, todas em inglês. Traduzindo:

| Letra | Nome original | Em português claro |
|---|---|---|
| **S** | Spoofing | **Falsificação de identidade** — alguém ou algo se passar por outro |
| **T** | Tampering | **Adulteração** — modificar dados que deveriam estar íntegros |
| **R** | Repudiation | **Negação de autoria** — fazer algo e não haver registro de quem fez |
| **I** | Information Disclosure | **Vazamento de informação** — dados chegarem a quem não deveria |
| **D** | Denial of Service | **Negação de serviço** — impedir o sistema de funcionar |
| **E** | Elevation of Privilege | **Escalação de privilégio** — ganhar poderes que não deveria ter |

### Uma adaptação necessária, e por que ela é honesta

Você pediu a análise por componente: *frontend, backend, banco de dados e integrações externas*. Essa divisão é a de uma aplicação web. **Seu projeto não é uma aplicação web** — é um programa que roda no computador da pessoa. Ele não tem servidor nem banco de dados.

Fingir que tem produziria um relatório bonito e inútil. Então mapeei os seus componentes reais para os equivalentes que você pediu:

| Componente que você pediu | Equivalente real neste projeto |
|---|---|
| **Frontend** | A janela do programa (Tkinter) — onde o usuário digita e clica |
| **Backend** | O motor que executa comandos do sistema, incluindo os que rodam **como administrador** |
| **Banco de dados** | O armazenamento local: o arquivo ISO baixado, as pastas temporárias e **o pendrive de destino** |
| **Integrações externas** | Os servidores da Microsoft, os repositórios de programas (apt/brew/etc.) e os utilitários do sistema |

### O que a modelagem revelou

**A concentração de risco deste projeto é o componente "backend" — a parte que roda como administrador.** É onde estavam as duas ameaças de maior gravidade, ambas agora mitigadas.

Um dado que ajuda a entender o perfil do sistema: das 24 ameaças analisadas, **nenhuma é de vazamento de dados de terceiros**, porque o programa não coleta, não transmite e não armazena dados de ninguém. Isso é raro e é um mérito do desenho.

### Placar

| Situação | Quantidade |
|---|---|
| Mitigado | 18 |
| Parcialmente mitigado | 4 |
| Risco aceito (com justificativa) | 2 |
| Sem mitigação | 0 |
| **Total de ameaças analisadas** | **24** |

---

## Diagrama de fluxo

```
   ┌──────────────────────────────────────────────────────────────┐
   │  USUÁRIO (tem senha de administrador da máquina)             │
   └───────────────────────────┬──────────────────────────────────┘
                               │ digita link, escolhe arquivo e disco
                               ▼
   ┌──────────────────────────────────────────────────────────────┐
   │  COMPONENTE 1 — FRONTEND (janela Tkinter)                    │
   │  Campos de link, checksum, seleção de disco, confirmações    │
   └───────────────┬──────────────────────────────┬───────────────┘
                   │                              │
                   ▼                              ▼
   ┌───────────────────────────┐   ┌──────────────────────────────┐
   │ COMPONENTE 4 — INTEGRAÇÕES│   │ COMPONENTE 2 — BACKEND       │
   │ • Servidores Microsoft    │   │ • run_cmd (privilégio normal)│
   │ • apt/dnf/brew/pacman     │   │ • PrivilegeHelper  ⚠ ROOT ⚠  │
   │ • parted/rsync/wimlib     │   │ • parted, mkfs, wipefs, mount│
   └───────────┬───────────────┘   └──────────────┬───────────────┘
               │                                  │
               ▼                                  ▼
   ┌──────────────────────────────────────────────────────────────┐
   │  COMPONENTE 3 — ARMAZENAMENTO ("banco de dados")             │
   │  Arquivo ISO · pastas temporárias · log de auditoria         │
   │  ⚠ PENDRIVE DE DESTINO (apagado por completo) ⚠              │
   └──────────────────────────────────────────────────────────────┘

   ⚠ = fronteira de confiança: aqui o privilégio aumenta ou dados são destruídos
```

---

## COMPONENTE 1 — Frontend (a janela do programa)

| # | Categoria | Ameaça | Gravidade | Status | Mitigação |
|---|---|---|---|---|---|
| F-S1 | **Spoofing** | Um programa falso se passar pelo EPMA Creator para colher a senha de administrador | Média | **Parcial** | O programa é distribuído como código-fonte legível. Não há assinatura digital do executável — ver riscos residuais. |
| F-T1 | **Tampering** | Usuário colar um link malicioso induzido por terceiros | **Alta** | **Mitigado** | Somente HTTPS; aviso obrigatório para servidor não-Microsoft; verificação SHA-256 opcional (`validate_download_url`). |
| F-T2 | **Tampering** | Valor digitado no campo de disco chegar adulterado ao comando | **Alta** | **Mitigado** | Validação estrita por expressão regular; entrada fora do formato é **recusada**, não escapada. |
| F-R1 | **Repudiation** | Usuário apagar o disco errado e não haver registro do ocorrido | Média | **Mitigado** | Registro de auditoria com data/hora de cada operação destrutiva. |
| F-I1 | **Info. Disclosure** | Caminhos internos e nome de usuário aparecerem em diálogos de erro (durante apresentação ou suporte remoto) | Baixa | **Mitigado** | `_report_error` mostra apenas o tipo do erro; detalhe vai para o log local. |
| F-D1 | **DoS** | Interface travar durante download ou gravação | Baixa | **Mitigado** | Operações longas rodam em segundo plano (`threading`); download tem tempo limite de 60s. |
| F-E1 | **Elevation** | Usuário sem privilégio usar o programa para obter privilégio | **Alta** | **Mitigado** | O `sudo` continua exigindo a senha real; o programa não contorna nada. A via que **existia** (injeção via nome de arquivo) foi eliminada. |

**Sobre a confirmação em três etapas** (marcar a caixa + digitar o identificador + confirmar no diálogo): é um bom controle contra erro humano e foi preservado integralmente. A digitação manual do identificador é especialmente eficaz — obriga o usuário a **ler** qual disco selecionou.

---

## COMPONENTE 2 — Backend (execução de comandos, incluindo como administrador)

**Este é o componente crítico do sistema.**

| # | Categoria | Ameaça | Gravidade | Status | Mitigação |
|---|---|---|---|---|---|
| B-S1 | **Spoofing** | Um programa falso chamado `parted` ou `rsync` numa pasta do `PATH` ser executado no lugar do verdadeiro | Média | **Parcial** | `shutil.which` resolve pelo `PATH` do usuário. Ver riscos residuais. |
| B-T1 | **Tampering** | Nome de arquivo ou disco injetar comandos extras no script executado como root | **Alta** | **Mitigado** | Parâmetros posicionais (`"$1"`, `"$2"`) — dados nunca são colados no texto do comando. Comprovado por teste. |
| B-T2 | **Tampering** | Script privilegiado continuar executando após uma falha no meio | Média | **Mitigado** | `set -eu` interrompe na primeira falha e em variável não definida. |
| B-R1 | **Repudiation** | Não haver registro de comandos executados como administrador | Média | **Mitigado** | Registro de auditoria + o próprio `sudo` registra no log do sistema. |
| B-I1 | **Info. Disclosure** | Senha de administrador aparecer na lista de processos (visível a outros usuários via `ps`) | **Alta** | **Mitigado** | Senha enviada exclusivamente por `stdin`, nunca como argumento. **Já estava correto no código original.** |
| B-I2 | **Info. Disclosure** | Senha permanecer na memória após o uso | Média | **Mitigado** | `clear_cached_password()` no `finally` de toda operação. |
| B-D1 | **DoS** | Tentativas repetidas de senha bloquearem a conta do usuário no `sudo` | Baixa | **Aceito** | Limite de 3 tentativas, abaixo do padrão do `sudo`. Risco desprezível. |
| B-E1 | **Elevation** | Dado controlado pelo atacante virar comando root | **Alta** | **Mitigado** | Igual a B-T1 — era a falha SAST-01. |
| B-E2 | **Elevation** | Instalar pacote arbitrário como administrador pelo botão de dependências | Média | **Mitigado** | Lista fixa no código + validação de formato + comando exibido antes de executar. |

---

## COMPONENTE 3 — Armazenamento local ("banco de dados")

Aqui não há banco de dados, mas há algo mais valioso: **o disco do usuário**.

| # | Categoria | Ameaça | Gravidade | Status | Mitigação |
|---|---|---|---|---|---|
| A-S1 | **Spoofing** | `/dev/sdb` apontar para um disco diferente do que o usuário escolheu | **Alta** | **Mitigado** | `reverify_target_disk()` reconfere identificador **e tamanho** imediatamente antes de apagar. |
| A-T1 | **Tampering** | Imagem do Windows adulterada ser gravada no pendrive | **Alta** | **Parcial** | SHA-256 calculado e exibido; verificação bloqueante se o valor esperado for informado. **Mas o usuário precisa fornecer esse valor.** Ver riscos residuais. |
| A-T2 | **Tampering** | Arquivo ISO ser trocado entre a seleção e o uso | Baixa | **Aceito** | Exigiria acesso local simultâneo à máquina; nesse cenário o atacante já tem outras vias mais diretas. |
| A-R1 | **Repudiation** | Não haver registro de qual disco foi apagado e quando | Média | **Mitigado** | Registro de auditoria com identificador e resultado da operação. |
| A-I1 | **Info. Disclosure** | Registro de auditoria legível por outros usuários da máquina | Baixa | **Mitigado** | Arquivo criado com permissão `0600`; pasta com `0700`. Verificado na prática. |
| A-I2 | **Info. Disclosure** | Download parcial (`.part`) legível por outros usuários | Baixa | **Mitigado** | Criado com `0600` desde o primeiro byte. |
| A-I3 | **Info. Disclosure** | Dados antigos do pendrive sobreviverem à formatação | Baixa | **Parcial** | `wipefs` limpa as assinaturas, mas não sobrescreve todos os setores. Ver riscos residuais. |
| A-D1 | **DoS** | Destruição irreversível dos dados do disco errado | **Alta** | **Mitigado** | Filtro fail-closed + exclusão de discos com pontos de montagem críticos + tripla confirmação + reconferência. |
| A-D2 | **DoS** | Espaço em disco esgotar durante o download de ~5 GB | Baixa | **Aceito** | O erro do sistema é reportado e o arquivo parcial é removido. Não há corrupção. |

---

## COMPONENTE 4 — Integrações externas

| # | Categoria | Ameaça | Gravidade | Status | Mitigação |
|---|---|---|---|---|---|
| E-S1 | **Spoofing** | Servidor falso se passar pela Microsoft | **Alta** | **Mitigado** | HTTPS obrigatório com validação de certificado (confirmada: `CERT_REQUIRED`) + lista de servidores conhecidos com aviso. |
| E-S2 | **Spoofing** | Repositório de pacotes falso servir programas adulterados | Média | **Mitigado** | Delegado à assinatura digital dos repositórios oficiais (apt/dnf/pacman/brew), que é o mecanismo correto. |
| E-T1 | **Tampering** | Conteúdo alterado em trânsito (ataque *man-in-the-middle*) | **Alta** | **Mitigado** | HTTPS obrigatório; redirecionamentos revalidados para impedir rebaixamento a HTTP. |
| E-R1 | **Repudiation** | Não haver registro da origem do download | Baixa | **Mitigado** | Registro de auditoria grava o servidor de origem e se era confiável. |
| E-I1 | **Info. Disclosure** | O programa enviar dados do usuário para fora | — | **Não aplicável** | **O programa não envia nada.** Não há telemetria, análise de uso ou envio de dados. Só faz download. |
| E-D1 | **DoS** | Servidor não responder e travar o programa | Baixa | **Mitigado** | Tempo limite de 60 segundos por leitura + botão de cancelar funcional. |

---

## Riscos residuais

Os quatro pontos abaixo **não puderam ser resolvidos apenas com código**. São honestos e cada um tem uma ação recomendada.

### R1 — A imagem do Windows continua sem verificação obrigatória · **Alta**

**O que fizemos:** o programa calcula e mostra a impressão digital SHA-256, avisa quando o servidor não é da Microsoft e bloqueia o arquivo se o usuário informar um valor esperado que não confere.

**O que continua faltando:** se o usuário não informar nenhum valor esperado, a verificação não acontece. Não é possível embutir o valor correto no código, porque a Microsoft muda a imagem a cada atualização e **não publica os checksums de forma estável e automatizável**.

**Ação recomendada:** oriente quem for usar o programa a baixar sempre pelo site oficial da Microsoft e, quando um checksum estiver disponível, colá-lo no campo. É o único elo que depende de uma pessoa.

### R2 — Não há assinatura digital do próprio programa · **Média**

Qualquer pessoa com acesso ao arquivo `win11_usb_creator.py` pode modificá-lo. Como ele pede a senha de administrador, uma versão adulterada é um alvo atraente.

**Ação recomendada:** distribua o programa apenas pelo repositório oficial do GitHub e considere assinar os commits com GPG. Para uso pessoal, verifique que o arquivo veio do seu próprio repositório.

### R3 — Utilitários do sistema são localizados pelo `PATH` · **Média**

O programa usa `shutil.which("parted")` para encontrar os utilitários. Se um atacante já conseguiu colocar um `parted` falso numa pasta que apareça antes no `PATH` do usuário, ele seria executado.

**Avaliação honesta:** para explorar isso, o atacante já precisa ter conseguido escrever no `PATH` do usuário — momento em que ele já tem controle suficiente da conta para atacar de formas mais diretas. **Não é a defesa mais fraca do sistema.**

**Ação recomendada:** nenhuma ação urgente. Se quiser máxima rigidez, é possível fixar os caminhos absolutos (`/usr/sbin/parted`), ao custo de compatibilidade entre distribuições.

### R4 — A formatação não apaga os dados anteriores do pendrive · **Baixa**

`wipefs` + formatação removem a "tabela de conteúdo" do pendrive, mas os dados antigos continuam fisicamente nos setores até serem sobrescritos. Ferramentas de recuperação conseguem resgatar parte deles.

**Ação recomendada:** se o pendrive continha dados sensíveis, apague-o antes com sobrescrita completa (`shred`, ou "Apagar com segurança" no Utilitário de Disco do macOS). Implementar isso no programa multiplicaria o tempo de gravação por várias vezes — não é adequado como comportamento padrão.

---

## Conclusão

O perfil de risco deste sistema é incomum e vale resumir: **ele não guarda dados de ninguém, não tem usuários para autenticar e não fala com a internet além de baixar um arquivo.** As categorias que dominam auditorias de sistemas web — vazamento de dados pessoais, falhas de autenticação, controle de acesso — são em grande parte inaplicáveis aqui.

Em compensação, ele concentra dois poderes que poucos programas têm: **executar comandos como administrador** e **destruir discos inteiros**. As duas ameaças de maior gravidade estavam exatamente aí (B-E1/B-T1 e A-S1/A-D1), e as duas foram mitigadas.

O risco que sobra e mais merece sua atenção é o **R1** — e ele não é um defeito de código, é um limite do mundo real: nenhum programa consegue garantir sozinho que uma imagem de sistema operacional baixada da internet é autêntica, se quem a publica não fornece um valor de referência confiável.
