# Relatório SCA — Análise de Bibliotecas de Terceiros

> **Nota (v1.1.0):** este relatório registra a auditoria da **v1.0.0** e não foi reescrito. Controles
> que mudaram depois: a *confirmação em três etapas* (caixa + digitação + diálogo) foi substituída por
> *diálogo final sempre* + *digitação do identificador só para discos de alto risco* (grandes, com dados);
> o filtro de discos passou a ser **somente USB** (sem `mmc`/removível genérico); toda gravação é
> **verificada por releitura antes do eject**; a senha de administrador é conferida **antes** de mexer no
> pendrive e não fica retida na memória. Detalhes: `CHANGELOG.md` e `SECURITY.md`.

**Projeto:** EPMA Windows 11 Creator USB
**Data:** 27 de julho de 2026
**Arquivo analisado:** `win11_usb_creator.py` (819 linhas)

---

## Resumo em linguagem simples

**O que é SCA:** é a conferência dos "ingredientes de terceiros" do seu programa. Quase todo software moderno é montado com pedaços de código escritos por outras pessoas. Se um desses pedaços tem um defeito de segurança conhecido, o seu programa herda o defeito — mesmo que o seu código esteja perfeito.

**O resultado, em uma frase: seu projeto está numa situação invejável.**

Seu programa **não usa nenhuma biblioteca de terceiros do Python**. Nenhuma. Ele usa apenas o que já vem instalado junto com o Python (chamado "biblioteca padrão"), que é mantido pela própria equipe do Python.

Para você ter noção do que isso significa: um projeto Python comum tem entre 20 e 200 bibliotecas de terceiros, cada uma podendo ter suas próprias bibliotecas, formando uma corrente de centenas de peças que ninguém audita de verdade. É de longe a porta de entrada mais comum de ataques hoje. **O seu projeto tem zero peças nessa corrente.** Isso não foi sorte nem descuido — foi uma boa decisão de arquitetura, e minha recomendação é que você a mantenha.

**Porém, há uma nuance importante.** O programa não depende de bibliotecas Python, mas **depende de programas do sistema operacional** — `parted`, `rsync`, `wimlib`, entre outros — que ele chama para fazer o trabalho pesado. Esses programas são código de terceiros também, e o seu programa chega a **instalá-los automaticamente como administrador**. É aí que fica a sua superfície de risco real de "ingredientes".

**E há um "ingrediente" que ninguém costuma enxergar como tal: a imagem do Windows 11 de 5 GB que o programa baixa e grava no pendrive.** É o maior componente de terceiros de todo o fluxo, e hoje ele é aceito sem nenhuma conferência de autenticidade. Este é o achado mais grave deste relatório.

### Placar

| Gravidade | Quantidade |
|---|---|
| Crítica | 0 |
| Alta | 1 |
| Média | 1 |
| Baixa | 1 |
| Info | 3 |

---

## 1. Dependências Python (bibliotecas de terceiros)

### 1.1 Inventário completo

Todos os módulos importados pelo projeto, conforme linhas 40–51 e 53–55 de `win11_usb_creator.py`:

| Módulo importado | Origem | Terceiro? | Observação |
|---|---|---|---|
| `json` | Biblioteca padrão do Python | Não | Leitura da saída do `lsblk` |
| `os` | Biblioteca padrão | Não | Operações de arquivo |
| `platform` | Biblioteca padrão | Não | Detecção do sistema operacional |
| `plistlib` | Biblioteca padrão | Não | Leitura da saída do `diskutil` (macOS) |
| `shutil` | Biblioteca padrão | Não | Cópia de arquivos, busca de executáveis |
| `subprocess` | Biblioteca padrão | Não | Execução de comandos do sistema |
| `sys` | Biblioteca padrão | Não | Saída do programa |
| `tempfile` | Biblioteca padrão | Não | Pastas temporárias |
| `threading` | Biblioteca padrão | Não | Trabalho em segundo plano |
| `time` | Biblioteca padrão | Não | Esperas e cálculo de velocidade |
| `urllib.request` | Biblioteca padrão | Não | Download da ISO |
| `webbrowser` | Biblioteca padrão | Não | Abrir o site da Microsoft |
| `tkinter` / `ttk` | Biblioteca padrão (interface gráfica) | Não | A janela do programa |

**Total de dependências de terceiros em Python: 0.**

### 1.2 Sobre o que apareceu no `pip list` — atenção para não se confundir

Ao rodar o comando que lista bibliotecas instaladas neste computador, apareceram 28 pacotes (`Flask`, `requests`, `cryptography`, `pillow`, `lxml`, `PyJWT`, `msal`, etc.).

**Nenhum deles é dependência deste projeto.** Eles estão instalados no seu computador porque você (ou outro programa) os instalou para outros usos. Uma ferramenta automática de SCA mal configurada apontaria esses 28 pacotes como "dependências do projeto" e geraria um relatório inteiro de vulnerabilidades falsas. Estou registrando isso explicitamente para que ninguém — nem uma ferramenta, nem um auditor futuro — cometa esse erro no seu projeto.

A prova é simples: o projeto só importa os módulos da tabela 1.1, todos da biblioteca padrão.

### 1.3 Interpretador Python

| Componente | Versão neste computador | Situação |
|---|---|---|
| Python | 3.14.6 | Atual e suportado |
| OpenSSL (usado para conexões seguras) | 3.6.3 (9/jun/2026) | Atual |
| Verificação de certificado HTTPS | Ativada por padrão (`CERT_REQUIRED`) | Correto |

**Nota positiva:** confirmei por teste que o Python valida os certificados de segurança das conexões HTTPS por padrão. Isso significa que, **quando** o download acontece por HTTPS, ninguém no meio do caminho consegue se passar pelos servidores da Microsoft. (O problema, como vamos ver no item 3.1, é que o programa não *obriga* o uso de HTTPS.)

---

## 2. Dependências de sistema (programas do sistema operacional)

Estas são as verdadeiras dependências de terceiros do projeto. O programa não as "importa" — ele as **executa**. Declaradas em `win11_usb_creator.py:79` (`LINUX_REQUIRED_TOOLS`).

### 2.1 Inventário

| Programa | Para que serve | Plataforma | Presente neste Mac |
|---|---|---|---|
| `diskutil` | Apagar/formatar disco | macOS (vem da Apple) | Sim — `/usr/sbin/diskutil` |
| `hdiutil` | Montar a imagem ISO | macOS (vem da Apple) | Sim — `/usr/bin/hdiutil` |
| `rsync` | Copiar os arquivos para o pendrive | Ambos | Sim — `/usr/bin/rsync` (ver 2.2) |
| `wimlib-imagex` | Dividir o arquivo grande do Windows | Ambos | Sim — 1.14.5 |
| `sudo` | Executar comandos como administrador | Linux | Sim — 1.9.17p2 |
| `parted` / `partprobe` | Particionar o disco | Linux | Ausente (normal no macOS) |
| `mkfs.vfat` | Formatar em FAT32 | Linux | Ausente (normal no macOS) |
| `wipefs` | Limpar assinaturas do disco | Linux | Ausente (normal no macOS) |
| `pkexec` | Alternativa ao `sudo` | Linux | Ausente (normal no macOS) |
| `brew` | Instalador de programas | macOS | Sim |

### 2.2 SCA-01 — O `rsync` do macOS não é o `rsync` que ele diz ser · **Info**

Ao perguntar a versão do `rsync` neste Mac, a resposta foi:

```
openrsync: protocol version 29
rsync version 2.6.9 compatible
```

Traduzindo: desde versões recentes do macOS, a Apple substituiu o `rsync` original por um programa diferente chamado **openrsync**, que apenas *finge* ser a versão 2.6.9 para manter compatibilidade.

**Por que isso importa:** uma ferramenta automática de segurança leria "rsync 2.6.9" (uma versão de 2006, com várias falhas conhecidas) e geraria um alarme falso gravíssimo. Não é o caso: o programa instalado é o openrsync, atual e mantido pela Apple.

**Não é uma vulnerabilidade.** É um registro para evitar diagnóstico errado no futuro, e um lembrete de que **auditar dependências de sistema por número de versão não é confiável** — ao contrário das bibliotecas Python, que têm versão exata e banco de dados de vulnerabilidades.

### 2.3 SCA-02 — Não é possível declarar vulnerabilidades conhecidas das dependências de sistema · **Info**

Você pediu que eu identificasse quais dependências têm vulnerabilidades conhecidas e a versão segura para cada uma. **Preciso ser honesto sobre um limite real aqui, em vez de preencher a tabela com dados inventados.**

Para bibliotecas Python, isso é objetivo: existe um banco de dados público que diz "a versão 2.30.0 da biblioteca X tem a falha CVE-AAAA-NNNN, corrigida na 2.31.0". Como seu projeto tem **zero** bibliotecas Python de terceiros, essa tabela seria vazia de qualquer forma.

Para as dependências de sistema, a situação é diferente e não permite uma resposta única:

- A versão de `parted`, `rsync` ou `wimlib` **não é definida pelo seu projeto** — é definida pela distribuição Linux ou versão do macOS de **cada usuário**. Um usuário no Ubuntu 22.04 e outro no Fedora 42 terão versões diferentes.
- Cada distribuição aplica correções de segurança nas suas próprias versões sem mudar o número (o chamado *backport*), então o número da versão não diz se a falha está corrigida.
- Portanto, **não existe "a versão segura para atualizar"** que eu possa recomendar para o seu projeto. A resposta correta é: *cada usuário deve manter o sistema operacional atualizado.*

**Nenhum scanner automático (`pip-audit`, `bandit`, `semgrep`, `trivy`, `grype`, `osv-scanner`) está instalado neste ambiente**, e instalar um deles não mudaria a conclusão — não há manifesto de dependências Python para escanear.

**O que registro em vez de números inventados:** as três dependências abaixo merecem atenção, não por uma falha específica conhecida, mas pelo poder que exercem no seu fluxo.

| Dependência | Por que merece atenção |
|---|---|
| `wimlib-imagex` | Processa um arquivo de vários GB vindo da internet. Se tiver falha de leitura de arquivo malformado, o arquivo malicioso é o vetor. |
| `parted` / `mkfs.vfat` / `wipefs` | Executam **como administrador** e destroem dados por natureza. |
| `rsync` | Copia milhares de arquivos vindos da imagem baixada. |

**Recomendação:** documentar no README que o usuário deve manter o sistema atualizado (`sudo apt upgrade`, `brew upgrade`). É a única mitigação real e está sob o controle do usuário, não do seu código.

---

## 3. Achados de risco na cadeia de suprimentos

### 3.1 SCA-03 — A imagem do Windows 11 é aceita sem nenhuma verificação de autenticidade · **Alta**

**Localização:** `win11_usb_creator.py:496–523` (classe `DownloadThread`) e `win11_usb_creator.py:249` (uso do arquivo).

**O que acontece hoje:** o usuário cola um endereço na caixa de texto, o programa baixa o que estiver naquele endereço, e grava esse conteúdo no pendrive. **O programa não confere de forma alguma se o que chegou é realmente o Windows da Microsoft.**

**Por que isso é grave, em linguagem simples:** o arquivo baixado não é um dado qualquer — é um **sistema operacional inteiro que a pessoa vai instalar no computador dela e usar para tudo**. Se alguém conseguir substituí-lo por uma versão adulterada, essa pessoa instala, com as próprias mãos, um Windows com porta dos fundos embutida. E vai confiar nele completamente, porque instalou "do jeito certo".

**Como um atacante exploraria:**

1. **O caminho mais fácil — engenharia social.** O programa aceita *qualquer* endereço. Basta convencer o usuário a colar um link de um "espelho mais rápido" (num fórum, num vídeo, num grupo). O programa obedece sem questionar.
2. **Endereço sem criptografia.** Se o link colado começar com `http://` em vez de `https://`, o conteúdo trafega aberto e pode ser trocado no caminho (num Wi-Fi público, por exemplo). O código não exige `https://`.
3. **Redirecionamento.** Um link `https://` legítimo pode redirecionar para `http://`, e o `urllib` segue o redirecionamento silenciosamente.

**O agravante:** as instruções na tela (linhas 550–560) ensinam o usuário a *copiar e colar um link*, treinando-o exatamente para o comportamento que o ataque explora.

**Correção aplicada:** ver Etapa 8 do plano — implementada verificação de esquema HTTPS obrigatório, aviso sobre domínios não-Microsoft, e cálculo de impressão digital SHA-256 do arquivo baixado com verificação opcional. Detalhes no relatório SAST (achado SAST-04).

### 3.2 SCA-04 — Comando `pacman -Sy` pode quebrar sistemas Arch Linux · **Média**

**Localização:** `win11_usb_creator.py:97` —

```python
"pacman": "pacman -Sy --noconfirm {pkgs}",
```

**O que é:** quando falta um programa, seu app oferece instalá-lo automaticamente **como administrador**. No Arch Linux, ele executa `pacman -Sy`.

**O problema:** `-Sy` atualiza a lista de programas disponíveis mas instala apenas o pacote pedido, sem atualizar o resto do sistema. Isso é chamado de "atualização parcial" e é **explicitamente desaconselhado pela documentação oficial do Arch Linux** — pode deixar o sistema num estado inconsistente e, em casos ruins, impedir que a máquina inicialize.

Traduzindo para o cotidiano: é como trocar o motor do carro por um modelo novo mantendo as peças velhas ao redor. Às vezes funciona; às vezes o carro não liga mais.

**Por que classifico como Média e não Baixa:** o comando roda como administrador, com `--noconfirm` (sem perguntar nada ao usuário), e o dano é no sistema inteiro do usuário — não só no seu programa.

**Correção aplicada:** trocado para `pacman -Syu --noconfirm {pkgs}`, que atualiza o sistema junto e é a forma recomendada oficialmente.

### 3.3 SCA-05 — Instalação automática de pacotes como administrador · **Baixa**

**Localização:** `win11_usb_creator.py:653–678` (`install_dependencies`) e `win11_usb_creator.py:92–99`.

**O que acontece:** o botão "Install missing dependencies" executa comandos de instalação **como administrador**, sem que o usuário veja o que será instalado antes de aprovar.

**Avaliação:** o risco é baixo, e vou explicar por que **não** é grave, para não te alarmar à toa:

- A lista de programas a instalar é **fixa dentro do código** (`LINUX_PKG_MAP`, linhas 80–91) — não vem da internet nem do que o usuário digita. Um atacante não consegue fazer o programa instalar um pacote arbitrário.
- Os pacotes vêm dos repositórios oficiais da distribuição, que são assinados digitalmente.

**O que permanece como risco:** o usuário não vê o comando antes de autorizar, e digita a senha de administrador para uma operação cujo conteúdo desconhece. Isso é um mau hábito de segurança sendo ensinado ao usuário.

**Correção aplicada:** o comando exato passou a ser exibido no log **antes** da execução, e a lista de pacotes é validada contra uma lista permitida antes de montar o comando.

---

## 4. Pontos fortes identificados

Vale registrar o que está certo, porque é bastante:

| Ponto forte | Por que importa |
|---|---|
| **Zero dependências Python de terceiros** | Elimina a via de ataque mais comum em software moderno. |
| **Arquivo único, sem instalação** | Não há processo de build nem publicação em repositório de pacotes que possa ser comprometido. |
| **HTTPS com validação de certificado ativa** | Conexões seguras são de fato verificadas pelo Python. |
| **Comandos montados como lista de argumentos** em `run_cmd` (linha 114) | A forma correta de chamar programas: impede injeção de comandos nesse ponto específico. |
| **Lista de pacotes fixa no código** | Impede que um atacante escolha o que será instalado como administrador. |

---

## 5. Tabela consolidada de achados SCA

| ID | Achado | Gravidade | Versão segura recomendada | Status |
|---|---|---|---|---|
| SCA-03 | Imagem do Windows aceita sem verificação de autenticidade | **Alta** | Não aplicável (falta de controle, não versão) | Corrigido |
| SCA-04 | `pacman -Sy` causa atualização parcial no Arch Linux | **Média** | Não aplicável (correção de comando) | Corrigido |
| SCA-05 | Instalação de pacotes como admin sem transparência | **Baixa** | Não aplicável | Corrigido |
| SCA-01 | `rsync` do macOS é openrsync disfarçado | Info | Nenhuma ação necessária | Documentado |
| SCA-02 | Vulnerabilidades de dependências de sistema não determináveis | Info | Manter o SO atualizado | Documentado |
| SCA-06 | Projeto sem arquivo declarando ausência de dependências | Info | — | Corrigido (ver abaixo) |

### SCA-06 — Ausência de manifesto de dependências · **Info**

O projeto não tem `requirements.txt` nem `pyproject.toml`. Hoje isso é inofensivo (não há o que declarar), mas cria dois problemas práticos:

1. Ferramentas de segurança automáticas não conseguem distinguir "projeto sem dependências" de "projeto não escaneado", e podem silenciosamente pular o projeto.
2. Se alguém adicionar uma biblioteca de terceiros no futuro, não há lugar óbvio para registrá-la, e a boa propriedade atual se perde sem ninguém perceber.

**Correção aplicada:** criado `requirements.txt` documentando explicitamente a ausência de dependências de terceiros, e `SECURITY.md` com as dependências de sistema listadas.

---

## 6. Conclusão

O seu projeto **não tem nenhuma vulnerabilidade conhecida herdada de biblioteca de terceiros**, pela razão mais sólida possível: não usa nenhuma. Mantenha assim — cada biblioteca adicionada no futuro é uma peça que alguém precisará auditar para sempre.

O risco real de "cadeia de suprimentos" deste projeto não está em bibliotecas, e sim no **arquivo de 5 GB baixado da internet e gravado como sistema operacional**, que era aceito sem qualquer verificação. Esse é o achado que exigiu correção urgente.
