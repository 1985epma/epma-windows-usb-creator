# EPMA USB CREATOR

[English](README.md) · **Português**

> A versão oficial deste documento é o [README.md em inglês](README.md). Esta
> tradução é mantida por conveniência e pode ficar desatualizada em relação a ela.

Aplicação multiplataforma (**macOS** e **qualquer distribuição Linux**) para baixar a ISO oficial do Windows 11 e gravar um pendrive bootável no padrão **UEFI (GPT + FAT32)**. Também grava **qualquer ISO híbrida** (Ubuntu, Debian, Fedora, Mint, Arch…) e o **ChromeOS Flex do Google** direto no pendrive, e toda gravação é **relida e verificada** antes de o pendrive ser ejetado.

Tem interface gráfica (em inglês americano) e um [modo linha de comando](#linha-de-comando).

Escrita em Python puro com Tkinter — **sem dependências de bibliotecas Python externas**.

![Licença](https://img.shields.io/badge/licen%C3%A7a-GPLv3-blue)
![Plataformas](https://img.shields.io/badge/plataformas-macOS%20%7C%20Linux-lightgrey)
![Python](https://img.shields.io/badge/python-3.10%2B-green)
[![Release](https://img.shields.io/github/v/release/1985epma/epma-windows-usb-creator)](https://github.com/1985epma/epma-windows-usb-creator/releases/latest)
[![CI](https://github.com/1985epma/epma-windows-usb-creator/actions/workflows/ci.yml/badge.svg)](https://github.com/1985epma/epma-windows-usb-creator/actions/workflows/ci.yml)

<p align="center">
  <img src="docs/images/interface.png" alt="Janela do EPMA USB CREATOR: cinco cartões (Google Chrome, Windows 11, Linux, Other ISO, Hardening seed), a opção de reforço do Windows, a lista de pendrives e o botão Create Bootable USB Drive" width="620">
  <br><em>O programa inteiro em uma janela: escolha o tipo de imagem, o pendrive e o arquivo, e crie.</em>
</p>

---

## Índice

- [Recursos](#recursos)
- [Novidades da 1.1.0](#novidades-da-110)
- [Como funciona](#como-funciona)
- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Uso](#uso)
- [Segurança](#segurança)
- [Desenvolvimento](#desenvolvimento)
- [Solução de problemas](#solução-de-problemas)
- [Limitações](#limitações)
- [Licença](#licença)

---

## Recursos

- **Download da ISO** direto pela aplicação, com barra de progresso, velocidade, tempo restante e botão de cancelar.
- **Uso de ISO já existente**, caso você já tenha baixado o arquivo pelo navegador.
- **Formatação automática** do pendrive como GPT + FAT32 com rótulo `WIN11USB` (compatível com boot UEFI, sem precisar desativar o Secure Boot).
- **Divisão automática do `install.wim` / `install.esd`**: esses arquivos costumam passar de 4 GB, o limite do FAT32. A aplicação detecta o caso e divide o arquivo em `.swm` usando `wimlib-imagex`.
- **Instalação automática de dependências**: detecta o gerenciador de pacotes (`apt-get`, `dnf`, `yum`, `pacman`, `zypper`, `apk`) ou o Homebrew no macOS e instala o que estiver faltando. Ferramentas ausentes são detectadas **antes** de apagar qualquer coisa: o botão Create fica desativado, com uma dica do que instalar.
- **Quatro cartões de imagem**: *Google Chrome* (ChromeOS Flex), *Windows 11*, *Linux* e *Other ISO*. O *Windows 11* é formatado como GPT + FAT32 e tem os arquivos copiados; os outros três são gravados byte a byte, como o `dd` (*Linux* e *Other ISO* gravam do mesmo jeito). O cartão é escolhido pelo **conteúdo** da imagem, não pelo nome do arquivo, e você sempre pode trocá-lo.
- **ChromeOS Flex**: o cartão *Google Chrome* baixa a imagem oficial do Google (`dl.google.com`, HTTPS, com retomada), extrai do ZIP com segurança e a prepara para o pendrive. O ChromeOS comum não é distribuído para PCs em geral; por isso o Flex — o ChromeOS gratuito do Google para PCs e Macs — é a opção oficial.
- **Gravação verificada**: depois de gravar, o pendrive é relido e comparado com a ISO (byte a byte nas imagens Linux; comparação de checksum e `wimlib-imagex verify` no Windows). Se algo for diferente, o pendrive **não** é ejetado e você é avisado para não usá-lo.
- **Eject confiável** depois da verificação, com mensagem clara se o sistema recusar.
- **Pendrives encontrados automaticamente** ao abrir o programa e sempre que você volta à janela; uma dica sob o botão **Criar** diz o que ainda falta (arquivo da imagem ou pendrive) enquanto ele está desativado.
- **Barra de progresso** com porcentagem, velocidade e tempo restante na gravação e na verificação; botão **Cancel** para a operação inteira.
- **Proteção contra apagar o disco errado**: só discos USB são listados, com modelo e volumes; o disco do sistema nunca aparece; discos de risco (grandes, com dados ou parecidos com disco de backup) exigem que você **digite o identificador**; e há sempre uma confirmação final. Fechar a janela durante a gravação pede confirmação antes, e uma ISO do Windows maior que o pendrive é recusada logo de início.
- **Conferência SHA-256 de uma ISO que você já tem** (cole o valor esperado ou uma linha de `SHA256SUMS`).
- **Download com retomada** e novas tentativas automáticas.
- **Modo linha de comando** (`list`, `write`, `detect`, `sha256`, `--dry-run`, saída JSON, códigos de saída) para scripts.
- **Documentação integrada**: abra **Help → EPMA USB CREATOR Help** (ou tecle **F1**) para ver guias rápidos, uma referência da janela e dos cinco cartões, segurança, verificação e eject, linha de comando, solução de problemas e os arquivos/configurações usados (a documentação da janela é em inglês).
- **Verificação de integridade**: downloads só por HTTPS, avisos para servidores desconhecidos e o checksum SHA-256 da imagem baixada.
- **Reforço da instalação (opcional, experimental):** uma opção do Windows e um pendrive *Hardening seed* para Ubuntu, Fedora/RHEL, Debian e Windows 11 que fazem uma instalação nova começar com configurações mais seguras; veja [Reforço da instalação](#reforço-da-instalação-opcional).
- **Log em tempo real** de todos os comandos executados, dentro da própria janela: abra **Show details** para lê-lo (ele abre sozinho quando uma gravação falha).

## Novidades da 1.1.0

- **Uma janela só, com quatro cartões** (Google Chrome, Windows 11, Linux, Other ISO), em vez de telas separadas.
- **ChromeOS Flex**: baixado do Google, extraído com segurança e gravado no pendrive.
- **Gravação verificada**: o pendrive é relido e comparado antes de ser ejetado, e o eject é confiável.
- **Modo linha de comando** com `--dry-run`, saída JSON e códigos de saída documentados.
- **Mais proteção contra apagar o disco errado**: modelo e volumes exibidos, confirmação digitada para discos de risco, reconferência do número de série, dependências checadas antes de apagar qualquer coisa.
- **Ajuda integrada** (**F1**) e botão **Cancel** para a operação inteira.
- Funciona em Python até a versão **3.15**.

Todas as mudanças estão no [CHANGELOG](CHANGELOG.md); os downloads ficam na página de [Releases](https://github.com/1985epma/epma-windows-usb-creator/releases).

## Como funciona

1. A ISO é montada em modo somente leitura (`hdiutil` no macOS, `mount -o loop,ro` no Linux).
2. O pendrive é apagado e reparticionado como GPT com uma partição FAT32 marcada como ESP.
3. Todos os arquivos da ISO são copiados com `rsync`, **exceto** o `install.wim`/`install.esd`.
4. Esse arquivo grande é tratado à parte: se couber no limite do FAT32, é copiado direto; se passar de 4 GB, é dividido em partes de ~3,8 GB com `wimlib-imagex split`.
5. As escritas são sincronizadas em disco, o pendrive é remontado e **relido para verificar** que cada arquivo confere com a ISO (no modo Linux a ISO é gravada direto e todo o conteúdo do pendrive é comparado com ela).
6. Só então o pendrive é desmontado e ejetado com segurança.

## Requisitos

### macOS

```bash
brew install python-tk@3.15 wimlib
```

> É necessário Python **3.10 ou mais novo**. Use a fórmula `python-tk` que corresponde à versão do seu Python (por exemplo `python-tk@3.15` para o Python 3.15). No modo Windows o macOS não precisa de `sudo` (as operações de disco passam por `diskutil` e `hdiutil`); o modo Linux, que grava o dispositivo bruto, pede a sua senha de administrador.

### Linux

Os nomes dos pacotes variam por distribuição. Ferramentas necessárias:

| Ferramenta | Debian/Ubuntu | Fedora/RHEL | Arch | openSUSE |
|---|---|---|---|---|
| `parted`, `partprobe` | `parted` | `parted` | `parted` | `parted` |
| `mkfs.vfat` | `dosfstools` | `dosfstools` | `dosfstools` | `dosfstools` |
| `wipefs` | `util-linux` | `util-linux` | `util-linux` | `util-linux` |
| `rsync` | `rsync` | `rsync` | `rsync` | `rsync` |
| `wimlib-imagex` | `wimtools` | `wimlib-utils` | `wimlib` | `wimlib` |
| GUI (Tkinter) | `python3-tk` | `python3-tkinter` | `tk` | `python3-tk` |

Exemplo em Debian/Ubuntu:

```bash
sudo apt install python3-tk parted dosfstools util-linux rsync wimtools
```

Você também pode simplesmente abrir a aplicação e usar o botão **"Install missing dependencies"** acima do botão Create — ela monta e executa o comando certo para o seu gerenciador de pacotes.

No Linux, particionar/formatar/montar um dispositivo de bloco exige privilégios de root, então a aplicação pede sua senha de administrador (via `sudo`, ou `pkexec` se `sudo` não existir).

## Instalação

### Homebrew (macOS — recomendado)

```bash
brew tap 1985epma/tap
brew trust 1985epma/tap
brew install epma-windows-usb-creator
```

Depois execute com `epma-windows-usb-creator`.

O Homebrew instala sozinho o `wimlib` e um Python com Tkinter, então não há
mais nada para instalar. O `brew trust` é exigido pelo Homebrew para qualquer
tap de terceiros — é uma confirmação única de que você aceita código deste
tap.

### A partir de um release

Cada [release](https://github.com/1985epma/epma-windows-usb-creator/releases) traz o programa, os checksums e a lista de componentes (SBOM). Baixe, confira e execute:

```bash
V=v1.1.0
curl -fsSLO https://github.com/1985epma/epma-windows-usb-creator/releases/download/$V/win11_usb_creator.py
curl -fsSLO https://github.com/1985epma/epma-windows-usb-creator/releases/download/$V/SHA256SUMS.txt
grep ' win11_usb_creator.py$' SHA256SUMS.txt | shasum -a 256 -c -          # deve imprimir: OK
gh attestation verify win11_usb_creator.py --repo 1985epma/epma-windows-usb-creator   # prova que o GitHub o gerou a partir deste repositório
python3 win11_usb_creator.py
```

### A partir do código-fonte

```bash
git clone https://github.com/1985epma/epma-windows-usb-creator.git
cd epma-windows-usb-creator
chmod +x win11_usb_creator.py
```

**Verifique o arquivo antes de executá-lo.** Esta aplicação pede a sua senha de administrador, o que faz de uma cópia adulterada um alvo valioso para um atacante:

```bash
shasum -a 256 win11_usb_creator.py
```

Para arquivos baixados de uma [release](https://github.com/1985epma/epma-windows-usb-creator/releases), compare o resultado com o `SHA256SUMS.txt` publicado, ou verifique a atestação de procedência da build emitida pelo GitHub:

```bash
gh attestation verify win11_usb_creator.py --repo 1985epma/epma-windows-usb-creator
```

## Uso

```bash
python3 win11_usb_creator.py
```

### A janela

Uma janela só, com três etapas numeradas — **1 Image type** (cinco cartões: os quatro tipos de imagem e o opcional **Hardening seed**), **2 Image** (onde obter e o arquivo) e **3 USB drive** — e o botão **Create**. Um cabeçalho fino mostra a versão, um indicador **Ready** / **Missing tools** das ferramentas necessárias e o **Help**.

1. **Escolha um cartão** — *Google Chrome* (ChromeOS Flex), *Windows 11*, *Linux* ou *Other ISO*. O painel sob os cartões mostra onde obter esse tipo de imagem. Ao selecionar um arquivo de imagem, o cartão certo é escolhido para você, pelo **conteúdo** do arquivo.
2. **Obtenha a imagem** (pule se já tiver):
   - **Windows 11** — clique em **"Open Microsoft's official page"**, escolha *Windows 11 (multi-edition ISO)* e o idioma, **clique com o botão direito** no botão azul de 64 bits e escolha **"Copiar endereço do link"** (não clique nele). Cole o link, opcionalmente cole o SHA-256 da Microsoft e clique em **"Download ISO"**.
   - **Google Chrome (ChromeOS Flex)** — clique em **"Download ChromeOS Flex from Google"**; o ZIP é baixado (com retomada), extraído e selecionado para você. Detalhes abaixo.
   - **Linux / Other ISO** — baixe a ISO no site da sua distribuição.
3. **Selecione o arquivo** com **"Select existing ISO file..."** (um `.zip` do ChromeOS Flex é extraído para você). Aparece o link **"Verify the selected ISO (SHA-256)"** sob o nome do arquivo: clique nele, cole o hash publicado (ou uma linha do `SHA256SUMS`) e clique em **"Calculate SHA-256"**.
4. **Escolha o pendrive** — conecte-o (**mínimo 8 GB**; **16 GB ou mais** para o ChromeOS Flex) e selecione a linha dele (modelo, tamanho, volumes e um selo `USB`). A lista é lida ao abrir o programa e sempre que você volta à janela; clique em **"Refresh USB drives list"** se o pendrive não aparecer. Enquanto o **Create** está desativado, uma dica abaixo dele diz o motivo.
5. Clique em **"Create Bootable USB Drive"**. O diálogo final mostra modelo, tamanho e volumes do pendrive. Para um **disco de alto risco** (maior que 256 GB, com muitos dados ou parecido com disco externo/de backup) você também precisa digitar o identificador (por exemplo `disk4`). Em seguida o pendrive é apagado, a imagem é gravada, verificada e o pendrive é ejetado. **Cancel** interrompe; o pendrive fica inutilizável até ser gravado de novo. Os resultados aparecem sob o botão, sem janelas pop-up: uma caixa verde quando o pendrive foi verificado e ejetado (com **Make another**) e uma vermelha com **Try again** para um download que falhou.

O que cada cartão faz:

- **Windows 11** — GPT + FAT32, os arquivos da ISO são copiados (o `install.wim` é dividido quando passa de 4 GB).
- **Linux** e **Other ISO** — a imagem é gravada byte a byte no pendrive (como o `dd`). Use *Linux* para Ubuntu, Debian, Fedora, Mint, Arch… e *Other ISO* para qualquer outra imagem de boot. Imagens sem assinatura de boot são recusadas antes de apagar qualquer coisa.
- **Google Chrome (ChromeOS Flex)** — imagem de disco do Google, também gravada byte a byte. O pendrive precisa ser do tamanho da imagem ou maior (o Google pede 16 GB ou mais).

Se o arquivo claramente não combina com o cartão (por exemplo uma ISO Linux em *Windows 11*), o programa pergunta antes de apagar qualquer coisa, e um arquivo que não é imagem do ChromeOS Flex em *Google Chrome* é recusado.

> Senha de administrador é necessária no Linux e, no macOS, nos cartões de gravação direta (*Google Chrome*, *Linux*, *Other ISO*). Ela é pedida e verificada logo após a confirmação, **antes** de mexer no pendrive (senha errada ou cancelada não altera nada). Uma barra de progresso mostra porcentagem, velocidade e tempo restante.
>
> **macOS e imagens Linux/ChromeOS:** o macOS não lê essas imagens. Por isso o pendrive pronto **não aparece no Finder** e o macOS pode dizer que o disco "não pôde ser lido". Clique em **Ignorar** — nunca em *Inicializar*. O conteúdo já foi verificado contra a imagem.

A interface é sempre em inglês americano. Existe uma tradução em português, que só é ativada explicitamente com `EPMA_LANG=pt`; o idioma do sistema nunca é usado.

### ChromeOS Flex

O [ChromeOS Flex](https://support.google.com/chromeosflex/answer/11541904) é a versão gratuita do ChromeOS do Google para PCs e Macs. O programa não oferece o ChromeOS comum porque o Google não o publica para computadores em geral.

1. Escolha o cartão **Google Chrome** e clique em **"Download ChromeOS Flex from Google"**; escolha onde salvar. O ZIP é extraído automaticamente (e o ZIP que o programa baixou é apagado). Já tem o `latest.bin.zip` ou o `.bin` de dentro dele? Use **"Select existing ISO file..."** — um ZIP é extraído para você.
2. Conecte um pendrive de **16 GB ou maior** (exigência do Google), selecione-o na lista (clique em **"Refresh USB drives list"** se ele não estiver lá) e clique em **"Create Bootable USB Drive"**.
3. Inicie o computador de destino pelo pendrive e siga o [guia do Google](https://support.google.com/chromeosflex/answer/11541904).

O Google lista estes requisitos para o computador: processador Intel ou AMD de 64 bits, 4 GB de RAM, 16 GB de armazenamento interno e boot por USB; só garante modelos certificados ([requisitos](https://support.google.com/chromeosflex/answer/11552529)). O Google também avisa que alguns pendrives podem não funcionar como instaladores. O ChromeOS Flex é fornecido pelo Google sob os termos do próprio Google.

### Reforço da instalação (opcional)

Arquivos opcionais para que uma instalação nova comece com configurações mais seguras. Eles são **inspirados em baselines de segurança comuns**; o programa **não** afirma que o resultado esteja em conformidade com, ou certificado por, qualquer padrão. Nada aqui escolhe disco, cria conta nem define senha ou chave: o Windows Setup e os instaladores Linux continuam interativos.

> **Experimental.** Os scripts foram verificados só com testes automatizados e sistemas simulados (nenhuma instalação real de Windows, Debian, Ubuntu ou Fedora foi executada). Teste primeiro em um computador reserva ou numa máquina virtual e leia os arquivos antes de usar: o `harden-files` grava tudo numa pasta, sem tocar em nenhum pendrive.

<p align="center">
  <img src="docs/images/interface-hardening.png" alt="O cartão Hardening seed: um segundo pendrive pequeno com configurações de instalação automática, o sistema de destino (Ubuntu, Fedora / RHEL, Debian) e o botão Create Seed Drive" width="620">
</p>

- **Windows 11 (no mesmo pendrive):** marque **"Add hardening settings to the Windows installation (optional)"** no cartão Windows 11. Um script roda no **fim** da instalação do Windows (log: `C:\Windows\Temp\epma-hardening.log`) e desliga SMBv1 e LLMNR e o AutoRun/AutoPlay, liga o firewall, aplica algumas proteções do Microsoft Defender (uma regra de redução de superfície em modo Block e quatro em modo Audit), desativa o recurso PowerShell 2.0 e o cache de credenciais WDigest, liga o log de blocos de script e uma política de auditoria avançada (o log de Segurança sobe para 128 MiB). **"What does it change?"** lista cada ajuste com o seu risco. BitLocker, níveis de NTLM, contas, discos, idioma e chave do produto não são alterados. Os arquivos são conferidos byte a byte junto com o resto do pendrive, e se a imagem já contiver algum deles o programa para **antes** de apagar qualquer coisa.
- **Linux e outros (um segundo pendrive):** ISOs gravadas direto não aceitam arquivos extras, então o cartão **Hardening seed** apaga um **segundo pendrive pequeno** (GPT + FAT32) e grava os arquivos nele. Mantenha o pendrive do instalador e conecte o do kit ao lado. **Ubuntu** (`autoinstall`, rótulo `CIDATA`; acrescente `autoinstall` na linha de boot, todas as telas continuam interativas), **Fedora / RHEL** (kickstart, rótulo `OEMDRV`, o instalador encontra sozinho) e **Debian** (o instalador **não** encontra o pendrive: monte-o depois de instalar e rode `sudo bash harden-linux.sh`, ou `su -` se não houver sudo).
- **Windows 11 (um segundo pendrive):** o mesmo cartão tem a opção **Windows 11 (run after install)**, que serve para um Windows 11 **já instalado** (não participa da instalação do Windows): abra o pendrive, dê dois cliques em `audit.cmd` (relatório só de leitura; linhas `[DIFF]` não estão em vigor), depois em `harden.cmd` (pede `y` e o aviso de administrador); `undo.cmd` desfaz (nunca religa o SMBv1 nem o PowerShell 2.0 e não restaura o que já estava assim antes). Os arquivos do pendrive não são autenticados: use só um pendrive de kit que você mesmo fez e mantenha-o com você. Extra opcional: `harden.ps1 -DisableLegacyNetwork` (NetBIOS sobre TCP/IP e WPAD desligados).
- **O script Linux** (`harden-linux.sh`) é texto puro, aceita `--dry-run`, `--yes`, `--undo` e `--help`, guarda cópia de cada arquivo que altera (`.epma-bak`), mostra cada mudança e grava em `/var/log/epma-hardening.log`. É idempotente e tenta não trancar você para fora: login de root ou por senha no SSH só é desligado quando existe uma conta de administrador com chave, e o firewall não é ligado num computador com Docker, libvirt ou LXD, a não ser que você use `--yes`.

```bash
python3 win11_usb_creator.py harden-files --target ubuntu --out ./ubuntu-seed          # só os arquivos, sem pendrive
python3 win11_usb_creator.py harden-seed --target fedora --disk disk4 --dry-run        # plano de um pendrive de kit
python3 win11_usb_creator.py harden-seed --target windows --disk disk4                 # kit do Windows 11
python3 win11_usb_creator.py harden-files --target windows-seed --out ./win-seed        # arquivos do kit Windows, sem pendrive
python3 win11_usb_creator.py write --iso Win11.iso --disk disk4 --hardened             # Windows + arquivos de reforço
```

### Linha de comando

O mesmo motor está disponível sem a janela (não precisa de Tkinter):

```bash
epma-usb-creator --help                 # Homebrew: epma-windows-usb-creator
python3 win11_usb_creator.py list                       # pendrives USB utilizáveis (--json disponível)
python3 win11_usb_creator.py detect ubuntu.iso          # windows | linux | chromeos | unknown
python3 win11_usb_creator.py sha256 ubuntu.iso --expected <hash>
python3 win11_usb_creator.py write --iso ubuntu.iso --disk disk4 --dry-run   # mostra o plano, não altera nada
python3 win11_usb_creator.py write --iso ubuntu.iso --disk disk4             # pede para digitar o id do disco
python3 win11_usb_creator.py fetch-chromeos --dest ~/Downloads               # ChromeOS Flex: baixar + extrair
python3 win11_usb_creator.py write --iso ~/Downloads/<imagem>.bin --disk disk4 --mode chromeos
```

Os comandos de reforço (`harden-files`, `harden-seed`, `write --hardened`) estão em [Reforço da instalação](#reforço-da-instalação-opcional).

O `write` sempre verifica o pendrive e exige que você digite o identificador do disco (ou `--yes` quando não há terminal). Não existe opção para pular a verificação. Sem argumentos, abre a janela.

| Código de saída | Significado |
|---|---|
| 0 | sucesso |
| 1 | erro genérico |
| 2 | uso incorreto ou falta de confirmação |
| 3 | verificação falhou / checksum diferente |
| 4 | gravado e verificado, mas o pendrive não pôde ser ejetado |
| 130 | interrompido (Ctrl-C) |

Dados vão para o stdout; mensagens, progresso e erros vão para o stderr. `NO_COLOR` é respeitado.

## Segurança

Esta aplicação **apaga completamente** o disco selecionado e executa comandos privilegiados. As proteções implementadas são:

### Como se evita apagar o disco errado

- Apenas discos **USB** são listados. No macOS o disco interno é filtrado duas vezes (`diskutil list external physical` + verificação da flag `Internal`) e o protocolo do barramento precisa ser `USB`; no Linux o disco que contém a raiz `/` é excluído e apenas dispositivos com transporte USB são exibidos (cartões SD e discos internos não aparecem).
- **Falha fechada:** se o programa não conseguir *confirmar* que um disco é externo, ele o esconde em vez de exibi-lo. No Linux, discos que contêm `/`, `/boot` (ou qualquer coisa sob ele), `/boot/efi`, `/home`, `/usr`, `/var` ou `/etc` nunca são listados, mesmo que o sistema os marque como removíveis — isso protege máquinas que inicializam por cartão SD ou USB, como um Raspberry Pi.
- **Você vê o que vai apagar:** a lista e o diálogo final mostram modelo, tamanho e volumes (com espaço usado). Discos grandes, com muitos dados ou parecidos com disco de backup exigem a digitação do identificador.
- **Reconferência antes de apagar:** imediatamente antes da gravação, o programa reconsulta a lista de discos e confirma que o identificador escolhido ainda aponta para o mesmo dispositivo, com o mesmo tamanho **e o mesmo serial/modelo**. Nomes como `/dev/sdb` são reciclados pelo sistema — se um pendrive for trocado nesse intervalo, a operação é abortada.
- Há sempre um diálogo de confirmação final antes de qualquer escrita.
- **Conferido antes de apagar:** ferramentas ausentes são detectadas de início (Create fica desativado com uma dica), uma ISO do Windows maior que o pendrive é recusada, e fechar a janela durante a gravação pede confirmação antes.
- **Nada é repetido às cegas:** um script privilegiado que falha nunca é executado uma segunda vez.
- **Verificado antes do eject:** uma diferença aborta sem ejetar e o pendrive é declarado inutilizável.
- **Os arquivos de reforço são dados, não decisões:** nunca escolhem nem apagam um disco, nunca criam conta e nunca trazem senha ou chave; o pendrive do kit é apagado como qualquer outro alvo e passa pelas mesmas conferências, e uma imagem que já traz os mesmos arquivos é recusada antes de qualquer coisa ser apagada.

> Mesmo assim: **confira duas vezes o disco selecionado antes de confirmar.**

### Tratamento da senha de administrador

A senha é usada apenas para executar comandos de disco locais via `sudo`. É conferida uma vez, só por **`stdin`** (nunca na linha de comando, onde outros usuários poderiam vê-la com `ps`), e então normalmente descartada da memória: a operação continua com o carimbo de credencial do próprio sudo, renovado durante a execução e invalidado (`sudo -k`) no fim. Se esta máquina não mantiver esse carimbo, a senha fica na memória **somente até o fim da operação** e é passada ao `sudo` por `stdin` a cada comando privilegiado. **Nunca é registrada em log, gravada em disco nem enviada para lugar nenhum.** Cada execução fica num registro de auditoria só do dono, incluindo o SHA-256 da ISO gravada.

### Integridade da imagem baixada

O programa aceita **apenas links HTTPS** e avisa se o servidor não for um endereço conhecido de download da Microsoft; um redirecionamento de um servidor confiável para um não confiável é recusado. Ao final do download, ele exibe o **checksum SHA-256** do arquivo. Se você informar o valor esperado, o arquivo será descartado caso não confira.

> **Baixe sempre pelo site oficial da Microsoft.** Nunca use um link de "espelho mais rápido" indicado em fórum ou vídeo — uma imagem adulterada instalaria um Windows comprometido sem que você percebesse.

### Documentação de segurança

O modelo de ameaças, os controles implementados e as variáveis de ambiente opcionais estão em [SECURITY.md](SECURITY.md).

Os relatórios completos da auditoria (SCA, SAST, STRIDE, OWASP Top 10 e DAST) estão em [output/](output/). Comece pelo [relatório consolidado](output/relatorio-consolidado-seguranca.md). *Observação: os relatórios da auditoria são escritos em português.*

## Desenvolvimento

### Rodando as verificações localmente

Antes de enviar uma alteração, rode as mesmas verificações que a esteira de CI roda:

```bash
python3 verificar.py
```

É seguro: nada toca em disco, formata ou exige privilégios de administrador. Os testes unitários rodam sozinhos com `python3 -m unittest discover -s tests -t .` (não precisa de Tkinter).

### Integração contínua

Cada alteração é verificada automaticamente pelo GitHub Actions (todas as actions são fixadas pelo SHA do commit):

| Workflow | Finalidade |
|---|---|
| [`ci.yml`](.github/workflows/ci.yml) | Lint, testes unitários (Python 3.10–3.15, Linux e macOS), ShellCheck dos scripts embutidos, testes de ponta a ponta em loop devices, sondas de distribuições Linux |
| [`security.yml`](.github/workflows/security.yml) | Guarda de regressão de segurança, Bandit, Semgrep, CodeQL, busca de segredos |
| [`release.yml`](.github/workflows/release.yml) | Publica releases com checksums SHA-256, procedência da build e SBOM; atualiza o tap do Homebrew |
| [`scorecard.yml`](.github/workflows/scorecard.yml) | Avaliação de cadeia de suprimentos do OpenSSF Scorecard |

A esteira de segurança tem duas camadas: um guarda de regressão sem dependências, que verifica que cada correção da auditoria continua no lugar, e analisadores externos como segunda opinião. Cada arquivo de workflow é amplamente comentado, explicando o que cada passo faz e por quê.

### Contribuindo

Dependências de terceiros são evitadas de propósito — isso elimina a superfície de ataque de cadeia de suprimentos mais comum do software moderno, e a CI faz cumprir essa regra. Se uma dependência se tornar realmente necessária, a verificação que falhar explica o processo a seguir.

## Solução de problemas

**"Tkinter is not available for this Python installation"**
Instale o Tkinter para a sua versão do Python (veja [Requisitos](#requisitos)).

**"wimlib-imagex not found"**
Instale o `wimlib` (macOS: `brew install wimlib`; Linux: veja a tabela acima) ou use o botão de instalar dependências.

**"Could not find sources/install.wim or sources/install.esd on the ISO"**
A imagem selecionada não é uma ISO de instalação do Windows. Baixe a ISO *multi-edition* oficial da Microsoft.

**"Only HTTPS links are accepted"**
O link de download precisa começar com `https://`. Um link sem criptografia pode ser alterado no caminho, o que permitiria trocar a imagem do Windows por uma adulterada.

**"Neither 'sudo' nor 'pkexec' was found"**
Instale o `sudo` ou execute a aplicação como root.

**"Aborted for safety: /dev/sdX is no longer listed as an external drive"**
O dispositivo mudou entre a seleção e a gravação. Clique em *Refresh USB drives list* e selecione o pendrive de novo — essa verificação existe justamente para impedir que o disco errado seja apagado.

**Nenhum disco aparece na lista**
Só aparecem discos ligados por **USB** (cartões SD, discos internos e o disco do sistema nunca aparecem). Confira se o pendrive está conectado e clique em *Refresh USB drives list* (a lista também é atualizada quando você volta à janela, mas não durante uma gravação). A dica sob o botão **Create** diz se a lista está vazia ou se nenhum pendrive foi selecionado.

**O pendrive não aparece no Finder depois de gravar uma ISO Linux (macOS)**
É esperado: o macOS não lê imagens Linux. Se ele disser que "o disco não pôde ser lido", clique em **Ignorar**, nunca em *Inicializar*. O conteúdo foi verificado contra a ISO antes de ejetar.

**"Verification FAILED"**
Os dados no pendrive diferem da ISO. O pendrive não foi ejetado e não deve ser usado. Grave de novo; se continuar falhando, tente outra porta USB ou outro pendrive.

**O pendrive não aparece no menu de boot**
Certifique-se de que a máquina está em modo **UEFI** (não Legacy/CSM). O pendrive gerado é UEFI + GPT e não inicializa em BIOS legado.

## Limitações

- Não funciona no Windows (o script sai com erro nessa plataforma).
- Gera apenas mídia **UEFI/GPT** — sem suporte a boot BIOS legado.
- Não faz bypass dos requisitos do Windows 11 (TPM 2.0 / Secure Boot).
- Um download cancelado ou interrompido mantém o arquivo parcial e retoma quando o servidor permite; uma falha de integridade o descarta.
- A formatação não sobrescreve o conteúdo anterior do pendrive. Se ele guardava dados sensíveis, apague-o antes com `shred` (Linux) ou "Apagar com segurança" no Utilitário de Disco (macOS).

## Licença

Copyright (C) 2026 EPMA

Este programa é software livre: você pode redistribuí-lo e/ou modificá-lo sob os termos da **GNU General Public License, versão 3**, conforme publicada pela Free Software Foundation, ou (a seu critério) qualquer versão posterior.

Este programa é distribuído na esperança de que seja útil, mas **SEM NENHUMA GARANTIA**; sem sequer a garantia implícita de COMERCIABILIDADE ou ADEQUAÇÃO A UM DETERMINADO FIM. Consulte a GNU General Public License para mais detalhes.

O texto completo da licença está em [LICENSE](LICENSE) e também disponível em <https://www.gnu.org/licenses/gpl-3.0.html>.

---

> **Aviso:** Windows e Windows 11 são marcas registradas da Microsoft Corporation. Google, Chrome, ChromeOS e ChromeOS Flex são marcas da Google LLC. Este projeto não é afiliado à Microsoft nem ao Google. A ISO é baixada exclusivamente dos servidores oficiais da Microsoft, e seu uso está sujeito aos termos de licenciamento da Microsoft.
