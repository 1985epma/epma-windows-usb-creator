# EPMA Windows 11 Creator USB

[English](README.md) · **Português**

> A versão oficial deste documento é o [README.md em inglês](README.md). Esta
> tradução é mantida por conveniência e pode ficar desatualizada em relação a ela.

Aplicação multiplataforma (**macOS** e **qualquer distribuição Linux**) para baixar a ISO oficial do Windows 11 e gravar um pendrive bootável no padrão **UEFI (GPT + FAT32)**. Também grava **qualquer ISO híbrida** (Ubuntu, Debian, Fedora, Mint, Arch…) direto no pendrive, e toda gravação é **relida e verificada** antes de o pendrive ser ejetado.

Tem interface gráfica (em português e inglês) e um [modo linha de comando](#linha-de-comando).

Escrita em Python puro com Tkinter — sem dependências de bibliotecas Python externas.

![Licença](https://img.shields.io/badge/licen%C3%A7a-GPLv3-blue)
![Plataformas](https://img.shields.io/badge/plataformas-macOS%20%7C%20Linux-lightgrey)
![Python](https://img.shields.io/badge/python-3.10%2B-green)

---

## Índice

- [Recursos](#recursos)
- [Como funciona](#como-funciona)
- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Uso](#uso)
- [Segurança](#segurança)
- [Solução de problemas](#solução-de-problemas)
- [Limitações](#limitações)
- [Licença](#licença)

---

## Recursos

- **Download da ISO** direto pela aplicação, com barra de progresso, velocidade, tempo restante e botão de cancelar.
- **Uso de ISO já existente**, caso você já tenha baixado o arquivo pelo navegador.
- **Formatação automática** do pendrive como GPT + FAT32 com rótulo `WIN11USB` (compatível com boot UEFI, sem precisar desativar o Secure Boot).
- **Divisão automática do `install.wim` / `install.esd`**: esses arquivos costumam passar de 4 GB, o limite do FAT32. A aplicação detecta o caso e divide o arquivo em `.swm` usando `wimlib-imagex`.
- **Instalação automática de dependências**: detecta o gerenciador de pacotes (`apt-get`, `dnf`, `yum`, `pacman`, `zypper`, `apk`) ou o Homebrew no macOS e instala o que estiver faltando.
- **Dois tipos de imagem**: *Windows 11* (GPT + FAT32, arquivos copiados) ou *Linux / outra ISO híbrida* (gravada byte a byte, como o `dd`). O tipo é detectado pelo **conteúdo** da ISO, não pelo nome do arquivo, e você sempre pode trocá-lo.
- **Gravação verificada**: depois de gravar, o pendrive é relido e comparado com a ISO (byte a byte nas imagens Linux; checksum e `wimlib-imagex verify` no Windows). Se algo for diferente, o pendrive **não** é ejetado e você é avisado para não usá-lo.
- **Eject confiável** depois da verificação, com mensagem clara se o sistema recusar.
- **Barra de progresso** com porcentagem, velocidade e tempo restante na gravação e na verificação; botão **Cancelar** para a operação inteira.
- **Proteção contra apagar o disco errado**: só discos USB são listados, com modelo e volumes; o disco do sistema nunca aparece; discos de risco (grandes, com dados ou parecidos com disco de backup) exigem que você **digite o identificador**; e há sempre uma confirmação final.
- **Conferência SHA-256 de uma ISO que você já tem** (cole o valor esperado ou uma linha de `SHA256SUMS`).
- **Download com retomada** e novas tentativas automáticas.
- **Modo linha de comando** (`list`, `write`, `detect`, `sha256`, `--dry-run`, saída JSON, códigos de saída) para scripts.
- **Log em tempo real** de todos os comandos executados, dentro da própria janela.

## Como funciona

1. A ISO é montada em modo somente leitura (`hdiutil` no macOS, `mount -o loop,ro` no Linux).
2. O pendrive é apagado e reparticionado como GPT com uma partição FAT32 marcada como ESP.
3. Todos os arquivos da ISO são copiados com `rsync`, **exceto** o `install.wim`/`install.esd`.
4. Esse arquivo grande é copiado à parte: se couber no FAT32, é copiado direto; se passar de 4 GB, é dividido em partes de ~3,8 GB com `wimlib-imagex split`.
5. As escritas são sincronizadas em disco, o pendrive é remontado e **relido para verificar** que cada arquivo confere com a ISO (no modo Linux a ISO é gravada direto e todo o conteúdo do pendrive é comparado com ela).
6. Só então o pendrive é desmontado e ejetado com segurança.

## Requisitos

### macOS

```bash
brew install python-tk@3.14 wimlib
```

> Ajuste `python-tk@<versão>` para a versão do Python que você usa. No macOS não é necessário `sudo`: as operações de disco em unidades externas são feitas via `diskutil` e `hdiutil`.

### Linux

Os nomes dos pacotes variam por distribuição. Ferramentas necessárias:

| Ferramenta | Pacote (Debian/Ubuntu) | Fedora/RHEL | Arch | openSUSE |
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

Você também pode simplesmente abrir a aplicação e usar o botão **"Install missing dependencies"** na aba 2 — ela monta e executa o comando certo para o seu gerenciador de pacotes.

No Linux, particionar/formatar/montar um dispositivo de bloco exige privilégios de root, então a aplicação pede sua senha de administrador (via `sudo`, ou `pkexec` se `sudo` não existir).

## Instalação

```bash
git clone https://github.com/1985epma/epma-windows-usb-creator.git
cd epma-windows-usb-creator
chmod +x win11_usb_creator.py
```

## Uso

```bash
python3 win11_usb_creator.py
```

### Aba 1 — Baixar a ISO

A Microsoft só libera o link direto da ISO depois que você escolhe a edição e o idioma no site oficial. Por isso:

1. Clique em **"Open Microsoft's official page"**.
2. Em *Download Windows 11 Disk Image (ISO)*, escolha **Windows 11 (multi-edition ISO)** e clique em Download.
3. Escolha o idioma e confirme.
4. **Clique com o botão direito** no botão azul de download de 64 bits e escolha **"Copiar endereço do link"** (não clique para baixar pelo navegador).
5. Cole o link no campo e clique em **"Download ISO"**.

Se você já baixou a ISO manualmente, use **"Select existing ISO file..."** e pule para a aba 2.

### Aba 2 — Criar o pendrive

1. Confira o status das dependências no topo (instale as que faltarem, se necessário).
2. Conecte o pendrive (mínimo **8 GB**) e clique em **"Refresh USB drives list"**.
3. Selecione o pendrive na lista.
4. Escolha o **tipo de imagem** (é sugerido pelo nome do arquivo ISO):
   - **Windows 11** — GPT + FAT32, arquivos da ISO copiados (`install.wim` dividido quando passa de 4 GB).
   - **Linux / outra ISO híbrida** — a ISO é gravada byte a byte no pendrive (como o `dd`). Use para Ubuntu, Debian, Fedora, Mint, Arch etc. Selecione a ISO em *Select existing ISO file...* na aba 1. ISOs sem assinatura de boot são recusadas antes de apagar qualquer coisa.
5. Clique em **"Create Bootable USB Drive"**. O diálogo final mostra modelo, tamanho e volumes do pendrive. Para um **disco de alto risco** (maior que 256 GB, com muitos dados ou parecido com disco externo/de backup) você também precisa digitar o identificador (por exemplo `disk4`). Em seguida o pendrive é apagado, a imagem é gravada, verificada e o pendrive é ejetado.
6. Use **Cancel** para interromper uma operação em andamento. O pendrive fica inutilizável até ser gravado de novo.

> Senha de administrador é necessária no Linux e, no macOS, no modo Linux (gravação direta). Ela é pedida e verificada logo após a confirmação, **antes** de mexer no pendrive (senha errada ou cancelada não altera nada). Uma barra de progresso mostra porcentagem, velocidade e tempo restante.
>
> **macOS e imagens Linux:** o macOS não lê imagens Linux (ISO 9660/ext). Por isso o pendrive pronto **não aparece no Finder** e o macOS pode dizer que o disco "não pôde ser lido". Clique em **Ignorar** — nunca em *Inicializar*. O conteúdo já foi verificado contra a ISO.

A interface segue o idioma do sistema (português se `LANG` começar com `pt`). Para forçar: `EPMA_LANG=pt` ou `EPMA_LANG=en`.

O processo leva vários minutos, dependendo da velocidade do pendrive. Acompanhe pelo log na parte inferior da janela.

### Linha de comando

O mesmo motor está disponível sem a janela (não precisa de Tkinter):

```bash
epma-usb-creator --help                 # Homebrew: epma-windows-usb-creator
python3 win11_usb_creator.py list                       # pendrives USB utilizáveis (--json disponível)
python3 win11_usb_creator.py detect ubuntu.iso          # windows | linux | unknown
python3 win11_usb_creator.py sha256 ubuntu.iso --expected <hash>
python3 win11_usb_creator.py write --iso ubuntu.iso --disk disk4 --dry-run   # mostra o plano, não altera nada
python3 win11_usb_creator.py write --iso ubuntu.iso --disk disk4             # pede para digitar o id do disco
```

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

Esta aplicação **apaga completamente** o disco selecionado. As proteções implementadas são:

- Apenas discos **USB** são listados. No macOS o disco interno é filtrado duas vezes (`diskutil list external physical` + verificação da flag `Internal`) e o protocolo do barramento precisa ser `USB`; no Linux o disco que contém a raiz `/` é excluído e apenas dispositivos com transporte USB são exibidos (cartões SD e discos internos não aparecem).
- **Você vê o que vai apagar:** a lista e o diálogo final mostram modelo, tamanho e volumes (com espaço usado). Discos grandes, com muitos dados ou parecidos com disco de backup exigem a digitação do identificador.
- Há sempre um diálogo de confirmação final antes de qualquer escrita.
- **Nada é repetido às cegas:** um script privilegiado que falha nunca é executado uma segunda vez.
- **Verificado antes do eject:** uma diferença aborta sem ejetar e o pendrive é declarado inutilizável.
- **Reconferência antes de apagar:** imediatamente antes da gravação, o programa reconsulta a lista de discos e confirma que o identificador escolhido ainda aponta para o mesmo dispositivo, com o mesmo tamanho **e o mesmo serial/modelo**. Nomes como `/dev/sdb` são reciclados pelo sistema — se um pendrive for trocado nesse intervalo, a operação é abortada.
- **Falha fechada:** se o programa não conseguir *confirmar* que um disco é externo, ele o esconde em vez de exibi-lo. Discos que contêm `/`, `/boot`, `/home`, `/usr`, `/var` ou `/etc` nunca são listados, mesmo que o sistema os marque como removíveis (protege máquinas que inicializam por cartão SD ou USB, como um Raspberry Pi).

Sobre a senha de administrador: ela é usada apenas para executar comandos de disco locais via `sudo`. É conferida uma vez, só por `stdin` (nunca na linha de comando, onde outros usuários poderiam vê-la com `ps`), e então descartada da memória: a operação continua com o carimbo de credencial do próprio sudo, renovado durante a execução e invalidado (`sudo -k`) no fim. Se o sistema não mantiver esse carimbo, o programa pergunta de novo em vez de guardar a senha. **Nunca é gravada em disco nem enviada para lugar nenhum.** Cada execução fica num registro de auditoria só do dono, incluindo o SHA-256 da ISO gravada.

Mesmo assim: **confira duas vezes o disco selecionado antes de confirmar.**

### Integridade da imagem baixada

O programa aceita **apenas links HTTPS** e avisa se o servidor não for um endereço conhecido da Microsoft. Ao final do download, ele exibe a **impressão digital SHA-256** do arquivo. Se você informar o valor esperado no campo opcional, o arquivo será descartado caso não confira.

> **Baixe sempre pelo site oficial da Microsoft.** Nunca use um link de "espelho mais rápido" indicado em fórum ou vídeo — uma imagem adulterada instalaria um Windows comprometido sem que você percebesse.

### Documentação de segurança

O modelo de ameaças, os controles implementados e as variáveis de ambiente opcionais estão em [SECURITY.md](SECURITY.md). Os relatórios completos da auditoria (SCA, SAST, STRIDE, OWASP Top 10 e DAST) estão em [output/](output/).

## Solução de problemas

**"Tkinter is not available for this Python installation"**
Instale o Tkinter para a sua versão do Python (veja [Requisitos](#requisitos)).

**"wimlib-imagex not found"**
Instale o `wimlib` (macOS: `brew install wimlib`; Linux: veja a tabela acima) ou use o botão de instalar dependências.

**"Could not find sources/install.wim or sources/install.esd on the ISO"**
A imagem selecionada não é uma ISO de instalação do Windows. Baixe a ISO *multi-edition* oficial da Microsoft.

**"Neither 'sudo' nor 'pkexec' was found"**
Instale o `sudo` ou execute a aplicação como root.

**Nenhum disco aparece na lista**
Só aparecem discos ligados por **USB** (cartões SD, discos internos e o disco do sistema nunca aparecem). Confira se o pendrive está conectado e clique em *Refresh*.

**O pendrive não aparece no Finder depois de gravar uma ISO Linux (macOS)**
É esperado: o macOS não lê imagens Linux. Se ele disser que "o disco não pôde ser lido", clique em **Ignorar**, nunca em *Inicializar*. O conteúdo foi verificado contra a ISO antes de ejetar.

**"Verification FAILED"**
Os dados no pendrive diferem da ISO. O pendrive não foi ejetado e não deve ser usado. Grave de novo; se continuar falhando, tente outra porta USB ou outro pendrive.

**O pendrive não aparece no boot**
Certifique-se de que a máquina está em modo **UEFI** (não Legacy/CSM). O pendrive gerado é UEFI + GPT e não inicializa em BIOS legado.

## Limitações

- Não funciona no Windows (o script sai com erro nessa plataforma).
- Gera apenas mídia **UEFI/GPT** — sem suporte a boot BIOS legado.
- Não faz bypass dos requisitos do Windows 11 (TPM 2.0 / Secure Boot).
- Um download cancelado ou interrompido mantém o arquivo parcial e retoma quando o servidor permite; uma falha de integridade o descarta.

## Licença

Copyright (C) 2026 EPMA

Este programa é software livre: você pode redistribuí-lo e/ou modificá-lo sob os termos da **GNU General Public License, versão 3**, conforme publicada pela Free Software Foundation, ou (a seu critério) qualquer versão posterior.

Este programa é distribuído na esperança de que seja útil, mas **SEM NENHUMA GARANTIA**; sem sequer a garantia implícita de COMERCIABILIDADE ou ADEQUAÇÃO A UM DETERMINADO FIM. Consulte a GNU General Public License para mais detalhes.

O texto completo da licença está em [LICENSE](LICENSE) e também disponível em <https://www.gnu.org/licenses/gpl-3.0.html>.

---

> **Aviso:** Windows e Windows 11 são marcas registradas da Microsoft Corporation. Este projeto não é afiliado à Microsoft. A ISO é baixada exclusivamente dos servidores oficiais da Microsoft, e seu uso está sujeito aos termos de licenciamento da Microsoft.
