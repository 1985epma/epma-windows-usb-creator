# EPMA Windows 11 Creator USB

[English](README.md) · **Português**

> A versão oficial deste documento é o [README.md em inglês](README.md). Esta
> tradução é mantida por conveniência e pode ficar desatualizada em relação a ela.

Aplicação gráfica multiplataforma (**macOS** e **qualquer distribuição Linux**) para baixar a ISO oficial do Windows 11 e gravar um pendrive bootável no padrão **UEFI (GPT + FAT32)**.

Escrita em Python puro com Tkinter — sem dependências de bibliotecas Python externas.

![Licença](https://img.shields.io/badge/licen%C3%A7a-GPLv3-blue)
![Plataformas](https://img.shields.io/badge/plataformas-macOS%20%7C%20Linux-lightgrey)
![Python](https://img.shields.io/badge/python-3.9%2B-green)

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
- **Proteção contra apagar o disco errado**: apenas discos externos/removíveis são listados, o disco de sistema nunca aparece, e são exigidas três confirmações antes de gravar.
- **Log em tempo real** de todos os comandos executados, dentro da própria janela.

## Como funciona

1. A ISO é montada em modo somente leitura (`hdiutil` no macOS, `mount -o loop,ro` no Linux).
2. O pendrive é apagado e reparticionado como GPT com uma partição FAT32 marcada como ESP.
3. Todos os arquivos da ISO são copiados com `rsync`, **exceto** o `install.wim`/`install.esd`.
4. Esse arquivo grande é copiado à parte: se couber no FAT32, é copiado direto; se passar de 4 GB, é dividido em partes de ~3,8 GB com `wimlib-imagex split`.
5. As escritas são sincronizadas em disco e o pendrive é desmontado/ejetado com segurança.

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
5. Clique em **"Create Bootable USB Drive"** e confirme (**Sim**) no diálogo final. O pendrive é então apagado e a imagem é gravada nele.

> O modo Linux exige senha de administrador nos dois sistemas. A senha é pedida e verificada logo após a confirmação, **antes** de mexer no pendrive (senha errada ou cancelada não altera nada). Uma barra de progresso mostra porcentagem, velocidade e tempo restante nos dois modos.

O processo leva vários minutos, dependendo da velocidade do pendrive. Acompanhe pelo log na parte inferior da janela.

## Segurança

Esta aplicação **apaga completamente** o disco selecionado. As proteções implementadas são:

- Apenas discos **USB** são listados. No macOS o disco interno é filtrado duas vezes (`diskutil list external physical` + verificação da flag `Internal`) e o protocolo do barramento precisa ser `USB`; no Linux o disco que contém a raiz `/` é excluído e apenas dispositivos com transporte USB são exibidos (cartões SD e discos internos não aparecem).
- Ainda há um diálogo de confirmação final antes de qualquer escrita.
- **Reconferência antes de apagar:** imediatamente antes da gravação, o programa reconsulta a lista de discos e confirma que o identificador escolhido ainda aponta para o mesmo dispositivo, com o mesmo tamanho. Nomes como `/dev/sdb` são reciclados pelo sistema — se um pendrive for trocado nesse intervalo, a operação é abortada.
- **Falha fechada:** se o programa não conseguir *confirmar* que um disco é externo, ele o esconde em vez de exibi-lo. Discos que contêm `/`, `/boot`, `/home`, `/usr`, `/var` ou `/etc` nunca são listados, mesmo que o sistema os marque como removíveis (protege máquinas que inicializam por cartão SD ou USB, como um Raspberry Pi).

Sobre a senha de administrador (Linux): ela é usada apenas para executar comandos de disco locais via `sudo -S`, é enviada exclusivamente por `stdin` (nunca na linha de comando, onde outros usuários poderiam vê-la com `ps`), **nunca é gravada em disco nem enviada para lugar nenhum**, e é removida da memória assim que a operação termina.

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
Confira se o pendrive está conectado e clique em *Refresh*. No Linux, alguns adaptadores USB-SATA aparecem como não removíveis e são propositalmente ocultados por segurança.

**O pendrive não aparece no boot**
Certifique-se de que a máquina está em modo **UEFI** (não Legacy/CSM). O pendrive gerado é UEFI + GPT e não inicializa em BIOS legado.

## Limitações

- Não funciona no Windows (o script sai com erro nessa plataforma).
- Gera apenas mídia **UEFI/GPT** — sem suporte a boot BIOS legado.
- Não faz bypass dos requisitos do Windows 11 (TPM 2.0 / Secure Boot).
- O download não suporta retomada: cancelar descarta o arquivo parcial.

## Licença

Copyright (C) 2026 EPMA

Este programa é software livre: você pode redistribuí-lo e/ou modificá-lo sob os termos da **GNU General Public License, versão 3**, conforme publicada pela Free Software Foundation, ou (a seu critério) qualquer versão posterior.

Este programa é distribuído na esperança de que seja útil, mas **SEM NENHUMA GARANTIA**; sem sequer a garantia implícita de COMERCIABILIDADE ou ADEQUAÇÃO A UM DETERMINADO FIM. Consulte a GNU General Public License para mais detalhes.

O texto completo da licença está em [LICENSE](LICENSE) e também disponível em <https://www.gnu.org/licenses/gpl-3.0.html>.

---

> **Aviso:** Windows e Windows 11 são marcas registradas da Microsoft Corporation. Este projeto não é afiliado à Microsoft. A ISO é baixada exclusivamente dos servidores oficiais da Microsoft, e seu uso está sujeito aos termos de licenciamento da Microsoft.
