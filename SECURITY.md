# Política e notas de segurança

Este documento descreve o modelo de segurança do **EPMA Windows 11 Creator USB**, as
proteções implementadas e as variáveis de ambiente que ajustam o comportamento
de segurança do programa.

Auditoria completa: pasta [`output/`](output/).

---

## Modelo de ameaça, em uma frase

Este é um **aplicativo de desktop** que roda com os privilégios do usuário e,
em determinados momentos, **como administrador do sistema** para apagar e
formatar discos. Não há servidor, não há banco de dados, não há autenticação de
usuários. Os dois danos possíveis são:

1. **Destruição de dados** — apagar o disco errado.
2. **Execução de código como administrador** — um dado malicioso virar comando.

Todas as proteções abaixo existem para impedir esses dois cenários.

---

## Proteções implementadas

### 1. Valores nunca viram comando (prevenção de injeção)

Todos os comandos privilegiados recebem seus valores como **parâmetros
posicionais** do shell (`"$1"`, `"$2"`, ...), nunca colados no texto do script.
Um caminho de arquivo contendo `"`, `;` ou `$(...)` é tratado como texto, não
como instrução. Ver `PrivilegeHelper.run_script`.

Este é o equivalente, neste projeto, das *prepared statements* que protegem
bancos de dados contra SQL Injection: **o dado viaja por um canal separado do
comando**.

### 2. Validação estrita de entradas

| Entrada | Regra |
|---|---|
| Identificador de disco | `^disk[0-9]+$` (macOS) / `^[a-zA-Z0-9_+-]{1,32}$` (Linux). Fora disso, recusa. |
| Caminho da ISO | Precisa existir, ser arquivo regular, legível e ter no mínimo 1 MB. |
| Endereço de download | Somente `https://`. Host fora da lista da Microsoft gera aviso explícito. |
| Checksum SHA-256 | Exatamente 64 caracteres hexadecimais. |
| Nomes de pacote a instalar | Somente os da lista fixa `LINUX_REQUIRED_TOOLS`. |

A abordagem é **recusar em vez de escapar**: não existe nome de disco legítimo
com espaço ou aspas.

### 3. Falha fechada (*fail closed*)

Quando o programa **não consegue confirmar** que um disco é externo e seguro,
ele **esconde o disco** em vez de exibi-lo. Antes, uma falha na verificação
resultava em o disco ser oferecido assim mesmo.

Inclui uma proteção específica para máquinas que inicializam por dispositivo
removível (por exemplo, um Raspberry Pi que inicializa pelo cartão SD): qualquer
disco que contenha `/`, `/boot`, `/home`, `/usr`, `/var` ou `/etc` é ocultado,
mesmo que o sistema o marque como removível.

### 4. Reconferência antes de destruir

Imediatamente antes de apagar o disco, o programa **reconsulta a lista de
discos** e confere que o identificador escolhido ainda corresponde ao mesmo
dispositivo, com o mesmo tamanho. Nomes como `/dev/sdb` são reciclados pelo
sistema operacional: se um pendrive for trocado entre a seleção e a gravação,
o nome pode apontar para outro disco. A operação é abortada nesse caso.

### 5. Verificação de integridade da imagem baixada

O SHA-256 (a "impressão digital" do arquivo) é calculado durante o download e
exibido ao final. Se um valor esperado for informado, o arquivo é **descartado**
quando não confere. Downloads incompletos também são descartados.

### 6. Cuidado com a senha de administrador

- Enviada apenas por `stdin`, **nunca** na linha de comando (que é visível para
  outros usuários da máquina através do comando `ps`).
- Nunca escrita em nenhum log, nem no registro de auditoria.
- Removida da memória assim que a operação termina
  (`PrivilegeHelper.clear_cached_password`).

### 7. Registro de auditoria

Operações destrutivas e eventos de segurança são registrados em arquivo com
permissão `0600` (somente o dono lê). O registro **nunca** contém senhas.

Local padrão: `~/.local/state/epma-win11-usb-creator/audit.log`

### 8. Erros que não vazam informação

Falhas inesperadas mostram uma mensagem curta na tela; o detalhe técnico
(caminhos internos, linhas de comando) vai para o log local e para o registro
de auditoria, não para a caixa de diálogo.

---

## Variáveis de ambiente

**Nenhuma é obrigatória.** O programa funciona sem configurar nada. Não existem
segredos, senhas ou chaves de API neste projeto.

| Variável | Obrigatória? | Para que serve |
|---|---|---|
| `WIN11USB_AUDIT_LOG` | Opcional | Caminho alternativo para o registro de auditoria. |
| `WIN11USB_DISABLE_AUDIT_LOG` | Opcional | `1` desliga o registro de auditoria. |
| `WIN11USB_TRUSTED_ISO_HOSTS` | Opcional | Lista de servidores confiáveis, separados por vírgula, substituindo a lista padrão da Microsoft. |
| `WIN11USB_ALLOW_ANY_DOWNLOAD_HOST` | Opcional | `1` desliga o aviso de servidor não reconhecido. **Reduz a segurança.** |
| `WIN11USB_EXPECTED_SHA256` | Opcional | Preenche automaticamente o campo de checksum esperado. |

Como definir (exemplo em macOS/Linux, no terminal):

```bash
export WIN11USB_AUDIT_LOG="$HOME/meus-logs/usb-creator.log"
python3 win11_usb_creator.py
```

Para tornar permanente, acrescente a linha `export ...` ao seu `~/.zshrc`
(macOS) ou `~/.bashrc` (Linux).

---

## Responsabilidades do usuário

Duas coisas o código **não** consegue garantir sozinho:

1. **Manter o sistema operacional atualizado.** O programa depende de `parted`,
   `rsync`, `wimlib` e outros utilitários do sistema. Correções de segurança
   deles chegam pela atualização do sistema (`sudo apt upgrade`, `brew upgrade`).

2. **Conferir a autenticidade da imagem do Windows.** O programa avisa e calcula
   a impressão digital, mas só o usuário pode compará-la com o valor publicado
   pela Microsoft. **Baixe sempre do site oficial.**

---

## Reportando uma vulnerabilidade

Abra uma issue em
<https://github.com/1985epma/epma-windows-usb-creator/issues>.
Para falhas sensíveis, evite publicar detalhes de exploração antes da correção.
