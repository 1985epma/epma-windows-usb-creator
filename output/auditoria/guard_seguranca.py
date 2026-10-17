#!/usr/bin/env python3
"""
Guarda de regressão de segurança — EPMA Windows 11 Creator USB.

O QUE ESTE ARQUIVO FAZ, EM LINGUAGEM SIMPLES
--------------------------------------------
A auditoria de segurança corrigiu 17 problemas. Nada impede que uma alteração
futura desfaça uma dessas correções sem querer — e ninguém perceberia.

Este programa é o "cão de guarda": ele confere que as correções continuam no
lugar. Se alguma tiver sido desfeita, ele falha e a esteira de CI barra a
alteração antes que ela entre no projeto.

POR QUE ELE NÃO USA NENHUMA FERRAMENTA EXTERNA
----------------------------------------------
Ele lê o código usando o módulo `ast` da biblioteca padrão do Python, que
entende a ESTRUTURA do programa — não é busca de texto. Isso o torna preciso
(não se engana com um comentário) e independente de qualquer ferramenta de
terceiros, coerente com a política de zero dependências do projeto.

USO
---
    python3 output/auditoria/guard_seguranca.py

Código de saída 0 = tudo certo. 1 = alguma proteção foi desfeita.
"""

import ast
import os
import re
import sys

RAIZ = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
# Aceita um caminho alternativo como argumento — usado pelo autoteste que
# comprova que este guarda realmente detecta regressões.
ALVO = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(RAIZ, "win11_usb_creator.py")

falhas = []
avisos = []
verificacoes = 0


def falha(regra, mensagem, linha=None):
    local = f" (linha {linha})" if linha else ""
    falhas.append(f"[{regra}]{local} {mensagem}")


def ok(regra, descricao):
    global verificacoes
    verificacoes += 1
    print(f"  [OK]    {regra}: {descricao}")


def erro(regra, descricao, mensagem, linha=None):
    global verificacoes
    verificacoes += 1
    print(f"  [FALHA] {regra}: {descricao}")
    falha(regra, mensagem, linha)


with open(ALVO, encoding="utf-8") as fh:
    FONTE = fh.read()

ARVORE = ast.parse(FONTE, filename=ALVO)


def constantes_modulo():
    """Nomes atribuídos no nível do módulo (constantes MAIÚSCULAS)."""
    nomes = set()
    for no in ARVORE.body:
        if isinstance(no, ast.Assign):
            for alvo in no.targets:
                if isinstance(alvo, ast.Name) and alvo.id.isupper():
                    nomes.add(alvo.id)
    return nomes


CONSTANTES = constantes_modulo()


# ============================================================
# G01 — Nenhum valor variável pode ser colado dentro de um script de shell
#
# Esta é A correção mais importante da auditoria (achado SAST-01, gravidade
# Alta). Valores devem chegar ao shell como parâmetros ("$1", "$2"), nunca
# grudados no texto do comando.
#
# Exceção permitida: constantes do módulo em MAIÚSCULAS (ex.: {VOL_NAME}), que
# são fixas no código e não podem ser influenciadas por um atacante.
# ============================================================
print("\n=== G01 — Interpolação em scripts de shell (SAST-01, Alta) ===")


def interpolacoes_inseguras(no):
    """Retorna as interpolações de f-string que NÃO são constantes do módulo."""
    problemas = []
    for filho in ast.walk(no):
        if isinstance(filho, ast.JoinedStr):
            for parte in filho.values:
                if not isinstance(parte, ast.FormattedValue):
                    continue
                expr = parte.value
                if isinstance(expr, ast.Name) and expr.id in CONSTANTES:
                    continue  # constante do módulo: seguro
                problemas.append((ast.unparse(expr), getattr(filho, "lineno", None)))
    return problemas


encontrou_script = False
problemas_g01 = []
for no in ast.walk(ARVORE):
    if not isinstance(no, ast.Assign):
        continue
    nomes = [t.id for t in no.targets if isinstance(t, ast.Name)]
    if not any("script" in n.lower() for n in nomes):
        continue
    encontrou_script = True
    for expr, linha in interpolacoes_inseguras(no.value):
        problemas_g01.append((nomes[0], expr, linha))

if not encontrou_script:
    erro("G01", "scripts de shell localizados",
         "Nenhuma variável *script* encontrada. O código foi reestruturado? "
         "Revise esta regra manualmente.")
elif problemas_g01:
    for var, expr, linha in problemas_g01:
        erro("G01", f"interpolação insegura em '{var}'",
             f"O valor '{expr}' está sendo colado dentro do texto de um script de "
             "shell executado como administrador. Isso reabre a falha de injeção de "
             "comando (SAST-01). Passe o valor como parâmetro posicional via "
             "run_script(..., args=[...]) e use \"$1\", \"$2\" no script.", linha)
else:
    ok("G01", "nenhum valor variável é colado em script de shell")

# G01b — run_script nunca pode receber uma f-string com valor variável
problemas_g01b = []
for no in ast.walk(ARVORE):
    if not isinstance(no, ast.Call):
        continue
    nome = getattr(no.func, "attr", None)
    if nome != "run_script" or not no.args:
        continue
    for expr, linha in interpolacoes_inseguras(no.args[0]):
        problemas_g01b.append((expr, linha or no.lineno))

if problemas_g01b:
    for expr, linha in problemas_g01b:
        erro("G01b", "run_script recebeu texto interpolado",
             f"'{expr}' foi interpolado no script passado a run_script(). "
             "Use o parâmetro args=[...].", linha)
else:
    ok("G01b", "run_script nunca recebe texto interpolado com variável")


# ============================================================
# G02 — Execução perigosa: shell=True, os.system, eval, exec
# ============================================================
print("\n=== G02 — Chamadas de execução perigosas ===")

perigosas = []
for no in ast.walk(ARVORE):
    if not isinstance(no, ast.Call):
        continue
    # shell=True em qualquer chamada do subprocess
    for kw in no.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            perigosas.append(("shell=True", no.lineno))
    alvo = ast.unparse(no.func)
    if alvo in ("os.system", "os.popen", "eval", "exec", "subprocess.getoutput"):
        perigosas.append((alvo, no.lineno))

if perigosas:
    for nome, linha in perigosas:
        erro("G02", f"uso de {nome}",
             f"'{nome}' entrega texto direto ao interpretador de comandos e "
             "reintroduz risco de injeção. Use subprocess com lista de argumentos.", linha)
else:
    ok("G02", "sem shell=True, os.system, eval ou exec")


# ============================================================
# G03 — A senha de administrador nunca pode ir na linha de comando
#
# Argumentos de processo são visíveis a outros usuários da máquina pelo comando
# `ps`. A senha deve ir apenas por stdin (achado STRIDE B-I1).
# ============================================================
print("\n=== G03 — Senha fora da linha de comando (STRIDE B-I1, Alta) ===")

vazamento_argv = []
for no in ast.walk(ARVORE):
    if not isinstance(no, ast.Call):
        continue
    if ast.unparse(no.func) not in ("subprocess.Popen", "subprocess.run", "subprocess.check_output"):
        continue
    if not no.args:
        continue
    texto_args = ast.unparse(no.args[0])
    if re.search(r"\bpassword\b|\bsenha\b|\bpasswd\b", texto_args):
        vazamento_argv.append((texto_args[:70], no.lineno))

if vazamento_argv:
    for trecho, linha in vazamento_argv:
        erro("G03", "senha na lista de argumentos",
             f"A senha aparece nos argumentos do processo ({trecho}...). "
             "Outros usuários da máquina conseguiriam vê-la com `ps`. "
             "Envie a senha apenas por stdin.", linha)
else:
    ok("G03", "senha nunca aparece na lista de argumentos de processo")

if "proc.stdin.write(password" in FONTE:
    ok("G03b", "senha é enviada por stdin (forma correta)")
else:
    erro("G03b", "envio da senha por stdin",
         "O envio da senha por stdin não foi encontrado. Se o mecanismo mudou, "
         "revise esta regra e o relatório STRIDE (B-I1).")


# ============================================================
# G04 — Validação de entrada continua estrita
# ============================================================
print("\n=== G04 — Validação estrita de entradas (SAST-01/08) ===")

for nome_re, descricao in [("MAC_DEVICE_RE", "identificador de disco no macOS"),
                           ("LINUX_DEVICE_RE", "identificador de disco no Linux")]:
    m = re.search(rf"^{nome_re}\s*=\s*re\.compile\(r?['\"](.+?)['\"]\)", FONTE, re.M)
    if not m:
        erro("G04", f"{nome_re} presente",
             f"A expressão de validação do {descricao} sumiu. Sem ela, um nome "
             "de disco malicioso volta a alcançar comandos privilegiados.")
    elif not (m.group(1).startswith("^") and m.group(1).endswith("$")):
        erro("G04", f"{nome_re} ancorada",
             f"A expressão de {nome_re} precisa começar com ^ e terminar com $. "
             "Sem âncoras, ela aceita lixo antes ou depois do trecho válido.")
    else:
        ok("G04", f"{nome_re} presente e ancorada ({descricao})")

for funcao in ("validate_device_name", "validate_iso_path", "validate_download_url"):
    if re.search(rf"^def {funcao}\(", FONTE, re.M):
        ok("G04", f"função {funcao}() presente")
    else:
        erro("G04", f"função {funcao}()",
             f"A função de validação {funcao}() foi removida.")


# ============================================================
# G05 — Somente HTTPS para download (SAST-04 / OWASP A02, Alta)
# ============================================================
print("\n=== G05 — Somente HTTPS no download (SAST-04, Alta) ===")

m = re.search(r"^ALLOWED_URL_SCHEMES\s*=\s*\((.*?)\)", FONTE, re.M)
if not m:
    erro("G05", "lista de esquemas permitidos",
         "ALLOWED_URL_SCHEMES não encontrada.")
else:
    esquemas = re.findall(r"['\"](\w+)['\"]", m.group(1))
    inseguros = [e for e in esquemas if e != "https"]
    if inseguros:
        erro("G05", "apenas https permitido",
             f"Esquemas inseguros aceitos: {inseguros}. Um download por http:// "
             "pode ser trocado no caminho por uma imagem adulterada do Windows.")
    else:
        ok("G05", "apenas https é aceito como esquema de download")


# ============================================================
# G06 — Proteções contra apagar o disco errado (SAST-02/03, Alta)
# ============================================================
print("\n=== G06 — Proteção do disco do sistema (SAST-02/03, Alta) ===")

if re.search(r"^CRITICAL_MOUNTPOINTS\s*=", FONTE, re.M) and '"/"' in FONTE:
    ok("G06", "lista de pontos de montagem críticos presente")
else:
    erro("G06", "pontos de montagem críticos",
         "CRITICAL_MOUNTPOINTS sumiu. Sem ela, um sistema que inicializa por "
         "cartão SD (ex.: Raspberry Pi) volta a ter o disco do sistema listado "
         "para ser apagado.")

if re.search(r"^def reverify_target_disk\(", FONTE, re.M):
    ok("G06", "reconferência antes de apagar presente")
else:
    erro("G06", "reconferência antes de apagar",
         "reverify_target_disk() sumiu. Sem ela, /dev/sdb pode apontar para "
         "outro disco entre a escolha do usuário e a gravação (TOCTOU).")

if "reverify_target_disk(" in FONTE.split("def build_usb")[-1][:800]:
    ok("G06", "build_usb() chama a reconferência")
else:
    erro("G06", "build_usb chama a reconferência",
         "build_usb() não chama mais reverify_target_disk(). A proteção existe "
         "mas não está sendo usada.")


# ============================================================
# G07 — Segredos embutidos no código (OWASP A02 / SAST)
# ============================================================
print("\n=== G07 — Segredos embutidos no código ===")

PADRAO_SEGREDO = re.compile(
    r"""(?ix)
    \b(password|passwd|secret|token|api[_-]?key|apikey|
       credential|bearer|private[_-]?key|access[_-]?key)\b
    \s*=\s*
    ['"][^'"\n]{6,}['"]
    """
)
achados_segredo = []
for i, linha in enumerate(FONTE.splitlines(), 1):
    sem_comentario = linha.split("#")[0]
    if PADRAO_SEGREDO.search(sem_comentario):
        achados_segredo.append((i, linha.strip()[:80]))

if achados_segredo:
    for linha, trecho in achados_segredo:
        erro("G07", "possível segredo embutido",
             f"Possível senha/chave escrita no código: {trecho}. "
             "Mova para variável de ambiente.", linha)
else:
    ok("G07", "nenhuma senha, chave ou token embutido no código")


# ============================================================
# G08 — Permissões restritivas de arquivo (STRIDE A-I1/A-I2)
# ============================================================
print("\n=== G08 — Permissões de arquivo ===")

if re.search(r"^PRIVATE_FILE_MODE\s*=\s*0o600", FONTE, re.M):
    ok("G08", "arquivos criados com permissão 0600 (só o dono lê)")
else:
    erro("G08", "permissão 0600",
         "PRIVATE_FILE_MODE deixou de ser 0o600. O registro de auditoria e o "
         "download parcial ficariam legíveis por outros usuários da máquina.")


# ============================================================
# G09 — Scripts privilegiados param na primeira falha (STRIDE B-T2)
# ============================================================
print("\n=== G09 — Scripts privilegiados abortam em erro ===")

# Verificação ESTRUTURAL, não busca de texto: um comentário contendo "set -eu"
# em qualquer lugar do arquivo não pode enganar esta regra.
DESTRUTIVOS = ("wipefs", "mkfs", "parted", "dd ", "sgdisk")


def texto_literal(no):
    """Concatena, em ordem, todas as partes de texto fixo de um valor."""
    partes = []
    for filho in ast.walk(no):
        if isinstance(filho, ast.Constant) and isinstance(filho.value, str):
            partes.append(filho.value)
    return "".join(partes)


scripts_destrutivos = []
for no in ast.walk(ARVORE):
    if not isinstance(no, ast.Assign):
        continue
    nomes = [t.id for t in no.targets if isinstance(t, ast.Name)]
    if not any("script" in n.lower() for n in nomes):
        continue
    corpo = texto_literal(no.value)
    if any(cmd in corpo for cmd in DESTRUTIVOS):
        scripts_destrutivos.append((nomes[0], corpo, no.lineno))

if not scripts_destrutivos:
    erro("G09", "scripts destrutivos localizados",
         "Nenhum script com comandos destrutivos (wipefs/mkfs/parted) foi "
         "encontrado. O código foi reestruturado? Revise esta regra.")
else:
    for nome, corpo, linha in scripts_destrutivos:
        if corpo.lstrip().startswith("set -e"):
            ok("G09", f"'{nome}' começa com 'set -e' (aborta na primeira falha)")
        else:
            erro("G09", f"'{nome}' aborta em erro",
                 f"O script '{nome}' executa comandos destrutivos como administrador "
                 "mas não começa com 'set -eu'. Sem isso, ele continua rodando depois "
                 "de uma falha no meio — por exemplo, formatando após um erro de "
                 "particionamento.", linha)


# ============================================================
# G10 — Instalação de pacotes: comando correto e lista fechada (SCA-04/05)
# ============================================================
print("\n=== G10 — Instalação de dependências como administrador ===")

m = re.search(r'"pacman":\s*"pacman\s+(-\S+)', FONTE)
if not m:
    erro("G10", "comando do pacman", "Template do pacman não encontrado.")
elif m.group(1) != "-Syu":
    erro("G10", "pacman usa -Syu",
         f"O pacman voltou a usar '{m.group(1)}'. Atualização parcial (-Sy) é "
         "desaconselhada oficialmente pelo Arch Linux e pode impedir a máquina "
         "de inicializar.")
else:
    ok("G10", "pacman usa -Syu (atualização completa, forma recomendada)")

if "allowed = set(LINUX_REQUIRED_TOOLS)" in FONTE:
    ok("G10", "lista fechada de pacotes instaláveis como administrador")
else:
    erro("G10", "lista fechada de pacotes",
         "A validação por lista de permissão em linux_build_install_command() "
         "sumiu. Isso controla o que pode ser instalado como root.")


# ============================================================
# G11 — Registro de auditoria de operações destrutivas (OWASP A09)
# ============================================================
print("\n=== G11 — Registro de auditoria (OWASP A09) ===")

if re.search(r"^def audit\(", FONTE, re.M):
    ok("G11", "função de auditoria presente")
else:
    erro("G11", "função audit()",
         "A função de registro de auditoria sumiu. Sem ela não há rastro de "
         "qual disco foi apagado e quando.")

if "DESTRUCTIVE OPERATION START" in FONTE and "DESTRUCTIVE OPERATION COMPLETED" in FONTE:
    ok("G11", "operações destrutivas são registradas (início e fim)")
else:
    erro("G11", "registro de operação destrutiva",
         "Os eventos de início/fim de operação destrutiva sumiram do código.")


# ============================================================
# G12 — Tempo limite no download (SAST-13)
# ============================================================
print("\n=== G12 — Tempo limite de rede ===")

if re.search(r"urlopen\([^)]*timeout\s*=", FONTE):
    ok("G12", "download tem tempo limite definido")
else:
    erro("G12", "tempo limite no download",
         "urlopen() sem timeout: um servidor que aceita a conexão e nunca "
         "responde deixaria o programa travado para sempre.")


# ============================================================
# G13 — Verificação de integridade da imagem (SAST-04 / OWASP A08)
# ============================================================
print("\n=== G13 — Verificação de integridade da imagem ===")

if "hashlib.sha256()" in FONTE:
    ok("G13", "impressão digital SHA-256 é calculada")
else:
    erro("G13", "cálculo do SHA-256",
         "O cálculo da impressão digital do arquivo baixado sumiu.")

for fraco in ("hashlib.md5", "hashlib.sha1"):
    if fraco in FONTE:
        erro("G13", "algoritmo de resumo forte",
             f"{fraco} é considerado quebrado para fins de integridade. Use SHA-256.")
if "hashlib.md5" not in FONTE and "hashlib.sha1" not in FONTE:
    ok("G13", "nenhum algoritmo fraco (MD5/SHA-1) em uso")


# ============================================================
# G14 — Cópia dos arquivos de "hardening" para o pendrive (script privilegiado)
#
# HARDENING_COPY_SCRIPT roda como administrador e copia uma pasta preparada
# pelo programa (os arquivos extras do Windows) para o pendrive montado. Ele
# precisa ser texto literal (nada colado dentro), parar na primeira falha,
# validar as duas pastas recebidas, recusar links simbólicos, copiar SEM
# seguir links e respeitar o arquivo de cancelamento.
# ============================================================
print("\n=== G14 — Script privilegiado de cópia dos arquivos de hardening ===")


def _so_literais(no):
    """True se o valor é só texto fixo: constantes de string ligadas por '+'."""
    if isinstance(no, ast.Constant):
        return isinstance(no.value, str)
    if isinstance(no, ast.BinOp) and isinstance(no.op, ast.Add):
        return _so_literais(no.left) and _so_literais(no.right)
    return False


_script_hard = None
for no in ARVORE.body:
    if isinstance(no, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "HARDENING_COPY_SCRIPT"
                                          for t in no.targets):
        _script_hard = no

if _script_hard is None:
    erro("G14", "HARDENING_COPY_SCRIPT presente",
         "O script de cópia dos arquivos de hardening sumiu ou foi renomeado. "
         "Se a cópia mudou de forma, revise esta regra.")
elif not _so_literais(_script_hard.value):
    erro("G14", "HARDENING_COPY_SCRIPT é texto literal",
         "O script privilegiado deixou de ser texto literal (f-string, format, "
         "concatenação com variável). Valores só podem chegar como \"$1\", \"$2\", \"$3\".",
         _script_hard.lineno)
else:
    _texto_hard = texto_literal(_script_hard.value)
    _exigencias = [
        (_texto_hard.lstrip().startswith("set -eu"), "começar com 'set -eu'"),
        ('[ ! -d "$STAGE" ]' in _texto_hard and '[ ! -d "$MNT" ]' in _texto_hard,
         "validar que a pasta preparada e o ponto de montagem são diretórios"),
        ('find "$STAGE" -type l' in _texto_hard, "recusar links simbólicos na pasta preparada"),
        ("cp -RP -- " in _texto_hard, "copiar sem seguir links ('cp -RP --')"),
        ('[ -e "$STOP" ]' in _texto_hard and "HARDENING_CANCELED" in _texto_hard,
         "respeitar o arquivo de cancelamento"),
    ]
    _faltando = [descricao for presente, descricao in _exigencias if not presente]
    if _faltando:
        for descricao in _faltando:
            erro("G14", f"HARDENING_COPY_SCRIPT deve {descricao}",
                 f"O script privilegiado de cópia dos arquivos de hardening deixou de {descricao}.",
                 _script_hard.lineno)
    else:
        ok("G14", "script de cópia: literal, 'set -eu', valida pastas, recusa links, sem seguir links, cancelável")

_chamadas_hard = [no for no in ast.walk(ARVORE)
                  if isinstance(no, ast.Call) and getattr(no.func, "attr", None) == "run_script"
                  and no.args and isinstance(no.args[0], ast.Name) and no.args[0].id == "HARDENING_COPY_SCRIPT"]
if not _chamadas_hard:
    erro("G14", "HARDENING_COPY_SCRIPT é executado com argumentos posicionais",
         "Nenhuma chamada run_script(HARDENING_COPY_SCRIPT, ...) encontrada.")
else:
    for chamada in _chamadas_hard:
        argumentos = [kw for kw in chamada.keywords if kw.arg == "args"]
        if argumentos and isinstance(argumentos[0].value, ast.List) and len(argumentos[0].value.elts) == 3:
            ok("G14", "HARDENING_COPY_SCRIPT recebe a pasta, o ponto de montagem e o arquivo de cancelamento "
                      "por args=[...]")
        else:
            erro("G14", "HARDENING_COPY_SCRIPT recebe 3 argumentos posicionais",
                 "run_script(HARDENING_COPY_SCRIPT, ...) precisa passar args=[pasta, ponto, cancelamento].",
                 chamada.lineno)


# ============================================================
# Resultado
# ============================================================
print("\n" + "=" * 66)
if falhas:
    print(f"GUARDA DE SEGURANÇA: {len(falhas)} PROTEÇÃO(ÕES) DESFEITA(S)\n")
    for f in falhas:
        print(f"  * {f}\n")
    print("Uma correção da auditoria de segurança foi desfeita por esta alteração.")
    print("Consulte output/relatorio-consolidado-seguranca.md antes de prosseguir.")
    sys.exit(1)

print(f"GUARDA DE SEGURANÇA: todas as {verificacoes} proteções continuam no lugar.")
if avisos:
    for a in avisos:
        print(f"  aviso: {a}")
sys.exit(0)
