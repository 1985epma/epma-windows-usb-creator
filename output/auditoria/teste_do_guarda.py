#!/usr/bin/env python3
"""
Autoteste do guarda de segurança — "quem vigia o vigia?"

POR QUE ISTO EXISTE
-------------------
O guarda (guard_seguranca.py) confere que as correções de segurança continuam
no código. Mas e se o próprio guarda estiver quebrado e aprovando tudo?

Um verificador que sempre diz "está tudo bem" é pior que nenhum verificador,
porque dá uma falsa sensação de segurança.

Este autoteste pega o código real, desfaz PROPOSITALMENTE cada correção (numa
cópia temporária, nunca no arquivo original) e confirma que o guarda reclama.
Se o guarda aprovar um código sabidamente inseguro, ESTE teste falha.

USO
---
    python3 output/auditoria/teste_do_guarda.py
"""

import os
import re
import subprocess
import sys
import tempfile

AQUI = os.path.dirname(os.path.abspath(__file__))
RAIZ = os.path.abspath(os.path.join(AQUI, "..", ".."))
ORIGINAL = os.path.join(RAIZ, "win11_usb_creator.py")
GUARDA = os.path.join(AQUI, "guard_seguranca.py")

with open(ORIGINAL, encoding="utf-8") as fh:
    FONTE = fh.read()

# Cada cenário desfaz uma correção. (nome, função-que-quebra, regra esperada)
CENARIOS = [
    (
        "Voltar a colar o caminho da ISO dentro do script de administrador",
        lambda s: s.replace(
            "'mount -o loop,ro,uid=\"${OWNER%%:*}\",gid=\"${OWNER##*:}\" \"$ISO\" \"$ISO_MNT\"\\n'",
            "f'mount -o loop,ro \"{iso_path}\" \"$ISO_MNT\"\\n'",
        ),
        "G01",
    ),
    (
        "Usar shell=True numa chamada de subprocesso",
        lambda s: s.replace(
            "proc = subprocess.Popen(args, stdout=subprocess.PIPE",
            "proc = subprocess.Popen(args, shell=True, stdout=subprocess.PIPE",
        ),
        "G02",
    ),
    (
        "Passar a senha na linha de comando (visível via `ps`)",
        lambda s: s.replace(
            '["sudo", "-S", "-p", ""] + bash_argv',
            '["sudo", "-S", "-p", "", password] + bash_argv',
        ),
        "G03",
    ),
    (
        "Remover as âncoras ^ e $ da validação do identificador de disco",
        lambda s: s.replace(
            'LINUX_DEVICE_RE = re.compile(r"^[a-zA-Z0-9_+-]{1,32}$")',
            'LINUX_DEVICE_RE = re.compile(r"[a-zA-Z0-9_+-]{1,32}")',
        ),
        "G04",
    ),
    (
        "Voltar a aceitar download por http:// sem criptografia",
        lambda s: s.replace(
            'ALLOWED_URL_SCHEMES = ("https",)',
            'ALLOWED_URL_SCHEMES = ("https", "http")',
        ),
        "G05",
    ),
    (
        "Remover a lista de pontos de montagem críticos do sistema",
        lambda s: re.sub(r"^CRITICAL_MOUNTPOINTS\s*=.*$", "CRITICAL_MOUNTPOINTS_REMOVIDA = ()",
                         s, count=1, flags=re.M),
        "G06",
    ),
    (
        "Escrever uma chave de API dentro do código",
        lambda s: s.replace(
            'VOL_NAME = "WIN11USB"',
            'VOL_NAME = "WIN11USB"\napi_key = "sk-live-9f3a8c2e1b7d4a6f"',
        ),
        "G07",
    ),
    (
        "Afrouxar a permissão do log de auditoria para leitura por todos",
        lambda s: s.replace("PRIVATE_FILE_MODE = 0o600", "PRIVATE_FILE_MODE = 0o644"),
        "G08",
    ),
    (
        "Remover 'set -eu' do script executado como administrador",
        lambda s: s.replace("'set -eu\\n'", "'# sem set -eu\\n'"),
        "G09",
    ),
    (
        "Voltar o pacman para -Sy (atualização parcial)",
        lambda s: s.replace('"pacman": "pacman -Syu', '"pacman": "pacman -Sy'),
        "G10",
    ),
    (
        "Remover o registro de auditoria das operações destrutivas",
        lambda s: s.replace("DESTRUCTIVE OPERATION START", "operacao iniciada"),
        "G11",
    ),
    (
        "Remover o tempo limite do download",
        lambda s: s.replace("urlopen(req, timeout=DOWNLOAD_TIMEOUT_SECONDS)", "urlopen(req)"),
        "G12",
    ),
    (
        "Trocar SHA-256 por MD5 (algoritmo quebrado)",
        lambda s: s.replace("hashlib.sha256()", "hashlib.md5()"),
        "G13",
    ),
    # ===== hardening: engine-windows =====
    (
        "Build_usb deixa de conferir a imagem (arquivos de hardening que seriam substituídos) antes de apagar",
        lambda s: s.replace(
            "    refuse_hardening_clash(iso_path, hardening_files, log, priv)\n", ""),
        "G14",
    ),
    (
        "Colar o caminho da ISO dentro do script que lista a imagem antes de apagar",
        lambda s: s.replace(
            "'ISO=\"$1\"; ISO_MNT=\"$2\"; OWNER=\"$3\"\\n'",
            "f'ISO=\"{iso_path}\"; ISO_MNT=\"$2\"; OWNER=\"$3\"\\n'",
        ),
        "G01",
    ),
    (
        "Tirar o 'trap INT' do script que lista a imagem antes de apagar",
        lambda s: s.replace(
            "LINUX_ISO_PEEK_SCRIPT = (\n    'set -eu\\n'\n    \"trap '' INT\\n\"\n",
            "LINUX_ISO_PEEK_SCRIPT = (\n    'set -eu\\n'\n",
        ),
        "G14",
    ),
    # ===== end hardening: engine-windows =====
    # ===== hardening: engine-seed =====
    (
        "Colar o rótulo do pendrive de sementes dentro do script de administrador",
        lambda s: s.replace(
            "'mkfs.vfat -F 32 -n \"$LABEL\" \"$PART\"\\n'",
            "f'mkfs.vfat -F 32 -n {label} \"$PART\"\\n'",
        ),
        "G01",
    ),
    (
        "Tirar o 'set -eu' do script do pendrive de sementes",
        lambda s: s.replace(
            "LINUX_SEED_PREP_SCRIPT = (\n    'set -eu\\n'",
            "LINUX_SEED_PREP_SCRIPT = (\n    '# sem set -eu\\n'",
        ),
        "G09",
    ),
    (
        "Pendrive de sementes: o script deixa de olhar a bandeira de cancelamento antes de apagar",
        lambda s: s.replace(
            "    'if [ -e \"$FLAG\" ]; then echo SEED_NOT_TOUCHED; exit 0; fi\\n'\n", ""),
        "G14",
    ),
    (
        "Pendrive de sementes: build_seed_usb deixa de reconferir o disco antes de apagar",
        lambda s: s.replace(
            "            reverify_target_disk(dev, expected_size, log)\n            check_canceled(",
            "            check_canceled(",
        ),
        "G14",
    ),
    (
        "Pendrive de sementes: build_seed_usb deixa de validar os arquivos",
        lambda s: s.replace(
            "    files = validate_seed_files(files)\n    check_seed_target_size(",
            "    files = dict(files)\n    check_seed_target_size(",
        ),
        "G14",
    ),
    (
        "Pendrive de sementes: o script vira texto montado com .format()",
        lambda s: s.replace(
            "LINUX_SEED_REMOUNT_SCRIPT = (\n    'set -eu\\n'",
            "LINUX_SEED_REMOUNT_SCRIPT = ('{}'.format('x') + \n    'set -eu\\n'",
        ),
        "G14",
    ),
    (
        "Pendrive de sementes: o script de preparo deixa de ignorar o Ctrl-C do terminal",
        lambda s: s.replace(
            "LINUX_SEED_PREP_SCRIPT = (\n    'set -eu\\n'\n    \"trap '' INT\\n\"\n",
            "LINUX_SEED_PREP_SCRIPT = (\n    'set -eu\\n'\n",
        ),
        "G14",
    ),
    (
        "Pendrive de sementes: o script de remontagem deixa de ignorar o Ctrl-C do terminal",
        lambda s: s.replace(
            "LINUX_SEED_REMOUNT_SCRIPT = (\n    'set -eu\\n'\n    \"trap '' INT\\n\"\n",
            "LINUX_SEED_REMOUNT_SCRIPT = (\n    'set -eu\\n'\n",
        ),
        "G14",
    ),
    (
        "Pendrive de sementes: o script de limpeza deixa de ignorar o Ctrl-C do terminal",
        lambda s: s.replace(
            "LINUX_SEED_CLEANUP_SCRIPT = (\n    'set -eu\\n'\n    \"trap '' INT\\n\"\n",
            "LINUX_SEED_CLEANUP_SCRIPT = (\n    'set -eu\\n'\n",
        ),
        "G14",
    ),
    # ===== end hardening: engine-seed =====
    # ===== hardening2: engine-cli =====
    (
        "Pendrive de sementes: build_seed_usb deixa de recusar during_setup fora do Windows",
        lambda s: s.replace(
            "    if during_setup and target != SEED_WINDOWS:",
            "    if False and target != SEED_WINDOWS:",
        ),
        "G14",
    ),
    (
        # Ainda cita during_setup e ainda lança um erro (o teste antigo aprovava), mas já não compara com SEED_WINDOWS.
        "Pendrive de sementes: a recusa de during_setup passa a comparar com um texto solto, não com SEED_WINDOWS",
        lambda s: s.replace(
            "    if during_setup and target != SEED_WINDOWS:",
            "    if during_setup and target != \"windows\":",
        ),
        "G14",
    ),
    (
        # Cita SEED_WINDOWS e during_setup e lança erro, mas a lógica está invertida (recusaria o próprio Windows).
        "Pendrive de sementes: a recusa de during_setup é invertida (recusa o Windows em vez dos outros alvos)",
        lambda s: s.replace(
            "    if during_setup and target != SEED_WINDOWS:",
            "    if during_setup and target == SEED_WINDOWS:",
        ),
        "G14",
    ),
    # ===== end hardening2: engine-cli =====
]

print("Autoteste do guarda de segurança")
print("=" * 66)
print("Cada linha desfaz UMA correção numa cópia temporária e confere que o")
print("guarda reclama. O arquivo original nunca é alterado.\n")

falhas = []

for descricao, quebrar, regra_esperada in CENARIOS:
    quebrado = quebrar(FONTE)
    if quebrado == FONTE:
        print(f"  [ERRO ] {descricao}\n           -> o cenário não alterou nada; "
              "o código mudou e este teste precisa ser atualizado.")
        falhas.append(descricao)
        continue

    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as tmp:
        tmp.write(quebrado)
        caminho = tmp.name
    try:
        r = subprocess.run([sys.executable, GUARDA, caminho],
                           capture_output=True, text=True)
        # A linha "[FALHA] Gxx" (e não só "Gxx", que também aparece nas linhas [OK]) prova que foi ESSA regra.
        detectou = r.returncode != 0 and f"[FALHA] {regra_esperada}" in r.stdout
        if detectou:
            print(f"  [OK   ] {descricao}\n           -> guarda barrou ({regra_esperada})")
        else:
            print(f"  [FALHA] {descricao}\n           -> guarda NÃO barrou "
                  f"(esperado {regra_esperada}, saída {r.returncode})")
            falhas.append(descricao)
    finally:
        os.unlink(caminho)

print("\n" + "=" * 66)
if falhas:
    print(f"AUTOTESTE FALHOU: o guarda deixou passar {len(falhas)} de {len(CENARIOS)} regressões:")
    for f in falhas:
        print(f"  * {f}")
    print("\nO guarda de segurança não está confiável. Corrija-o antes de confiar na CI.")
    sys.exit(1)

print(f"AUTOTESTE APROVADO: o guarda detectou todas as {len(CENARIOS)} regressões.")
sys.exit(0)
