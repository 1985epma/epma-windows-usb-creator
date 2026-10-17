#!/usr/bin/env python3
"""
Verificação local — roda as mesmas conferências da esteira automática.

PARA QUE SERVE
--------------
A esteira do GitHub (CI/CD) roda estas conferências toda vez que o código muda.
Este programa roda AS MESMAS conferências no seu computador, para você descobrir
um problema antes de enviar — em segundos, em vez de esperar alguns minutos e
receber um X vermelho no GitHub.

COMO USAR
---------
    python3 verificar.py

É seguro: nenhuma conferência toca em disco, formata nada ou usa privilégio de
administrador.

Código de saída 0 = tudo certo. 1 = algo precisa de atenção.
"""

import os
import subprocess
import sys

RAIZ = os.path.dirname(os.path.abspath(__file__))
AUD = os.path.join(RAIZ, "output", "auditoria")
PY = sys.executable

# (nome amigável, comando, é obrigatório?)
CONFERENCIAS = [
    (
        "Sintaxe do código",
        [PY, "-m", "compileall", "-q", os.path.join(RAIZ, "win11_usb_creator.py"), AUD],
        True,
    ),
    (
        "Autoteste do guarda de segurança",
        [PY, os.path.join(AUD, "teste_do_guarda.py")],
        True,
    ),
    (
        "Guarda de segurança (27 proteções da auditoria)",
        [PY, os.path.join(AUD, "guard_seguranca.py")],
        True,
    ),
    (
        "Dependências de terceiros (devem continuar zero)",
        [PY, os.path.join(AUD, "verifica_dependencias.py")],
        True,
    ),
    (
        "Testes de validação (44 verificações)",
        [PY, os.path.join(AUD, "testes_validacao.py")],
        True,
    ),
    (
        "Testes unitários (tests/)",
        [PY, "-m", "unittest", "discover", "-s", os.path.join(RAIZ, "tests"), "-t", RAIZ],
        True,
    ),
    (
        "Teste da interface gráfica",
        [PY, os.path.join(AUD, "smoke_ui.py")],
        False,  # precisa de ambiente gráfico; no Linux sem tela, use xvfb-run
    ),
]

LARGURA = 68
print()
print("=" * LARGURA)
print("  VERIFICAÇÃO LOCAL — EPMA Windows 11 Creator USB")
print("=" * LARGURA)
print("  As mesmas conferências que a esteira automática do GitHub faz.")
print("  Nenhuma delas toca em disco nem pede senha de administrador.")
print("=" * LARGURA)
print()

falhas = []
pulados = []

for nome, comando, obrigatoria in CONFERENCIAS:
    try:
        # O limite de tempo é essencial: uma conferência que abrisse uma caixa
        # de diálogo ficaria esperando um clique para sempre.
        r = subprocess.run(comando, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        print(f"  [DEMOROU] {nome}")
        falhas.append((nome, "A conferência passou de 3 minutos e foi interrompida. "
                             "Ela pode estar esperando alguma interação."))
        continue
    except Exception as e:
        print(f"  [ERRO]    {nome}")
        falhas.append((nome, f"{type(e).__name__}: {e}"))
        continue

    if r.returncode == 0:
        print(f"  [OK]      {nome}")
    elif not obrigatoria:
        print(f"  [PULADO]  {nome}")
        pulados.append(nome)
    else:
        print(f"  [FALHOU]  {nome}")
        saida = (r.stdout or "") + (r.stderr or "")
        # Mostra só o fim da saída, que é onde fica o resumo do erro.
        linhas = [ln for ln in saida.strip().splitlines() if ln.strip()]
        falhas.append((nome, "\n".join(linhas[-15:])))

print()
print("=" * LARGURA)

if pulados:
    print("  Conferências puladas (não impedem o envio):")
    for nome in pulados:
        print(f"    - {nome}")
    if sys.platform.startswith("linux"):
        print("      No Linux sem tela, rode: xvfb-run -a python3 output/auditoria/smoke_ui.py")
    print()

if falhas:
    print(f"  RESULTADO: {len(falhas)} conferência(s) falharam.")
    print("=" * LARGURA)
    for nome, detalhe in falhas:
        print(f"\n  >>> {nome}")
        for linha in detalhe.splitlines():
            print(f"      {linha}")
    print()
    print("=" * LARGURA)
    print("  Corrija os pontos acima antes de enviar o código.")
    print("  Em caso de dúvida: output/relatorio-consolidado-seguranca.md")
    print("=" * LARGURA)
    sys.exit(1)

print("  RESULTADO: tudo certo. O código está pronto para ser enviado.")
print("=" * LARGURA)
print()
sys.exit(0)
