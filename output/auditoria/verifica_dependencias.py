#!/usr/bin/env python3
"""
Verificação de dependências — guarda a propriedade mais valiosa do projeto.

O QUE ISTO FAZ, EM LINGUAGEM SIMPLES
------------------------------------
Hoje o programa usa APENAS a biblioteca padrão do Python — nenhum pedaço de
código de terceiros. Isso elimina a porta de entrada mais comum de ataques em
software moderno (o relatório SCA explica em detalhe).

Essa propriedade é fácil de perder sem ninguém perceber: basta alguém escrever
`import requests` e pronto — o projeto passa a depender de código de estranhos,
e ninguém foi avisado.

Este verificador confere que todo módulo importado pertence à biblioteca padrão
do Python. Se alguém adicionar uma biblioteca de terceiros, a esteira falha e
avisa o que precisa ser feito.

Não é uma proibição: é um alarme. Se a dependência for mesmo necessária, o
processo está descrito na mensagem de erro.

USO
---
    python3 output/auditoria/verifica_dependencias.py
"""

import ast
import os
import sys

RAIZ = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
ALVO = os.path.join(RAIZ, "win11_usb_creator.py")

if sys.version_info < (3, 10):
    print("AVISO: esta verificação precisa do Python 3.10 ou superior "
          f"(rodando {sys.version_info.major}.{sys.version_info.minor}). Pulando.")
    sys.exit(0)

with open(ALVO, encoding="utf-8") as fh:
    arvore = ast.parse(fh.read(), filename=ALVO)

modulos = set()
for no in ast.walk(arvore):
    if isinstance(no, ast.Import):
        for alias in no.names:
            modulos.add(alias.name.split(".")[0])
    elif isinstance(no, ast.ImportFrom):
        if no.level == 0 and no.module:  # ignora imports relativos
            modulos.add(no.module.split(".")[0])

padrao = set(sys.stdlib_module_names)
terceiros = sorted(m for m in modulos if m not in padrao)

print("Verificação de dependências de terceiros")
print("=" * 66)
print(f"Módulos importados por win11_usb_creator.py: {len(modulos)}")
for m in sorted(modulos):
    origem = "biblioteca padrão" if m in padrao else ">>> TERCEIRO <<<"
    print(f"  {m:<18} {origem}")

print()
if terceiros:
    print("=" * 66)
    print(f"FALHA: {len(terceiros)} dependência(s) de terceiros encontrada(s):")
    for m in terceiros:
        print(f"  * {m}")
    print()
    print("O projeto tinha ZERO dependências de terceiros — essa era uma de suas")
    print("melhores propriedades de segurança (ver output/relatorio-sca.md).")
    print()
    print("Se a dependência for realmente necessária, faça o seguinte:")
    print("  1. Declare-a em requirements.txt com a versão fixada (ex.: pacote==1.2.3);")
    print("  2. Ative a verificação de vulnerabilidades: acrescente o passo do")
    print("     'pip-audit' ao arquivo .github/workflows/security.yml;")
    print("  3. Atualize a seção A06 de output/relatorio-owasp-top10.md, que hoje")
    print("     está marcada como 'Não aplicável' justamente por não haver nenhuma;")
    print("  4. Remova a exceção correspondente deste verificador.")
    sys.exit(1)

print("=" * 66)
print("APROVADO: o projeto continua usando apenas a biblioteca padrão do Python.")
print("Nenhuma dependência de terceiros — nenhuma vulnerabilidade herdada.")
sys.exit(0)
