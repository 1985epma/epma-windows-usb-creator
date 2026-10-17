#!/usr/bin/env python3
"""
Teste de fumaça da interface gráfica.

"Teste de fumaça" é o nome que se dá a uma verificação básica: liga o aparelho
e vê se sai fumaça. Aqui: constrói a janela do programa de verdade e confere que
todos os elementos existem.

POR QUE ISTO IMPORTA
--------------------
Durante a auditoria, uma alteração deixou o código com uma referência a um
elemento de tela que não existia. A sintaxe estava perfeita, os testes de
validação passavam — e o programa travaria na primeira vez que o usuário
baixasse a ISO. Só um teste que CONSTRÓI a janela pegaria isso.

Este teste roda sem exibir a janela (`withdraw`). No Linux, execute-o dentro de
um servidor gráfico virtual:

    xvfb-run -a python3 output/auditoria/smoke_ui.py

No macOS, basta:

    python3 output/auditoria/smoke_ui.py

O programa não executa nenhuma operação de disco: apenas monta a interface.
"""

import os
import sys

RAIZ = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, RAIZ)

# Não criar arquivo de log durante o teste.
os.environ["WIN11USB_DISABLE_AUDIT_LOG"] = "1"

import win11_usb_creator as app  # noqa: E402

# Elementos que o restante do código referencia. Se algum for renomeado ou
# esquecido, o programa quebra em tempo de execução — e este teste pega isso.
WIDGETS_OBRIGATORIOS = [
    "url_entry", "sha_entry", "download_btn", "cancel_btn",
    "progress", "progress_label", "iso_label", "iso_label2",
    "dep_label", "install_deps_btn", "disk_combo",
    "mode_var", "create_btn", "log_text",
]

METODOS_OBRIGATORIOS = [
    "start_download", "cancel_download", "pick_existing_iso", "set_iso",
    "refresh_disks", "selected_disk", "update_create_button_state",
    "start_create_usb", "log", "_report_error", "_on_download_done",
    "_on_download_error", "_on_progress", "check_dependencies",
    "install_dependencies", "open_ms_page", "on_mode_change",
]

print("Teste de fumaça da interface gráfica")
print("=" * 66)

falhas = []

try:
    janela = app.App()
except Exception as e:
    print(f"FALHA: a janela não pôde ser criada: {type(e).__name__}: {e}")
    if not os.environ.get("DISPLAY") and sys.platform.startswith("linux"):
        print("\nNo Linux é preciso um servidor gráfico virtual. Use:")
        print("    xvfb-run -a python3 output/auditoria/smoke_ui.py")
    sys.exit(1)

try:
    janela.withdraw()          # constrói tudo, mas não mostra a janela
    janela.update_idletasks()  # força a construção completa da interface

    print("\nElementos de tela:")
    for nome in WIDGETS_OBRIGATORIOS:
        if hasattr(janela, nome):
            print(f"  [OK]    {nome}")
        else:
            print(f"  [FALHA] {nome} — AUSENTE")
            falhas.append(f"elemento de tela '{nome}'")

    print("\nMétodos:")
    for nome in METODOS_OBRIGATORIOS:
        if callable(getattr(janela, nome, None)):
            print(f"  [OK]    {nome}()")
        else:
            print(f"  [FALHA] {nome}() — AUSENTE")
            falhas.append(f"método '{nome}'")

    # Exercita os caminhos que só executam em tempo real — é onde estava o
    # defeito que os testes de sintaxe não pegaram.
    #
    # IMPORTANTE: as caixas de diálogo (messagebox) são substituídas por
    # versões silenciosas. Um diálogo de verdade abriria uma janela e ficaria
    # esperando alguém clicar em OK — travando a esteira automática para
    # sempre. Trocando por funções vazias, o código É executado de verdade,
    # mas nada fica esperando interação humana.
    dialogos_chamados = []

    class _MessageboxSilencioso:
        @staticmethod
        def showerror(titulo, msg, **kw):
            dialogos_chamados.append(("erro", titulo))

        @staticmethod
        def showinfo(titulo, msg, **kw):
            dialogos_chamados.append(("info", titulo))

        @staticmethod
        def showwarning(titulo, msg, **kw):
            dialogos_chamados.append(("aviso", titulo))

        @staticmethod
        def askyesno(titulo, msg, **kw):
            dialogos_chamados.append(("pergunta", titulo))
            return False  # sempre "não", para nunca iniciar operação destrutiva

    messagebox_real = app.messagebox
    app.messagebox = _MessageboxSilencioso

    print("\nCaminhos de execução:")
    try:
        janela.log("linha de teste")
        print("  [OK]    log() escreve na caixa de registro")
    except Exception as e:
        print(f"  [FALHA] log(): {type(e).__name__}: {e}")
        falhas.append("log()")

    try:
        janela.update_create_button_state()
        print("  [OK]    update_create_button_state() sem disco selecionado")
    except Exception as e:
        print(f"  [FALHA] update_create_button_state(): {type(e).__name__}: {e}")
        falhas.append("update_create_button_state()")

    try:
        janela._report_error("Teste", "mensagem simples")
        janela._report_error("Teste", None, ValueError("erro de exemplo"))
        print("  [OK]    _report_error() nas duas formas de uso")
    except Exception as e:
        print(f"  [FALHA] _report_error(): {type(e).__name__}: {e}")
        falhas.append("_report_error()")

    # Este é O caminho onde estava o defeito introduzido durante a auditoria:
    # uma referência a um elemento de tela que não existia. Só é detectável
    # executando o método de verdade.
    try:
        sha_falso = "0" * 64
        janela._on_download_done("/tmp/exemplo.iso", sha_falso, True)
        janela._on_download_done("/tmp/exemplo.iso", sha_falso, False)
        print("  [OK]    _on_download_done() com e sem verificação de integridade")
    except Exception as e:
        print(f"  [FALHA] _on_download_done(): {type(e).__name__}: {e}")
        falhas.append("_on_download_done()")

    try:
        janela._on_download_error("mensagem de erro de exemplo")
        print("  [OK]    _on_download_error()")
    except Exception as e:
        print(f"  [FALHA] _on_download_error(): {type(e).__name__}: {e}")
        falhas.append("_on_download_error()")

    try:
        janela._on_progress(500, 1000, 250.0)   # com tamanho total conhecido
        janela._on_progress(500, 0, 250.0)      # sem tamanho total
        print("  [OK]    _on_progress() com e sem tamanho total conhecido")
    except Exception as e:
        print(f"  [FALHA] _on_progress(): {type(e).__name__}: {e}")
        falhas.append("_on_progress()")

    app.messagebox = messagebox_real
    print(f"\n  ({len(dialogos_chamados)} diálogos interceptados, nenhum exibido)")
finally:
    try:
        janela.destroy()
    except Exception as e:  # noqa: S110 - falha ao fechar a janela não invalida o teste
        print(f"  (aviso: não foi possível fechar a janela: {type(e).__name__})")

print("\n" + "=" * 66)
if falhas:
    print(f"FALHA: {len(falhas)} problema(s) na interface:")
    for f in falhas:
        print(f"  * {f}")
    sys.exit(1)

print("APROVADO: a janela é construída e todos os elementos existem.")
sys.exit(0)
