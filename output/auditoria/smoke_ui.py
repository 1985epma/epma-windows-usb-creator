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
    "nb", "tab3", "flex_download_btn", "flex_cancel_btn", "flex_progress", "flex_progress_label",
    "flex_status_label", "flex_disk_combo", "flex_create_btn", "flex_cancel_create_btn",
    "flex_write_progress", "flex_write_label", "mode_var", "create_btn", "cancel_create_btn", "create_progress", "create_progress_label", "log_text",
    "iso_check_frame", "iso_sha_entry", "iso_sha_btn", "iso_sha_progress", "iso_sha_label", "iso_sha_result",
]

METODOS_OBRIGATORIOS = [
    "start_download", "cancel_download", "pick_existing_iso", "set_iso",
    "refresh_disks", "selected_disk", "update_create_button_state",
    "start_create_usb", "cancel_create_usb", "log", "_report_error", "_on_download_done",
    "_on_download_error", "_on_progress", "check_dependencies",
    "install_dependencies", "open_ms_page", "on_mode_change",
    "start_flex_download", "start_flex_write", "_on_disk_selected", "cancel_flex", "_on_flex_progress", "_extract_flex_image", "_on_flex_extracted",
    "_on_flex_error", "report_callback_exception", "_fit_window", "_build_menu", "show_help", "show_about", "_on_create_progress", "_reset_create_progress", "_finish_create_progress",
    "log_threadsafe", "_flush_log", "confirm_erase", "calculate_iso_sha256",
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
        janela.log_threadsafe("linha da fila 1")
        janela.log_threadsafe("linha da fila 2")
        janela.log("linha direta")  # descarrega a fila preservando a ordem
        janela.update()
        texto = janela.log_text.get("1.0", "end")
        assert texto.index("linha da fila 1") < texto.index("linha da fila 2") < texto.index("linha direta")
        print("  [OK]    fila de log (thread-safe) preserva a ordem")
    except Exception as e:
        print(f"  [FALHA] fila de log: {type(e).__name__}: {e}")
        falhas.append("fila de log")

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

    try:
        janela._reset_create_progress()
        janela._on_create_progress(500, 1000, "Writing the image...")
        janela._on_create_progress(1000, 1000, "Writing the image...")
        janela._on_create_progress(0, 0, "Verifying the copied files...")   # tamanho desconhecido
        janela._on_create_progress(500, 1000, "Verifying the written image...")
        janela._finish_create_progress(True)
        janela._finish_create_progress(False)
        janela._finish_create_progress(False, True)   # cancelado pelo usuário
        print("  [OK]    progresso da criação do pendrive (indeterminado, parcial, 100%, falha)")
    except Exception as e:
        print(f"  [FALHA] progresso da criação: {type(e).__name__}: {e}")
        falhas.append("progresso da criação")

    try:
        # aba ChromeOS Flex: barra de progresso, erro e troca do tipo de imagem para ChromeOS
        janela._on_flex_progress(500, 1000, 250.0, "Downloading...")
        janela._on_flex_progress(500, 0, 0, "Extracting...")
        janela._on_flex_error("mensagem de erro de exemplo")          # messagebox silencioso
        janela.mode_var.set(app.MODE_CHROMEOS)
        janela.on_mode_change()
        # os controles de gravação da aba 2 e da aba ChromeOS Flex mostram sempre o mesmo estado
        janela._reset_create_progress()   # zera o intervalo mínimo entre atualizações da barra
        janela._on_create_progress(500, 1000, "Writing the image...")
        assert float(janela.flex_write_progress.cget("value")) == 50.0, "o progresso não foi espelhado na aba 3"
        janela._finish_create_progress(True)
        assert "100" in str(janela.flex_write_label.cget("text")), "o fim da gravação não foi espelhado"
        assert [str(t) for t in janela.nb.tabs()].__len__() == 3, "a terceira aba não existe"
        print("  [OK]    aba ChromeOS Flex (progresso, erro e tipo de imagem)")
    except Exception as e:
        print(f"  [FALHA] aba ChromeOS Flex: {type(e).__name__}: {e}")
        falhas.append("aba ChromeOS Flex")

    try:
        assert str(janela.cget("menu")), "a barra de menus (Help) não foi criada"
        janela.show_help()
        janela.show_help(len(app.help_sections()) - 1)   # segunda chamada reaproveita a janela
        janela._help_win.destroy()
        janela.show_about()                                # messagebox silencioso
        print("  [OK]    menu Help, janela de documentação e About")
    except Exception as e:
        print(f"  [FALHA] menu Help: {type(e).__name__}: {e}")
        falhas.append("menu Help")

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
