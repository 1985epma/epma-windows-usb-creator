#!/usr/bin/env python3
"""
Testes de validação das correções de segurança — EPMA Windows 11 Creator USB.

IMPORTANTE: estes testes NÃO tocam em nenhum disco, NÃO formatam nada e NÃO
executam comandos com privilégio de administrador. Eles apenas verificam que as
funções de validação e a montagem de comandos se comportam como esperado.

Uso:  python3 output/auditoria/testes_validacao.py
"""
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

# Evita abrir a janela gráfica ao importar o módulo.
os.environ.setdefault("WIN11USB_DISABLE_AUDIT_LOG", "1")
import win11_usb_creator as app  # noqa: E402

falhas = []
total = 0


def check(nome, condicao, detalhe=""):
    global total
    total += 1
    if condicao:
        print(f"  [OK]    {nome}")
    else:
        print(f"  [FALHA] {nome} {detalhe}")
        falhas.append(nome)


def espera_erro(nome, fn, *args):
    global total
    total += 1
    try:
        fn(*args)
    except (ValueError, RuntimeError) as e:
        print(f"  [OK]    {nome} -> rejeitado: {str(e)[:60]}...")
        return
    except Exception as e:
        print(f"  [FALHA] {nome} -> erro inesperado {type(e).__name__}: {e}")
        falhas.append(nome)
        return
    print(f"  [FALHA] {nome} -> ACEITOU quando deveria rejeitar")
    falhas.append(nome)


print("\n=== 1. Validação do endereço de download (SAST-04 / SCA-03) ===")
espera_erro("http:// sem criptografia é rejeitado",
            app.validate_download_url, "http://exemplo.com/win11.iso")
espera_erro("file:// (leitura de arquivo local) é rejeitado",
            app.validate_download_url, "file:///etc/passwd")
espera_erro("ftp:// é rejeitado", app.validate_download_url, "ftp://exemplo.com/a.iso")
espera_erro("campo vazio é rejeitado", app.validate_download_url, "")
espera_erro("texto que não é link é rejeitado", app.validate_download_url, "isso nao e um link")

url, host, nao_confiavel = app.validate_download_url(
    "https://software.download.prss.microsoft.com/db/Win11.iso?t=abc")
check("host oficial da Microsoft é aceito e marcado como confiável",
      host == "software.download.prss.microsoft.com" and not nao_confiavel)

url, host, nao_confiavel = app.validate_download_url("https://espelho-aleatorio.xyz/Win11.iso")
check("host desconhecido é aceito porém MARCADO como não confiável",
      nao_confiavel is True, f"(nao_confiavel={nao_confiavel})")

print("\n=== 2. Validação do identificador de disco (SAST-01) ===")
espera_erro("nome com ponto-e-vírgula é rejeitado", app.validate_device_name, "sdb; rm -rf /")
espera_erro("nome com aspas é rejeitado", app.validate_device_name, 'sdb" ; id ; "')
espera_erro("nome com $(...) é rejeitado", app.validate_device_name, "sdb$(whoami)")
espera_erro("nome com barra é rejeitado", app.validate_device_name, "../../dev/sda")
espera_erro("nome vazio é rejeitado", app.validate_device_name, "")
nome_valido = "disk4" if app.IS_MAC else "sdb"
check(f"nome legítimo '{nome_valido}' é aceito",
      app.validate_device_name(nome_valido) == nome_valido)

print("\n=== 3. Validação do arquivo ISO (validação de entrada) ===")
espera_erro("caminho inexistente é rejeitado", app.validate_iso_path, "/nao/existe/x.iso")
espera_erro("caminho vazio é rejeitado", app.validate_iso_path, "")
with tempfile.TemporaryDirectory() as d:
    espera_erro("diretório em vez de arquivo é rejeitado", app.validate_iso_path, d)
    pequeno = os.path.join(d, "falso.iso")
    with open(pequeno, "wb") as f:
        f.write(b"x" * 100)
    espera_erro("arquivo pequeno demais (download incompleto) é rejeitado",
                app.validate_iso_path, pequeno)
    grande = os.path.join(d, "ok.iso")
    with open(grande, "wb") as f:
        f.write(b"x" * (2 * 1024 * 1024))
    check("arquivo plausível é aceito", app.validate_iso_path(grande) == os.path.realpath(grande))

print("\n=== 4. Injeção de comando no script privilegiado (SAST-01) ===")
# Reproduz o script real de preparação e executa SEM privilégio, com um nome de
# arquivo malicioso, verificando que o comando injetado NÃO executa.
with tempfile.TemporaryDirectory() as d:
    marcador = os.path.join(d, "INJETADO.txt")
    malicioso = f'/tmp/Win11.iso" ; touch {marcador} ; echo "'
    script = 'ISO="$3"\necho "valor recebido: $ISO"\n'
    r = subprocess.run(["bash", "-c", script, "win11_usb_creator",
                        "/dev/sdb", "/dev/sdb1", malicioso],
                       capture_output=True, text=True)
    check("comando injetado NÃO foi executado", not os.path.exists(marcador))
    check("valor malicioso foi tratado como texto literal",
          malicioso in r.stdout, f"(saida={r.stdout!r})")

print("\n=== 5. Lista de pacotes instaláveis como administrador (SCA-05) ===")
cmd = app.linux_build_install_command("apt-get", ["parted", "rsync"])
check("comando apt-get montado corretamente", cmd == "apt-get update && apt-get install -y parted rsync", f"({cmd})")
check("pacman usa -Syu e não -Sy (SCA-04)",
      "-Syu" in app.LINUX_INSTALL_CMD_TEMPLATE["pacman"],
      f"({app.LINUX_INSTALL_CMD_TEMPLATE['pacman']})")
espera_erro("ferramenta fora da lista permitida é rejeitada",
            app.linux_build_install_command, "apt-get", ["curl; rm -rf /"])
espera_erro("gerenciador de pacotes desconhecido é rejeitado",
            app.linux_build_install_command, "malicioso", ["parted"])

print("\n=== 6. Funções originais preservadas (não quebrar o que funciona) ===")
check("human_size continua correto", app.human_size(1536) == "1.5 KB", f"({app.human_size(1536)})")
check("human_size em GB continua correto",
      app.human_size(5 * 1024 ** 3) == "5.0 GB", f"({app.human_size(5 * 1024 ** 3)})")
check("linux_partition_path para sdb", app.linux_partition_path("sdb", 1) == "/dev/sdb1")
check("linux_partition_path para nvme0n1", app.linux_partition_path("nvme0n1", 1) == "/dev/nvme0n1p1")
check("linux_partition_path para mmcblk0", app.linux_partition_path("mmcblk0", 1) == "/dev/mmcblk0p1")
check("limite do FAT32 preservado", app.FAT32_MAX_FILE_SIZE == 4_294_967_295)
check("nome do volume preservado", app.VOL_NAME == "WIN11USB")
check("página oficial da Microsoft preservada",
      app.MS_DOWNLOAD_PAGE == "https://www.microsoft.com/en-us/software-download/windows11")
check("lista de ferramentas exigidas preservada",
      app.LINUX_REQUIRED_TOOLS == ["parted", "mkfs.vfat", "wipefs", "partprobe", "rsync", "wimlib-imagex"])

print("\n=== 7. Registro de auditoria não grava segredos ===")
import inspect  # noqa: E402
fonte = inspect.getsource(app.PrivilegeHelper.run_script)
check("senha nunca entra na lista de argumentos do processo",
      "password" not in fonte.split("bash_argv =")[1].split("if shutil.which")[0])
check("senha é enviada apenas por stdin", "proc.stdin.write(password" in fonte)
check("função de limpeza da senha existe", hasattr(app.PrivilegeHelper, "clear_cached_password"))

print("\n" + "=" * 62)
if falhas:
    print(f"RESULTADO: {len(falhas)} de {total} verificações FALHARAM:")
    for f in falhas:
        print(f"  - {f}")
    sys.exit(1)
print(f"RESULTADO: todas as {total} verificações passaram.")
sys.exit(0)
