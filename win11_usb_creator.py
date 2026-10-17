#!/usr/bin/env python3
#
# EPMA USB CREATOR
# Copyright (C) 2026 EPMA
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
EPMA USB CREATOR: creates verified bootable USB drives from Windows 11, Linux and
other ISOs, and Google's ChromeOS Flex, on macOS and any Linux distro (GUI and
command line). Windows 11 gets a UEFI GPT + FAT32 drive; Linux, other hybrid ISOs
and ChromeOS Flex are written byte for byte. Every write is read back and verified.

macOS requirements:
  brew install python-tk@<version matching your Python, e.g. 3.15> wimlib

Linux requirements (package names vary by distro; the app can install them
for you via apt/dnf/yum/pacman/zypper/apk):
  parted, dosfstools (mkfs.vfat), util-linux (wipefs/mount/umount/lsblk),
  rsync, wimlib (wimlib-imagex) and python3-tk for the GUI itself.

wimlib-imagex is required for Windows 11 because install.wim/install.esd
usually exceeds 4 GB, the FAT32 file size limit — the script splits the
file automatically when that happens.

Writing a drive needs root on Linux (and on macOS for the byte-for-byte
modes), so the app asks for your sudo password (or uses pkexec if sudo isn't
available) once per operation, before the drive is touched. The password is
checked once and normally dropped: sudo's own credential timestamp carries the
operation. If the machine does not keep that timestamp, the password stays in
memory only until the operation ends and is passed to sudo on stdin. It is
never logged, written to disk or sent anywhere.
"""

import argparse
import atexit
import collections
import contextlib
import errno
import filecmp
import hashlib
import http.client
import json
import logging
import logging.handlers
import os
import pathlib
import platform
import plistlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
import zipfile
import zlib

# Tkinter is needed by the GUI only. The engine and the command line interface work
# without it, so a missing Tk is remembered here instead of ending the program at
# import time; main() prints the hint when the GUI is requested.
if platform.system() == "Darwin":
    TK_MISSING_MESSAGE = (
        "Tkinter is not available for this Python installation.\n"
        "Install it with: brew install python-tk@<version matching your python>"
    )
else:
    TK_MISSING_MESSAGE = (
        "Tkinter is not available for this Python installation.\n"
        "Install it with your package manager, e.g.:\n"
        "  Debian/Ubuntu: sudo apt install python3-tk\n"
        "  Fedora:        sudo dnf install python3-tkinter\n"
        "  Arch:          sudo pacman -S tk\n"
        "  openSUSE:      sudo zypper install python3-tk"
    )
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    from tkinter import font as tkfont
except ImportError:
    tk = ttk = filedialog = messagebox = tkfont = None

__version__ = "1.1.0"

IS_MAC = platform.system() == "Darwin"
IS_LINUX = platform.system() == "Linux"

APP_NAME = "epma-usb-creator"  # shown in the macOS menu bar / Dock and used as the Linux window class
# The one-sentence description of the product: README, the Help > About text and the command
# line --help all use it (the module docstring, the Homebrew formula and the SBOM repeat it;
# tests/test_docs_consistency.py keeps them in step).
APP_TAGLINE = "Create verified bootable USB drives from Windows 11, Linux and other ISOs, and Google's ChromeOS Flex"

MS_DOWNLOAD_PAGE = "https://www.microsoft.com/en-us/software-download/windows11"
PROJECT_URL = "https://github.com/1985epma/epma-windows-usb-creator"

# ChromeOS Flex is Google's free ChromeOS for PCs and Macs. Regular ChromeOS is not
# distributed for generic computers, so Flex is the official image this tool offers.
# URLs: https://support.google.com/chromeosflex/answer/11541904 (download and install) and
# https://support.google.com/chromeosflex/answer/11552529 (requirements).
CHROMEOS_FLEX_URL = "https://dl.google.com/chromeos-flex/images/latest.bin.zip"
# The official address redirects to a versioned file on the same host; any other host is refused.
CHROMEOS_FLEX_HOSTS = ("dl.google.com",)
# Measured on the real files (2026-10): the ZIP is about 1.4 GB and the image inside it about 9.5 GB.
# Downloading and extracting needs both on disk at once, so warn below this much free space.
CHROMEOS_FLEX_FREE_BYTES = 12_000_000_000
CHROMEOS_FLEX_GUIDE_URL = "https://support.google.com/chromeosflex/answer/11541904"
CHROMEOS_FLEX_REQUIREMENTS_URL = "https://support.google.com/chromeosflex/answer/11552529"
# Google asks for a USB drive of "16 GB or larger". Drives sold as 16 GB hold about 15.5e9
# bytes, so this is the point below which the user is warned.
CHROMEOS_MIN_USB_BYTES = 15_000_000_000
DISK_IMAGE_MAX_BYTES = 64 * 1024 ** 3      # an image larger than this is not a plausible ChromeOS image
FAT32_MAX_FILE_SIZE = 4_294_967_295  # 4GB - 1 byte
CHUNK_SIZE = 1024 * 1024
MIN_IMAGE_BYTES = 1024 * 1024  # a file smaller than this cannot be a disk image or an ISO
VOL_NAME = "WIN11USB"

# What kind of image is being written.
#   windows: format GPT + FAT32 and copy the ISO contents (splitting install.wim)
#   linux:   write the ISO byte-for-byte to the drive (hybrid ISO, like `dd`)
MODE_WINDOWS = "windows"
MODE_LINUX = "linux"
MODE_CHROMEOS = "chromeos"
ALL_MODES = (MODE_WINDOWS, MODE_LINUX, MODE_CHROMEOS)
# Image types that are written byte for byte to the whole drive (no partitioning, no copying).
RAW_MODES = (MODE_LINUX, MODE_CHROMEOS)
MODE_AUTO = "auto"  # command line only: take the mode from what detect_iso_kind() finds in the image
MODE_SEED = "seed"  # a drive that carries only the hardening seed files (no operating system image)
HARDENING_NONE = "none"
HARDENING_BASELINE = "baseline"
HARDENING_PROFILES = (HARDENING_NONE, HARDENING_BASELINE)
SEED_UBUNTU, SEED_FEDORA, SEED_DEBIAN = "ubuntu", "fedora", "debian"
SEED_TARGETS = (SEED_UBUNTU, SEED_FEDORA, SEED_DEBIAN)

# What detect_iso_kind() finds in an image. The strings are what `detect` prints; KIND_MODE says which
# mode writes each kind (the two sets of names are kept apart on purpose, whatever their spelling).
ISO_KIND_WINDOWS = "windows"
ISO_KIND_LINUX = "linux"
ISO_KIND_CHROMEOS = "chromeos"
ISO_KIND_UNKNOWN = "unknown"
KIND_UNKNOWN = ISO_KIND_UNKNOWN
KIND_MODE = {ISO_KIND_WINDOWS: MODE_WINDOWS, ISO_KIND_LINUX: MODE_LINUX, ISO_KIND_CHROMEOS: MODE_CHROMEOS}

# The four choices at the top of the window ("cards"), and how each one writes the drive.
CARD_CHROME, CARD_WINDOWS, CARD_LINUX, CARD_OTHER = "chrome", "windows", "linux", "other"
CARD_ORDER = (CARD_CHROME, CARD_WINDOWS, CARD_LINUX, CARD_OTHER)
CARD_MODE = {CARD_CHROME: MODE_CHROMEOS, CARD_WINDOWS: MODE_WINDOWS, CARD_LINUX: MODE_LINUX, CARD_OTHER: MODE_LINUX}
# The card a detected image selects (a hybrid image keeps "Other ISO" when that one is already chosen).
KIND_CARD = {ISO_KIND_CHROMEOS: CARD_CHROME, ISO_KIND_WINDOWS: CARD_WINDOWS, ISO_KIND_LINUX: CARD_LINUX}
LOG_MAX_LINES = 5000   # the on-screen log keeps only this many lines
LOG_FLUSH_MS = 100     # worker log lines are queued and written to the log box this often
AUTO_REFRESH_MIN_SECONDS = 3.0  # the drive list is not re-read more often than this when the window regains focus
PROGRESS_UI_INTERVAL = 0.2      # the write progress bar redraws at most this often (~5 times a second)
SHA_UI_INTERVAL = 0.1           # ... and the SHA-256 panel this often (~10 times a second)
VERIFY_PROGRESS_INTERVAL = 0.5  # seconds between the progress updates of the read-back verification
DD_LOG_INTERVAL = 5.0           # dd's frequent byte-count lines reach the log at most this often
PANEL_WRAP = 720                # wrap width (pixels) of the explanatory texts in the window
MBR_SIGNATURE = b"\x55\xaa"  # the last two bytes of the first sector of an image that can boot from USB
MBR_SIGNATURE_OFFSET = 510
VERIFY_CHUNK = 16 * 1024 * 1024  # bytes compared per step when reading a raw write back
RAW_WRITE_BLOCK = {"mac": "4m", "linux": "4M"}  # BSD dd and GNU dd spell the unit differently

LINUX_REQUIRED_TOOLS = ["parted", "mkfs.vfat", "wipefs", "partprobe", "rsync", "wimlib-imagex"]
# Package that provides each tool, for every package manager. Most names are the same everywhere; the
# managers differ only in the package for wimlib-imagex (and Alpine's wipefs). tests/e2e/distro_probe.py
# checks these names against the real distributions with its own, independent table.
_LINUX_PKG_COMMON = {"parted": "parted", "mkfs.vfat": "dosfstools", "wipefs": "util-linux",
                     "partprobe": "parted", "rsync": "rsync"}
LINUX_PKG_MAP = {
    "apt-get": {**_LINUX_PKG_COMMON, "wimlib-imagex": "wimtools"},
    "dnf":     {**_LINUX_PKG_COMMON, "wimlib-imagex": "wimlib-utils"},
    "yum":     {**_LINUX_PKG_COMMON, "wimlib-imagex": "wimlib-utils"},
    "pacman":  {**_LINUX_PKG_COMMON, "wimlib-imagex": "wimlib"},
    "zypper":  {**_LINUX_PKG_COMMON, "wimlib-imagex": "wimlib"},
    "apk":     {**_LINUX_PKG_COMMON, "wipefs": "util-linux-misc", "wimlib-imagex": "wimlib"},
}
LINUX_INSTALL_CMD_TEMPLATE = {
    "apt-get": "apt-get update && apt-get install -y {pkgs}",
    "dnf": "dnf install -y {pkgs}",
    "yum": "yum install -y {pkgs}",
    # -Syu (not -Sy): a partial upgrade is explicitly unsupported on Arch and can
    # leave the user's system in a broken state.
    "pacman": "pacman -Syu --noconfirm {pkgs}",
    "zypper": "zypper --non-interactive install {pkgs}",
    "apk": "apk add {pkgs}",
}

# ---- Security configuration (overridable via environment variables) ----
# Download URLs must use HTTPS and, unless the user opts out, come from a
# Microsoft-controlled host. See SECURITY.md.
ALLOWED_URL_SCHEMES = ("https",)
DEFAULT_TRUSTED_ISO_HOSTS = (
    "microsoft.com",
    "www.microsoft.com",
    "software-download.microsoft.com",
    "software.download.prss.microsoft.com",
    "download.microsoft.com",
)
ENV_TRUSTED_HOSTS = "WIN11USB_TRUSTED_ISO_HOSTS"
ENV_AUDIT_LOG = "WIN11USB_AUDIT_LOG"
ENV_DISABLE_AUDIT_LOG = "WIN11USB_DISABLE_AUDIT_LOG"
ENV_ALLOW_ANY_HOST = "WIN11USB_ALLOW_ANY_DOWNLOAD_HOST"
ENV_EXPECTED_SHA256 = "WIN11USB_EXPECTED_SHA256"

DOWNLOAD_TIMEOUT_SECONDS = 60  # per network read; prevents an indefinite hang
DOWNLOAD_MAX_ATTEMPTS = 3      # transient network errors are retried (resuming where possible)
DOWNLOAD_BACKOFF_SECONDS = (2, 5)  # wait before retry 2 and 3
QUERY_TIMEOUT = 30             # seconds allowed for quick query commands (diskutil list, lsblk, ...)
DISKUTIL_TIMEOUT = 120         # seconds allowed for macOS unmount, mount, eject and detach commands
IOREG_TIMEOUT = 10             # seconds for `ioreg`: it only adds the USB serial number, so it must not stall the list
SUDO_KEEPALIVE_SECONDS = 60    # how often the sudo timestamp is refreshed while an operation runs
SUDO_TIMEOUT = QUERY_TIMEOUT   # seconds allowed for the sudo password check and the timestamp refresh
SUDO_KEEPALIVE_MAX_SECONDS = 6 * 3600  # the keep-alive never outlives this, whatever happens
AUDIT_LOG_MAX_BYTES = 1_000_000
AUDIT_LOG_BACKUPS = 5
RAW_CANCELED_MARKER = "WRITE_CANCELED"  # printed by the root write scripts when they stop on request
DIRECT_IO_ALIGNMENT = 4096     # oflag=direct on Linux only when the image size is a multiple of this
PRIVATE_FILE_MODE = 0o600      # owner-only read/write for files we create
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)  # never follow a symlink planted at a temp/part file path
SLEEP_INHIBIT_SECONDS = 12 * 3600  # the Linux sleep inhibitor is bounded, so it can never leak for good
SLEEP_INHIBIT_CHECK_SECONDS = 0.3  # how long to wait to see that the inhibitor really started
# A write error that retrying cannot fix (and that must not be mistaken for a network problem).
DOWNLOAD_FATAL_ERRNOS = tuple(getattr(errno, n) for n in ("ENOSPC", "EDQUOT", "EROFS", "EACCES", "EPERM")
                              if hasattr(errno, n))

# Device identifiers we are willing to pass to privileged commands. Anything
# outside this shape is rejected rather than escaped: there is no legitimate
# disk name with spaces, quotes or shell metacharacters.
MAC_DEVICE_RE = re.compile(r"^disk[0-9]+$")
LINUX_DEVICE_RE = re.compile(r"^[a-zA-Z0-9_+-]{1,32}$")

# Mount points that must never live on a disk we are about to erase.
CRITICAL_MOUNTPOINTS = ("/", "/boot", "/boot/efi", "/home", "/usr", "/var", "/etc")

_audit_logger = None


# ============================================================
# Internationalization (GUI only)
#
# English is the default and the source language. Brazilian Portuguese is looked up in
# PT_BR (english text -> portuguese text); an unknown text falls back to the English one,
# so a missing translation can never break the program. Only text the GUI shows to the
# user goes through _(): engine and CLI output, exception messages, the audit log, shell
# scripts and anything code or tests match by substring stay in English on purpose.
# Placeholders use str.format syntax and must be identical in both languages:
# translate first, then format:  _("Hello {name}").format(name=name)
# Portuguese is used only when EPMA_LANG=pt is set; the system locale (LC_ALL / LANG) is never consulted.
# ============================================================
ENV_LANG = "EPMA_LANG"
LANG_EN = "en"
LANG_PT = "pt"


def detect_language(env=None):
    """"en" (US English) unless Portuguese is requested explicitly. `env` defaults to os.environ.

    The interface is always in English. The system locale (LANG, LC_*) is deliberately NOT
    consulted: only EPMA_LANG=pt (or pt-BR, case-insensitive) switches the window to
    Brazilian Portuguese. Any other value, or none, means English.
    """
    env = os.environ if env is None else env
    forced = (env.get(ENV_LANG) or "").strip()
    return LANG_PT if forced.lower().startswith("pt") else LANG_EN


ACTIVE_LANGUAGE = detect_language()  # decided once, at import

PT_BR = {
    # ----- image sources and download -----
    "Open Microsoft's official page": "Abrir a página oficial da Microsoft",
    "Direct ISO link (HTTPS only):": "Link direto da ISO (somente HTTPS):",
    "Download ISO": "Baixar a ISO",
    "Cancel": "Cancelar",
    "OK": "OK",
    "Select existing ISO file...": "Selecionar um arquivo ISO existente...",
    "No ISO selected yet.": "Nenhuma ISO selecionada ainda.",
    "ISO image": "Imagem ISO",
    "Save ISO as": "Salvar a ISO como",
    "Image type": "Tipo de imagem",
    "Image": "Imagem",
    "USB drive": "Unidade USB",
    "Unknown": "Desconhecido",
    "{done} / {total} ({pct:.1f}%) — {speed}/s — {eta}":
        "{done} / {total} ({pct:.1f}%) — {speed}/s — {eta}",
    "~{minutes}m{seconds:02d}s left": "faltam ~{minutes}m{seconds:02d}s",
    "calculating...": "calculando...",
    "{done} downloaded — {speed}/s": "{done} baixados — {speed}/s",
    "Download complete.": "Download concluído.",
    "Download failed.": "O download falhou.",
    "Download error": "Erro no download",
    "Invalid link": "Link inválido",
    "Invalid checksum": "Checksum inválido",
    "A SHA-256 checksum must be exactly 64 characters using only 0-9 and a-f.\n\n"
    "Leave the field empty if you do not have one.":
        "Um checksum SHA-256 deve ter exatamente 64 caracteres, usando apenas 0-9 e a-f.\n\n"
        "Deixe o campo vazio se você não tiver um.",
    "Unrecognised download server": "Servidor de download não reconhecido",
    "This link points to '{host}', which is not a known Microsoft download server.\n\n"
    "Downloading a Windows image from an unofficial source is a real risk: a tampered "
    "image would install a compromised Windows on the target computer, and you would "
    "have no way of noticing.\n\n"
    "Continue anyway?":
        "Este link aponta para '{host}', que não é um servidor de download conhecido da Microsoft.\n\n"
        "Baixar uma imagem do Windows de uma fonte não oficial é um risco real: uma imagem "
        "adulterada instalaria um Windows comprometido no computador de destino, e você "
        "não teria como perceber.\n\n"
        "Continuar mesmo assim?",
    "Done": "Concluído",
    "The SHA-256 checksum matches the value you supplied — the file is intact.":
        "O checksum SHA-256 confere com o valor informado — o arquivo está íntegro.",
    "SHA-256 of this file:\n{sha256}\n\n"
    "No checksum was supplied, so authenticity was NOT verified. If Microsoft "
    "publishes a checksum for this image, compare it with the value above before "
    "writing the USB drive.":
        "SHA-256 deste arquivo:\n{sha256}\n\n"
        "Nenhum checksum foi informado, então a autenticidade NÃO foi verificada. Se a Microsoft "
        "publicar um checksum para esta imagem, compare-o com o valor acima antes de "
        "gravar o pendrive.",
    "ISO downloaded to:\n{path}": "ISO baixada em:\n{path}",
    "SHA-256 of the downloaded file: {sha256}": "SHA-256 do arquivo baixado: {sha256}",
    "Image type preselected {how}: {image}.": "Tipo de imagem pré-selecionado {how}: {image}.",
    "from the content of the ISO": "pelo conteúdo da ISO",
    "Linux / other hybrid ISO": "Linux / outra ISO híbrida",

    # ----- ISO SHA-256 panel -----
    "Calculate SHA-256": "Calcular o SHA-256",
    "Select an ISO file first.": "Selecione um arquivo ISO primeiro.",
    "Calculating...": "Calculando...",
    "Calculating... {pct:.0f}% ({done} / {total})": "Calculando... {pct:.0f}% ({done} / {total})",
    "Calculating SHA-256 of {name}...": "Calculando o SHA-256 de {name}...",
    "SHA-256: {digest}": "SHA-256: {digest}",
    "SHA-256 of {name}: {digest}": "SHA-256 de {name}: {digest}",
    "Expected SHA-256: {expected}": "SHA-256 esperado: {expected}",
    "No expected checksum given: compare the value above yourself.":
        "Nenhum checksum esperado foi informado: compare o valor acima por conta própria.",
    "MATCH — the file is intact and identical to the published one.":
        "CONFERE — o arquivo está íntegro e idêntico ao publicado.",
    "MISMATCH — this is NOT the published file. Do not use it.":
        "NÃO CONFERE — este NÃO é o arquivo publicado. Não use este arquivo.",
    "Checksum comparison: {outcome}": "Comparação do checksum: {outcome}",
    "UNVERIFIED": "NÃO VERIFICADO",
    "MATCH": "CONFERE",
    "MISMATCH": "NÃO CONFERE",
    "Could not read the file ({reason}).": "Não foi possível ler o arquivo ({reason}).",

    # ----- the drive and the Create button -----
    "● Ready": "● Pronto",
    "● Missing tools": "● Faltam ferramentas",
    "Dismiss": "Fechar",
    "Try again": "Tentar de novo",
    "Make another": "Criar outro",
    "Install missing dependencies": "Instalar as dependências que faltam",
    "Refresh USB drives list": "Atualizar a lista de pendrives",
    "USB": "USB",
    "No USB drive found": "Nenhum pendrive USB encontrado",
    "Plug in a USB drive (8 GB or more) and it will appear here.": "Conecte um pendrive USB (de 8 GB ou mais) e ele aparecerá aqui.",
    "contents unknown": "conteúdo desconhecido",
    "no volumes": "sem volumes",
    "1 volume ({names})": "1 volume ({names})",
    "{count} volumes ({names})": "{count} volumes ({names})",
    "Could not list disks: {error}": "Não foi possível listar os discos: {error}",
    "Create Bootable USB Drive": "Criar o pendrive bootável",

    # ----- confirmations and creation -----
    "Windows 11": "Windows 11",
    "the selected Linux image": "a imagem Linux selecionada",
    "This will PERMANENTLY ERASE all data on /dev/{id} and write {what} to it.":
        "Isto vai APAGAR PERMANENTEMENTE todos os dados de /dev/{id} e gravar {what} nele.",
    "Confirm erasing this drive": "Confirmar o apagamento desta unidade",
    "Final confirmation": "Confirmação final",
    "Continue?": "Continuar?",
    "Drive: /dev/{id}": "Unidade: /dev/{id}",
    "Model: {model}": "Modelo: {model}",
    "Size: {size}": "Tamanho: {size}",
    "Contents: could not be read": "Conteúdo: não foi possível ler",
    "Contents: no volumes found (the drive looks empty)": "Conteúdo: nenhum volume encontrado (a unidade parece vazia)",
    "Contents that will be DESTROYED:": "Conteúdo que será DESTRUÍDO:",
    "  - ... and {count} more": "  - ... e mais {count}",
    "{size} used": "{size} usados",
    "not mounted, usage unknown": "não montado, uso desconhecido",
    "(unnamed)": "(sem nome)",
    "This drive does not look like a spare USB stick:": "Esta unidade não parece um pendrive sobressalente:",
    "It is large ({size}); installer sticks are usually much smaller. "
    "This may be an external hard disk or SSD.":
        "Ela é grande ({size}); pendrives de instalação costumam ser bem menores. "
        "Pode ser um HD ou SSD externo.",
    "Its model name ({model}) suggests an external hard disk or SSD.":
        "O nome do modelo ({model}) sugere um HD ou SSD externo.",
    "What is stored on it could not be read, so there is no way to tell what would be lost.":
        "Não foi possível ler o que está gravado nela, então não há como saber o que seria perdido.",
    "It holds a lot of data ({size} in use).": "Ela guarda muitos dados ({size} em uso).",
    "Volume name(s) suggest personal data or backups: {names}.":
        "O(s) nome(s) de volume sugere(m) dados pessoais ou backups: {names}.",
    "It has {count} volumes, which is unusual for a USB stick.":
        "Ela tem {count} volumes, o que é incomum para um pendrive.",
    "To confirm, type the drive identifier exactly as shown ({expected}):":
        "Para confirmar, digite o identificador da unidade exatamente como aparece ({expected}):",
    "Erase this drive": "Apagar esta unidade",
    "Administrator access is required to write /dev/{id}.":
        "É necessário acesso de administrador para gravar em /dev/{id}.",
    "Canceled: administrator password was not provided. The drive was not modified.":
        "Cancelado: a senha de administrador não foi informada. A unidade não foi modificada.",
    "It was verified against the ISO and ejected — you can unplug it now.":
        "Ele foi verificado em relação à ISO e ejetado — já pode ser removido.",
    "It was verified against the ISO, but could not be ejected automatically. "
    "Eject it from the file manager before unplugging.":
        "Ele foi verificado em relação à ISO, mas não pôde ser ejetado automaticamente. "
        "Ejete-o pelo gerenciador de arquivos antes de removê-lo.",
    "Bootable USB drive created successfully!": "Pendrive bootável criado com sucesso!",
    "Canceled": "Cancelado",
    "The operation was canceled.\n\nThe USB drive was left incomplete and unusable. "
    "Create it again before using it.":
        "A operação foi cancelada.\n\nO pendrive ficou incompleto e inutilizável. "
        "Crie-o novamente antes de usá-lo.",
    "Canceled. The drive was left unusable; create it again before use.":
        "Cancelado. A unidade ficou inutilizável; crie-a novamente antes de usar.",
    "Cancel the operation?": "Cancelar a operação?",
    "Canceling now will leave the USB drive incomplete and UNUSABLE until it is created "
    "again.\n\nDo you really want to cancel?":
        "Cancelar agora deixará o pendrive incompleto e INUTILIZÁVEL até que ele seja criado "
        "novamente.\n\nDeseja mesmo cancelar?",
    "Cancel requested: stopping safely...": "Cancelamento solicitado: parando com segurança...",

    # ----- progress -----
    "Preparing the drive...": "Preparando a unidade...",
    "Writing the image...": "Gravando a imagem...",
    "Verifying the written image...": "Verificando a imagem gravada...",
    "Verifying the copied files...": "Verificando os arquivos copiados...",
    "Verifying the install image...": "Verificando a imagem de instalação...",
    "Copying files...": "Copiando os arquivos...",
    "Copying the install image...": "Copiando a imagem de instalação...",
    "Hashing the ISO...": "Calculando o hash da ISO...",
    "Splitting the install image...": "Dividindo a imagem de instalação...",
    "Flushing data to the drive...": "Gravando os dados pendentes na unidade...",
    "Adding hardening files...": "Adicionando os arquivos de proteção...",
    "Written": "Gravado",
    "{stage} (this can take a few minutes)": "{stage} (isto pode levar alguns minutos)",
    " — calculating...": " — calculando...",
    "Done — 100%": "Concluído — 100%",
    "Canceled.": "Cancelado.",
    "Failed.": "Falhou.",

    # ----- administrator password and errors -----
    "Administrator password": "Senha de administrador",
    "That password was not accepted. Try again.\n\n": "Essa senha não foi aceita. Tente novamente.\n\n",
    "Enter your sudo/administrator password to partition and format the drive.\n"
    "It is used only to run local disk commands and is never stored or sent anywhere.":
        "Digite a sua senha de administrador (sudo) para particionar e formatar a unidade.\n"
        "Ela é usada apenas para executar comandos de disco locais e nunca é guardada nem enviada a lugar nenhum.",
    "{reason}\n\nEnter your administrator (sudo) password.\n"
    "It is used only to run local disk commands and is never stored or sent anywhere.":
        "{reason}\n\nDigite a sua senha de administrador (sudo).\n"
        "Ela é usada apenas para executar comandos de disco locais e nunca é guardada nem enviada a lugar nenhum.",
    "Wrong password": "Senha incorreta",
    "That password was not accepted. Please try again.": "Essa senha não foi aceita. Tente novamente.",
    "Too many incorrect attempts. Nothing was changed.": "Muitas tentativas incorretas. Nada foi alterado.",
    "Error": "Erro",
    "Unexpected error": "Erro inesperado",
    "The operation could not be completed.\n\nReason: {reason}\n\n"
    "The full technical detail was written to the log box below and to the "
    "audit log at:\n{path}":
        "Não foi possível concluir a operação.\n\nMotivo: {reason}\n\n"
        "O detalhe técnico completo foi gravado na caixa de log abaixo e no "
        "log de auditoria em:\n{path}",
    "EPMA USB CREATOR Help": "Ajuda do EPMA USB CREATOR",
    "Open the audit log folder": "Abrir a pasta do log de auditoria",
    "Project page (GitHub)": "Página do projeto (GitHub)",
    "About EPMA USB CREATOR": "Sobre o EPMA USB CREATOR",
    "Help": "Ajuda",
    "Close": "Fechar",
    "Audit log": "Log de auditoria",
    "Could not open the folder: {reason}": "Não foi possível abrir a pasta: {reason}",
    "ChromeOS Flex is ready": "O ChromeOS Flex está pronto",
    "ChromeOS Flex": "ChromeOS Flex",
    "Download ChromeOS Flex from Google": "Baixar o ChromeOS Flex do Google",
    "Select an ISO or disk image": "Selecione uma ISO ou imagem de disco",
    "Download ChromeOS Flex": "Baixar o ChromeOS Flex",
    "Save ChromeOS Flex as": "Salvar o ChromeOS Flex como",
    "Extracting...": "Extraindo...",
    "Ready.": "Pronto.",
    "The selected image is not a ChromeOS Flex disk image:\n{path}\n\nDownload it with the button above, or select the .bin file from Google's latest.bin.zip.": "A imagem selecionada não é uma imagem de disco do ChromeOS Flex:\n{path}\n\nBaixe-a com o botão acima, ou selecione o arquivo .bin do latest.bin.zip do Google.",
    "Drive too small": "Pendrive pequeno demais",
    "Small USB drive": "Pendrive pequeno",
    "Google's installation guide": "Guia de instalação do Google",
    "Google's requirements page": "Página de requisitos do Google",
    "ISO and disk images": "Imagens ISO e de disco",
    "All files": "Todos os arquivos",
    "ChromeOS Flex is provided by Google and is subject to Google's own terms.\n\nThis program only downloads Google's official image from its servers (dl.google.com) over HTTPS and prepares it for your USB drive. Google's installation guide: {url}\n\nDownload it now?": "O ChromeOS Flex é fornecido pelo Google e está sujeito aos termos do próprio Google.\n\nEste programa apenas baixa a imagem oficial dos servidores do Google (dl.google.com) por HTTPS e a prepara para o seu pendrive. Guia de instalação do Google: {url}\n\nBaixar agora?",
    "ZIP archive": "Arquivo ZIP",
    "The image ({image}) is larger than this drive ({drive}). Choose a bigger drive. Nothing was changed.": "A imagem ({image}) é maior que este pendrive ({drive}). Escolha um pendrive maior. Nada foi alterado.",
    "Google asks for a USB drive of 16 GB or larger for ChromeOS Flex, and this one is {size}. It may not work as an installer.\n\nContinue anyway?": "O Google pede um pendrive de 16 GB ou maior para o ChromeOS Flex, e este tem {size}. Ele pode não funcionar como instalador.\n\nContinuar mesmo assim?",
    "Downloading...": "Baixando...",
    "Canceled during verification. The image was written but NOT verified; do not rely on this drive.": "Cancelado durante a verificação. A imagem foi gravada mas NÃO foi verificada; não confie neste pendrive.",
    "The operation was canceled during verification.\n\nThe image was written to the drive but NOT verified, so do not rely on it. Create it again to verify it.": "A operação foi cancelada durante a verificação.\n\nA imagem foi gravada no pendrive mas NÃO foi verificada, então não confie nele. Crie-o de novo para verificá-lo.",
    "Choose the image file first (\"Select existing ISO file...\" or the download above).": "Escolha primeiro o arquivo da imagem (\"Select existing ISO file...\" ou o download acima).",
    "No USB drive found. Plug it in and click \"Refresh USB drives list\".": "Nenhum pendrive USB encontrado. Conecte-o e clique em \"Refresh USB drives list\".",
    "Select a USB drive in the list.": "Selecione um pendrive USB na lista.",
    "WARNING: ALL DATA on the selected drive will be PERMANENTLY erased.": "AVISO: TODOS OS DADOS do pendrive selecionado serão apagados PERMANENTEMENTE.",
    "Google Chrome": "Google Chrome",
    "Copies the files": "Copia os arquivos",
    "Linux": "Linux",
    "Ubuntu, Fedora...": "Ubuntu, Fedora...",
    "Other ISO": "Outra ISO",
    "Any bootable image": "Qualquer imagem de boot",
    "Verify the selected ISO (SHA-256)": "Verificar a ISO selecionada (SHA-256)",
    "Paste the published hash or SHA256SUMS line, then calculate": "Cole o hash publicado ou a linha do SHA256SUMS e calcule",
    "Show details": "Mostrar detalhes",
    "Hide details": "Ocultar detalhes",
    "a Linux image": "uma imagem Linux",
    "a ChromeOS image": "uma imagem ChromeOS",
    "This does not look like Windows": "Isto não parece ser Windows",
    "The disk image is ready:\n{path}\n\nNext: plug in a USB drive of 16 GB or larger, click \"Refresh USB drives list\", select the drive and click \"Create Bootable USB Drive\".": "A imagem de disco está pronta:\n{path}\n\nPróximo passo: conecte um pendrive de 16 GB ou maior, clique em \"Refresh USB drives list\", selecione o pendrive e clique em \"Create Bootable USB Drive\".",
    "ChromeOS Flex is Google's free version of ChromeOS for PCs and Macs. Google does not publish regular ChromeOS for ordinary computers. It needs a USB drive of 16 GB or larger; the computer you install it on needs an Intel or AMD 64-bit processor, 4 GB of RAM and 16 GB of storage, and Google only guarantees certified models.": "O ChromeOS Flex é a versão gratuita do ChromeOS do Google para PCs e Macs. O Google não publica o ChromeOS comum para computadores em geral. Precisa de um pendrive de 16 GB ou maior; o computador onde você instala precisa de processador Intel ou AMD de 64 bits, 4 GB de RAM e 16 GB de armazenamento, e o Google só garante modelos certificados.",
    "Microsoft only gives out the direct ISO link after you choose the edition and language: open the official page, pick 'Windows 11 (multi-edition ISO)', right-click the blue 64-bit button, choose 'Copy Link Address' (do NOT click it) and paste the link here.": "A Microsoft só libera o link direto da ISO depois que você escolhe a edição e o idioma: abra a página oficial, escolha 'Windows 11 (ISO de várias edições)', clique com o botão direito no botão azul de 64 bits, escolha 'Copiar endereço do link' (NÃO clique nele) e cole o link aqui.",
    "Expected SHA-256 (optional):": "SHA-256 esperado (opcional):",
    "Download the ISO from your distribution's website (Ubuntu, Debian, Fedora, Mint, Arch...), then choose the file below. It is written to the drive as it is, so it must be a hybrid image; all current Linux ISOs are. Check its SHA-256 below if the site publishes one.": "Baixe a ISO no site da sua distribuição (Ubuntu, Debian, Fedora, Mint, Arch...) e escolha o arquivo abaixo. Ela é gravada no pendrive como está, então precisa ser uma imagem híbrida; todas as ISOs Linux atuais são. Confira o SHA-256 abaixo se o site publicar um.",
    "Any bootable hybrid ISO or disk image is written to the drive exactly as it is. Choose the file below. Images that cannot boot from a USB drive are refused before anything is erased.": "Qualquer ISO híbrida de boot ou imagem de disco é gravada no pendrive exatamente como está. Escolha o arquivo abaixo. Imagens que não conseguem iniciar por USB são recusadas antes de apagar qualquer coisa.",
    "Already downloaded the image (ISO, or ChromeOS Flex .zip/.bin)?": "Já baixou a imagem (ISO, ou .zip/.bin do ChromeOS Flex)?",
    "The selected file looks like {name}, but \"Windows 11\" is chosen. Windows mode would erase the drive and then fail to find the Windows installer.\n\nChoose the matching card instead, or continue only if you are sure.\n\nContinue anyway?": "O arquivo selecionado parece ser {name}, mas \"Windows 11\" está escolhido. O modo Windows apagaria o pendrive e só depois não acharia o instalador do Windows.\n\nEscolha o cartão correspondente, ou continue só se tiver certeza.\n\nContinuar mesmo assim?",
    "Quit while writing?": "Sair durante a gravação?",
    "A USB drive is being written right now. Quitting cancels the operation and leaves the drive incomplete and UNUSABLE until it is created again.\n\nCancel the operation and quit?": "Um pendrive está sendo gravado agora. Sair cancela a operação e deixa o pendrive incompleto e INUTILIZÁVEL até ser criado de novo.\n\nCancelar a operação e sair?",
    "Still stopping": "Ainda parando",
    "The operation is taking a while to stop. Quit anyway? The drive stays unusable until it is created again.": "A operação está demorando para parar. Sair mesmo assim? O pendrive continua inutilizável até ser criado de novo.",
    "Canceled. The drive was not modified.": "Cancelado. O pendrive não foi modificado.",
    "The operation was canceled.\n\nThe USB drive was NOT modified.": "A operação foi cancelada.\n\nO pendrive NÃO foi modificado.",
    "Missing tools": "Ferramentas ausentes",
    "Missing tools: {tools}. Click \"Install missing dependencies\" first.": "Ferramentas ausentes: {tools}. Clique em \"Instalar as dependências que faltam\" primeiro.",
    "These tools are missing: {tools}. Click \"Install missing dependencies\" first. Nothing was changed.": "Estas ferramentas estão ausentes: {tools}. Clique em \"Instalar as dependências que faltam\" primeiro. Nada foi alterado.",
    "Installing the missing tools...": "Instalando as ferramentas ausentes...",
    "Unknown drive size": "Tamanho do pendrive desconhecido",
    "The size of this drive could not be read (it reports 0 bytes). It may be an empty card reader or a drive that is not ready. Nothing was changed.": "Não foi possível ler o tamanho deste pendrive (ele informa 0 bytes). Pode ser um leitor de cartão vazio ou um pendrive que não está pronto. Nada foi alterado.",
    "Image type not recognised": "Tipo de imagem não reconhecido",
    "The program could not identify the selected file, but \"Windows 11\" is chosen. Windows mode would erase the drive and then fail if this is not a Windows installer.\n\nContinue only if you are sure this is a Windows 11 ISO.\n\nContinue anyway?": "O programa não conseguiu identificar o arquivo selecionado, mas \"Windows 11\" está escolhido. O modo Windows apagaria o pendrive e depois falharia se isto não for um instalador do Windows.\n\nContinue só se tiver certeza de que é uma ISO do Windows 11.\n\nContinuar mesmo assim?",
    "The content of this image could not be identified, so the image type was not changed. Check that the selected card ({card}) is the right one.": "Não foi possível identificar o conteúdo desta imagem, então o tipo de imagem não foi alterado. Confira se o cartão selecionado ({card}) é o correto.",
    "Not much free space": "Pouco espaço livre",
    "The download (about 1.4 GB) and the extracted image (about 9.5 GB) need roughly {need} free in this folder, and only {free} is available. It may fail part-way.\n\nContinue anyway?": "O download (cerca de 1,4 GB) e a imagem extraída (cerca de 9,5 GB) precisam de aproximadamente {need} livres nesta pasta, e há só {free}. Pode falhar no meio.\n\nContinuar mesmo assim?",
}


def _(text):
    """The text in the active language; unknown texts (and English) come back unchanged."""
    if ACTIVE_LANGUAGE == LANG_PT:
        return PT_BR.get(text, text)
    return text


tr = _  # alias for code where "_" is used as a throwaway variable


def human_size(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _silent_remove(*paths):
    """Best-effort cleanup: delete each file, ignoring any that is missing or cannot be removed."""
    for path in paths:
        with contextlib.suppress(OSError):
            os.remove(path)


def _silent_rmdir(*paths):
    """Best-effort cleanup: remove each (empty) directory, ignoring any that cannot be removed."""
    for path in paths:
        with contextlib.suppress(OSError):
            os.rmdir(path)


def _eta_text(remaining_seconds, speed, translate=True):
    """'~2m05s left' for the progress labels; '' when the speed is unknown (nothing to estimate from).

    One helper for every progress label, so a long wait reads the same everywhere (minutes and
    seconds, never a raw count of seconds). `translate=False` (the command line) keeps it English.
    """
    _ = _text_for(translate)
    try:
        if not speed or speed <= 0 or remaining_seconds is None or remaining_seconds < 0:
            return ""
        seconds = int(remaining_seconds)
    except (TypeError, ValueError, OverflowError):
        return ""
    return _("~{minutes}m{seconds:02d}s left").format(minutes=seconds // 60, seconds=seconds % 60)


def _eta_remaining(done, total, speed, translate=True):
    """The time left to move `total` - `done` bytes at `speed` bytes per second ('' when the speed is unknown)."""
    if not speed or speed <= 0:
        return ""
    return _eta_text((total - done) / speed, speed, translate)


def _rate_tail(done, total, speed):
    """' — 12.0 MB/s — ~2m05s left' for a progress label; '' when the speed is unknown."""
    if not speed or speed <= 0:
        return ""
    return f" — {human_size(speed)}/s — {_eta_remaining(done, total, speed)}"


# ============================================================
# Audit trail
#
# Destructive, privileged operations should leave a record. The log is written
# with owner-only permissions and deliberately never receives passwords: the
# sudo password is passed on stdin and never appears in an argument list or in
# any string handed to audit()/log().
# ============================================================
def audit_log_path():
    override = os.environ.get(ENV_AUDIT_LOG)
    if override:
        return os.path.expanduser(override)
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    return os.path.join(base, "epma-win11-usb-creator", "audit.log")


class PrivateRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """Rotating log file that stays owner-only (0600), live file and rotated copies alike."""

    def _open(self):
        fd = os.open(self.baseFilename, os.O_WRONLY | os.O_CREAT | os.O_APPEND, PRIVATE_FILE_MODE)
        return os.fdopen(fd, self.mode, encoding=self.encoding, errors=self.errors)

    def doRollover(self):
        super().doRollover()
        for i in range(0, self.backupCount + 1):
            path = self.baseFilename if i == 0 else f"{self.baseFilename}.{i}"
            with contextlib.suppress(OSError):
                os.chmod(path, PRIVATE_FILE_MODE)


def get_audit_logger():
    """Lazily create the audit logger. Never raises: logging must not break the app."""
    global _audit_logger
    if _audit_logger is not None:
        return _audit_logger
    logger = logging.getLogger("epma.win11usb.audit")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if os.environ.get(ENV_DISABLE_AUDIT_LOG, "").strip().lower() in ("1", "true", "yes"):
        logger.addHandler(logging.NullHandler())
        _audit_logger = logger
        return logger
    try:
        path = audit_log_path()
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        # Create with restrictive permissions before the handler opens it.
        if not os.path.exists(path):
            os.close(os.open(path, os.O_CREAT | os.O_WRONLY, PRIVATE_FILE_MODE))
        else:
            os.chmod(path, PRIVATE_FILE_MODE)
        handler = PrivateRotatingFileHandler(
            path, maxBytes=AUDIT_LOG_MAX_BYTES, backupCount=AUDIT_LOG_BACKUPS, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)
    except Exception:
        # A read-only or unwritable home must not stop the user from making a USB.
        logger.addHandler(logging.NullHandler())
    _audit_logger = logger
    return logger


def audit(msg, level=logging.INFO):
    """Record a security-relevant event. Callers must not pass secrets or personal data."""
    try:
        get_audit_logger().log(level, msg)
    except Exception:  # noqa: S110 - deliberate: logging must never break the app
        pass


# ============================================================
# Input validation
# ============================================================
def validate_device_name(dev):
    """Return dev if it is a plausible disk identifier, else raise.

    Rejecting is safer than escaping: this value reaches privileged commands.
    """
    if not isinstance(dev, str) or not dev:
        raise ValueError("No disk was selected.")
    pattern = MAC_DEVICE_RE if IS_MAC else LINUX_DEVICE_RE
    # fullmatch, not match: "$" also matches just before a trailing newline, so "sdb\n" would pass.
    if not pattern.fullmatch(dev):
        audit(f"REJECTED invalid device identifier: {dev!r}", logging.WARNING)
        raise ValueError(
            f"Refusing to operate on {dev!r}: it is not a valid disk identifier. "
            "Expected something like 'disk4' (macOS) or 'sdb' (Linux)."
        )
    return dev


def has_mbr_signature(head):
    """True if `head` (the first bytes of a file) carries the MBR boot signature at offset 510."""
    return head[MBR_SIGNATURE_OFFSET:MBR_SIGNATURE_OFFSET + 2] == MBR_SIGNATURE


def resolve_path(path):
    """The absolute, symlink-free form of a path the user typed (``~`` expanded)."""
    return os.path.realpath(os.path.expanduser(path))


def validate_iso_path(path):
    """Return an absolute, existing, regular-file ISO path, or raise."""
    if not path:
        raise ValueError("No ISO file has been selected yet.")
    resolved = resolve_path(path)
    if not os.path.exists(resolved):
        raise ValueError(f"The selected ISO file no longer exists: {resolved}")
    if not os.path.isfile(resolved):
        raise ValueError(f"The selected ISO path is not a regular file: {resolved}")
    if not os.access(resolved, os.R_OK):
        raise ValueError(f"The selected ISO file cannot be read: {resolved}")
    if os.path.getsize(resolved) < MIN_IMAGE_BYTES:
        raise ValueError(
            "The selected file is too small to be a valid image "
            f"({human_size(os.path.getsize(resolved))}). It may be an incomplete download."
        )
    return resolved


def validate_hybrid_iso(path):
    """Raise unless `path` carries an MBR boot signature (isohybrid).

    Writing a non-hybrid ISO byte-for-byte produces a drive that will not boot, so
    refuse up front instead of erasing the drive for nothing. Windows ISOs are not
    hybrid; they must use the Windows mode.
    """
    with open(path, "rb") as fh:
        head = fh.read(512)
    if not has_mbr_signature(head):
        raise ValueError(
            "This ISO is not a bootable hybrid image, so it cannot be written directly to a USB drive.\n\n"
            "If this is a Windows ISO, choose 'Windows 11' as the image type. Otherwise use an "
            "ISO that is provided as a hybrid/USB-ready image (all current Ubuntu, Debian, Fedora, "
            "Mint and Arch ISOs are)."
        )


# ============================================================
# ISO inspection (pure stdlib, never raises, reads a few MB at most)
# ============================================================
GPT_HEADER_OFFSET = 512                 # LBA 1: "EFI PART"
GPT_ENTRIES_OFFSET = 1024               # LBA 2: the partition entries (128 bytes each)
GPT_ENTRY_SIZE = 128
# ChromeOS disks always carry these partition names (kernel and root slots, user state).
CHROMEOS_PARTITION_NAMES = {"KERN-A", "ROOT-A", "KERN-B", "ROOT-B", "STATE", "EFI-SYSTEM"}
ISO_SECTOR = 2048
ISO_PVD_OFFSET = 16 * ISO_SECTOR        # Primary Volume Descriptor: sector 16 (0x8000)
ISO_DIR_MAX_BYTES = 256 * 1024          # never read more than this per directory
ISO_UDF_SCAN_BYTES = 4 * 1024 * 1024    # how much of a UDF image is searched for Windows names
# Volume ids that Microsoft's media tools produce, e.g. CCCOMA_X64FRE_EN-US_DV9.
# The version must not run into another digit; "_" may follow it ("WIN11_23H2"), which is why
# there is no word boundary here ("_" is a word character, so it would stop WIN11_23H2 matching).
WINDOWS_VOLUME_ID_RE = re.compile(
    r"^(?:[A-Z0-9]{2,8}_(?:X64|X86|A64|ARM64)F?REV?_|WIN(?:DOWS)?[ _-]?(?:SERVER|1[01]|[78])(?![0-9]))",
    re.IGNORECASE)
WINDOWS_ROOT_FILES = {"BOOTMGR", "BOOTMGR.EFI", "SETUP.EXE"}
WINDOWS_SOURCES_FILES = {"INSTALL.WIM", "INSTALL.ESD", "INSTALL.SWM", "BOOT.WIM"}


def _iso_read_dir(fh, extent, length, block, file_size):
    """Parse one ISO 9660 directory into [(NAME, is_dir, extent, length)]. Names lose their ';1'."""
    offset = extent * block
    if length <= 0 or offset <= 0 or offset >= file_size:
        return []
    fh.seek(offset)
    data = fh.read(min(length, ISO_DIR_MAX_BYTES))
    entries = []
    pos = 0
    while pos < len(data):
        rec_len = data[pos]
        if rec_len == 0:  # records never span sectors; padding means "continue in the next one"
            pos = (pos // ISO_SECTOR + 1) * ISO_SECTOR
            continue
        if rec_len < 34 or pos + rec_len > len(data):
            break
        name_len = data[pos + 32]
        raw = data[pos + 33:pos + 33 + name_len]
        if raw not in (b"\x00", b"\x01"):  # skip the '.' and '..' entries
            name = raw.decode("latin-1").split(";")[0].rstrip(".").upper()
            entries.append((
                name,
                bool(data[pos + 25] & 0x02),
                int.from_bytes(data[pos + 2:pos + 6], "little"),
                int.from_bytes(data[pos + 10:pos + 14], "little"),
            ))
        pos += rec_len
    return entries


def _iso_has_udf(fh):
    """True if the volume recognition area (sectors 17-19) announces UDF (ECMA-167)."""
    fh.seek(ISO_PVD_OFFSET + ISO_SECTOR)
    area = fh.read(3 * ISO_SECTOR)
    return any(area[i * ISO_SECTOR + 1:i * ISO_SECTOR + 6] in (b"BEA01", b"NSR02", b"NSR03")
               for i in range(len(area) // ISO_SECTOR))


def _is_chromeos_disk_image(head):
    """True if `head` (the first sectors of a file) is a GPT disk with ChromeOS partition names."""
    if len(head) < GPT_ENTRIES_OFFSET + GPT_ENTRY_SIZE or head[GPT_HEADER_OFFSET:GPT_HEADER_OFFSET + 8] != b"EFI PART":
        return False
    names = set()
    for pos in range(GPT_ENTRIES_OFFSET, min(len(head), GPT_ENTRIES_OFFSET + 128 * GPT_ENTRY_SIZE), GPT_ENTRY_SIZE):
        entry = head[pos:pos + GPT_ENTRY_SIZE]
        if len(entry) < GPT_ENTRY_SIZE or not any(entry[:16]):
            continue  # unused slot (its partition type GUID is all zeros)
        names.add(entry[56:128].decode("utf-16-le", "ignore").split("\x00")[0].upper())
    # ROOT-A and KERN-A are in every ChromeOS image (installer, recovery and installed disks).
    return {"ROOT-A", "KERN-A"} <= names and len(names & CHROMEOS_PARTITION_NAMES) >= 3


def _detect_iso_kind(path):
    file_size = os.path.getsize(path)
    with open(path, "rb") as fh:
        head = fh.read(ISO_PVD_OFFSET + ISO_SECTOR)
        if _is_chromeos_disk_image(head):
            return ISO_KIND_CHROMEOS
        pvd = head[ISO_PVD_OFFSET:]
        if len(pvd) < ISO_SECTOR or pvd[0] != 1 or pvd[1:6] != b"CD001":
            return ISO_KIND_UNKNOWN  # not an ISO 9660 image
        volume_id = pvd[40:72].decode("latin-1").strip().upper()
        block = int.from_bytes(pvd[128:130], "little")
        if block < 512 or block > 65536:
            block = ISO_SECTOR
        root = pvd[156:190]
        root_extent = int.from_bytes(root[2:6], "little")
        root_length = int.from_bytes(root[10:14], "little")

        # 1. Walk the ISO 9660 tree: root files, then \SOURCES\.
        entries = _iso_read_dir(fh, root_extent, root_length, block, file_size)
        for name, is_dir, extent, length in entries:
            if not is_dir and name in WINDOWS_ROOT_FILES:
                return ISO_KIND_WINDOWS
            if is_dir and name == "SOURCES":
                for sub, sub_is_dir, _e, _l in _iso_read_dir(fh, extent, length, block, file_size):
                    if not sub_is_dir and sub in WINDOWS_SOURCES_FILES:
                        return ISO_KIND_WINDOWS

        # 2. Microsoft's own ISOs are UDF images whose ISO 9660 side is just a stub, so the
        #    names above are invisible. UDF stores them near the start of the file.
        if _iso_has_udf(fh):
            fh.seek(0)
            blob = fh.read(ISO_UDF_SCAN_BYTES).lower()
            for needle in (b"bootmgr", "bootmgr".encode("utf-16-be")):
                if needle in blob and (b"sources" in blob or "sources".encode("utf-16-be") in blob):
                    return ISO_KIND_WINDOWS
        if WINDOWS_VOLUME_ID_RE.match(volume_id):
            return ISO_KIND_WINDOWS

        # 3. Everything else that boots from a USB drive as-is is a hybrid image (Linux & co).
        if has_mbr_signature(head):
            return ISO_KIND_LINUX
    return ISO_KIND_UNKNOWN


def detect_iso_kind(path):
    """Classify an image by its content: 'windows', 'linux' (hybrid), 'chromeos' or 'unknown'.

    Never raises and reads at most a few MB, so it is safe to call on any file the user
    picks. 'unknown' means "could not tell"; callers must ask the user, not guess from the file name.
    """
    try:
        return _detect_iso_kind(path)
    except Exception:  # noqa: BLE001 - any malformed/unreadable file simply means "unknown"
        return ISO_KIND_UNKNOWN


# ---- Extracting the disk image from Google's ZIP ----
def extract_disk_image(zip_path, dest_dir, progress=None, cancel_event=None):
    """Extract the single .bin disk image from `zip_path` into `dest_dir`; return its path.

    Only the file's base name is used (an entry such as "../../x.bin" cannot escape the folder),
    it never overwrites an existing file, it refuses implausible sizes and checks the free space
    first, and the data goes to a temporary file that is renamed only when the whole archive
    entry was read and its CRC verified. `progress(done, total)` is called while copying.
    A damaged or unsupported archive always ends as a ValueError with a user-facing message
    (never a raw zlib/zipfile exception). The temporary file is created without following
    symlinks and never reuses an existing path.
    """
    try:
        archive = zipfile.ZipFile(zip_path)
    except (zipfile.BadZipFile, OSError):
        raise ValueError("That is not a valid ZIP file. If the download was interrupted, download it again.") from None
    with archive:
        images = [i for i in archive.infolist() if not i.is_dir() and i.filename.lower().endswith(".bin")]
        if not images:
            raise ValueError("The ZIP file does not contain a .bin disk image.")
        info = max(images, key=lambda i: i.file_size)
        if not MIN_IMAGE_BYTES <= info.file_size <= DISK_IMAGE_MAX_BYTES:
            raise ValueError(f"The disk image inside the ZIP has an implausible size "
                             f"({human_size(info.file_size)}), so it was not extracted.")
        if not os.path.isdir(dest_dir):
            raise ValueError(f"The folder does not exist: {dest_dir}")
        if shutil.disk_usage(dest_dir).free < info.file_size + 256 * 1024 * 1024:
            raise ValueError(f"Not enough free space in {dest_dir}: the disk image needs "
                             f"{human_size(info.file_size)}.")
        name = os.path.basename(info.filename.replace("\\", "/"))
        if not re.fullmatch(r"[A-Za-z0-9._+-]{1,128}", name):
            name = "chromeos_flex.bin"
        stem, ext = os.path.splitext(name)
        dest, n = os.path.join(dest_dir, name), 1
        while os.path.exists(dest):
            dest, n = os.path.join(dest_dir, f"{stem}-{n}{ext}"), n + 1
        tmp = dest + ".part"
        done = 0
        created = False
        try:
            # A stale ".part" (or a symlink planted at that name) is removed, never written through.
            if os.path.lexists(tmp):
                os.remove(tmp)
            fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | O_NOFOLLOW, PRIVATE_FILE_MODE)
            created = True
            with os.fdopen(fd, "wb") as out, archive.open(info) as src:
                while True:
                    check_canceled(cancel_event)
                    chunk = src.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    out.write(chunk)
                    done += len(chunk)
                    if progress:
                        progress(done, info.file_size)
            if done != info.file_size:
                raise ValueError("The disk image in the ZIP is incomplete. Download the file again.")
            os.replace(tmp, dest)
            created = False
        except OperationCanceled:
            raise
        except (zipfile.BadZipFile, zlib.error, EOFError):
            raise ValueError("The ZIP file is damaged (checksum or compression error). "
                             "Download it again.") from None
        except (NotImplementedError, RuntimeError):
            # zipfile: unsupported compression method, or an encrypted entry.
            raise ValueError("This ZIP file uses a compression method or encryption that is not "
                             "supported. Download latest.bin.zip again from Google.") from None
        finally:
            if created and os.path.lexists(tmp):
                _silent_remove(tmp)
    audit(f"Extracted a disk image from a ZIP ({human_size(done)})")
    return dest


# ---- SHA-256 of a local file ----
SHA256_CHUNK = 4 * 1024 * 1024
SHA256_HEX_RE = re.compile(r"[0-9A-Fa-f]{64}")  # exactly 64 hex digits (use with fullmatch)
_HEX64_RE = re.compile(rf"(?<![0-9A-Fa-f]){SHA256_HEX_RE.pattern}(?![0-9A-Fa-f])")  # one inside a longer text


def is_sha256_hex(text):
    """True if `text` is exactly a SHA-256 in hex (64 digits, either case)."""
    return bool(SHA256_HEX_RE.fullmatch(text))


def parse_expected_sha256(text, filename=None):
    """Extract a SHA-256 from what the user pasted. Returns lowercase hex, or None if empty.

    Accepts a bare hash, a `sha256sum` line (`<hash> *file.iso` / `<hash>  file.iso`), the BSD
    form (`SHA256 (file.iso) = <hash>`), or a whole SHA256SUMS file (then `filename` picks the
    line). Raises ValueError with a user-facing message when nothing valid can be found.
    """
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    if not lines:
        return None
    found = [(m.group(0).lower(), ln) for ln in lines for m in [_HEX64_RE.search(ln)] if m]
    if not found:
        raise ValueError("That is not a SHA-256 checksum: it must be 64 characters using only 0-9 and a-f.")
    if len(found) == 1 or len({h for h, _ in found}) == 1:
        return found[0][0]
    if filename:
        named = {h for h, ln in found if filename in ln}
        if len(named) == 1:
            return named.pop()
    raise ValueError("The pasted text contains several checksums. Paste only the line for your ISO file.")


def validate_disk_image(path):
    """Raise unless `path` is a raw disk image that can boot from a USB drive as-is.

    ChromeOS images are whole-disk images (a partition table plus the partitions), written to
    the drive byte for byte. They carry the MBR boot signature like a hybrid ISO does.
    """
    with open(path, "rb") as fh:
        head = fh.read(512)
    if head[:4] == b"PK\x03\x04":
        raise ValueError(
            "This is the ZIP archive, not the disk image inside it. Select it with 'Select existing "
            "ISO file...' so the program can extract the .bin file, or extract it yourself.")
    if not has_mbr_signature(head):
        raise ValueError(
            "This file is not a bootable disk image, so it cannot be written to a USB drive. "
            "For ChromeOS Flex use the .bin file from the official latest.bin.zip.")


def make_progress_log(log, interval=DD_LOG_INTERVAL):
    """Wrap `log` so dd's frequent progress lines are shown at most every `interval` seconds."""
    last = [0.0]

    def wrapped(line):
        if re.search(r"\d+ bytes", line):
            now = time.time()
            if now - last[0] < interval:
                return
            last[0] = now
        log(line)

    return wrapped


def make_dd_log(log, total, progress):
    """Log wrapper that turns dd's "N bytes ..." lines into progress updates.

    GNU dd (status=progress) and BSD dd (SIGINFO) both print the running byte count
    as "<N> bytes ...", so one pattern covers both.
    """
    throttled = make_progress_log(log)

    def wrapped(line):
        m = re.search(r"(\d+) bytes", line)
        if m and total and progress:
            progress(min(int(m.group(1)), total), total, "Writing the image...")
        throttled(line)

    return wrapped


def copy_file_with_progress(src, dst_dir, on_bytes, cancel_event=None):
    """Copy `src` into `dst_dir` in chunks, reporting the bytes copied so far."""
    dst = os.path.join(dst_dir, os.path.basename(src))
    copied = 0
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        while True:
            check_canceled(cancel_event)
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            fout.write(chunk)
            copied += len(chunk)
            on_bytes(copied)
    shutil.copystat(src, dst)


# Reads the whole image back from the drive and compares it with the ISO, chunk by
# chunk. It exits 0 and reports the result as a VERIFY_OK / VERIFY_FAIL marker line
# (so a mismatch is told apart from a script error). Values arrive as "$1".."$5",
# never pasted into the text; "$5" is the cancel flag file (VERIFY_CANCELED when it appears).
VERIFY_RAW_SCRIPT = (
    'set -eu\n'
    # A terminal Ctrl-C reaches this script too (same process group). Ignore it: the app turns
    # it into the cancel flag file, which the loop below polls.
    "trap '' INT\n"
    'ISO="$1"; DEV="$2"; SIZE="$3"; BS="$4"; STOP="$5"\n'
    # Linux: make sure we read the device, not the page cache (harmless elsewhere).
    '{ blockdev --flushbufs "$DEV"; echo 3 > /proc/sys/vm/drop_caches; } >/dev/null 2>&1 || true\n'
    'off=0; i=0\n'
    'while [ "$off" -lt "$SIZE" ]; do\n'
    '  if [ -e "$STOP" ]; then echo "VERIFY_CANCELED"; exit 0; fi\n'
    '  len=$(( SIZE - off ))\n'
    '  if [ "$len" -gt "$BS" ]; then len=$BS; fi\n'
    '  if ! cmp -s <(dd if="$ISO" bs="$BS" skip="$i" count=1 2>/dev/null | head -c "$len") \\\n'
    '              <(dd if="$DEV" bs="$BS" skip="$i" count=1 2>/dev/null | head -c "$len"); then\n'
    '    echo "VERIFY_FAIL $off"; exit 0\n'
    '  fi\n'
    '  off=$((off + len)); i=$((i + 1))\n'
    '  echo "VERIFY_PROGRESS $off"\n'
    'done\n'
    'echo "VERIFY_OK"\n'
    'exit 0\n'
)


def verify_raw_write(iso_path, device_path, log, priv, progress, cancel_event=None):
    """Read the drive back and compare it byte-for-byte with the ISO. Raises on any mismatch."""
    total = os.path.getsize(iso_path)
    log("Verifying the written image: reading the drive back and comparing it with the ISO...")
    result = {}
    last = [0.0]

    def watch(line):
        line = line.strip()
        m = re.fullmatch(r"VERIFY_PROGRESS (\d+)", line)
        if m:
            now = time.time()
            if progress and (now - last[0] >= VERIFY_PROGRESS_INTERVAL or int(m.group(1)) >= total):
                last[0] = now
                progress(min(int(m.group(1)), total), total, "Verifying the written image...")
            return
        if line == "VERIFY_OK":
            result["ok"] = True
        elif line == "VERIFY_CANCELED":
            result["canceled"] = True
        elif line.startswith("VERIFY_FAIL"):
            result["ok"] = False
            result["offset"] = line.split()[-1]
        else:
            log(line)

    check_canceled(cancel_event, written=True)
    with cancel_flag(cancel_event) as flag:
        priv.run_script(VERIFY_RAW_SCRIPT, watch,
                        args=[iso_path, device_path, str(total), str(VERIFY_CHUNK), flag])
    if result.get("canceled"):
        log("Verification canceled. The image was written completely but NOT verified.")
        raise OperationCanceled("Canceled by the user during verification. The image was written "
                                "but not verified.", written=True)
    if result.get("ok") is None:
        raise RuntimeError("Could not complete the verification of the written drive. "
                           "Do not trust this drive; run the creation again.")
    if not result["ok"]:
        audit(f"VERIFICATION FAILED at byte {result['offset']}", logging.ERROR)
        raise RuntimeError(
            f"Verification FAILED: the data on the drive differs from the ISO (first difference "
            f"near byte {result['offset']}).\n\nThe drive was NOT ejected and should not be used. "
            "Try again, and if it fails again, the USB drive or its port may be faulty.")
    audit("Verification passed (raw write matches the ISO)")
    log("Verification passed: the drive content is identical to the ISO.")


def verify_windows_payload(src_root, dst_root, rel_big, big_file, log, progress, cancel_event=None,
                           extra_files=None):
    """Compare what is on the drive with the ISO. Raises on any mismatch.

    Every file is compared by checksum (rsync dry run), and the install image is
    either compared directly or checked with `wimlib-imagex verify` when it was split.
    `extra_files` ({relative path: bytes}, the hardening files) are compared byte for byte too;
    they may replace a file of the ISO, so the rsync comparison leaves exactly those paths out.
    """
    log("Verifying the copied files (reading them back from the drive)...")
    if progress:
        progress(0, 0, "Verifying the copied files...")
    bad = []
    replaced = {rel.lower() for rel in (extra_files or {})}  # FAT32 ignores case

    def watch(line):
        log(line)
        if re.match(r"^(>f|cd|\*deleting)", line):
            item = re.match(r"^\S+ (.*)$", line.strip())  # "<flags> <path>" (the flags field varies by rsync)
            if item and item.group(1).lower() in replaced:
                return  # a hardening file written over an ISO file; verify_hardening_files compares it
            bad.append(line.strip())

    run_cmd(["rsync", "-rcn", "-i", f"--exclude={rel_big}", src_root + "/", dst_root + "/"], watch,
            cancel_event=cancel_event)
    if bad:
        audit(f"VERIFICATION FAILED: {len(bad)} file(s) differ", logging.ERROR)
        raise RuntimeError(
            f"Verification FAILED: {len(bad)} item(s) on the drive are missing or differ from the "
            f"ISO (for example: {bad[0]}).\n\nThe drive was NOT ejected and should not be used.")

    name = os.path.basename(big_file)
    sources = os.path.join(dst_root, os.path.dirname(rel_big))
    if progress:
        progress(0, 0, "Verifying the install image...")
    swm = os.path.join(sources, os.path.splitext(name)[0] + ".swm")
    if os.path.exists(swm):
        try:
            run_cmd(["wimlib-imagex", "verify", swm, f"--ref={sources}/{os.path.splitext(name)[0]}*.swm"], log,
                    cancel_event=cancel_event)
        except RuntimeError:
            raise RuntimeError(
                "Verification FAILED: the split install image on the drive is damaged.\n\n"
                "The drive was NOT ejected and should not be used.") from None
    elif check_canceled(cancel_event) or not filecmp.cmp(big_file, os.path.join(sources, name), shallow=False):
        raise RuntimeError(
            f"Verification FAILED: {name} on the drive differs from the ISO.\n\n"
            "The drive was NOT ejected and should not be used.")
    if extra_files:
        verify_hardening_files(dst_root, extra_files, log, cancel_event)
    audit("Verification passed (copied files match the ISO)")
    log("Verification passed: the files on the drive match the ISO.")


def find_case_insensitive(directory, name):
    """Return the real path of the entry in `directory` named `name` ignoring case, or None.

    ISO detection upper-cases names, so a custom image with "Sources/Install.wim" counts as
    Windows; the copy must therefore find it on a case-sensitive mount too.
    """
    try:
        entries = sorted(os.listdir(directory))
    except OSError:
        return None
    if name in entries:
        return os.path.join(directory, name)
    for entry in entries:
        if entry.lower() == name.lower():
            return os.path.join(directory, entry)  # the spelling on disk, even on a case-insensitive volume
    return None


def copy_windows_payload(src_root, dst_root, log, progress, wimlib_hint, reopen=None, cancel_event=None,
                         extra_files=None, write_extra=None):
    """Copy the contents of a mounted Windows ISO to the drive, reporting progress.

    Everything except sources/install.wim|esd is copied with rsync; that file is
    copied directly, or split into <4 GB parts when it exceeds the FAT32 limit.
    Progress is counted in bytes over the whole payload. The "sources" folder and the
    install image are looked up ignoring case.
    """
    sources_dir = find_case_insensitive(src_root, "sources")
    big_file = None
    for name in ("install.wim", "install.esd"):
        p = find_case_insensitive(sources_dir, name) if sources_dir else None
        if p and os.path.isfile(p):
            big_file = p
            break
    if not big_file:
        raise RuntimeError("Could not find sources/install.wim or sources/install.esd on the ISO.")

    rest_total = 0
    for root, _dirs, files in os.walk(src_root):
        for fname in files:
            path = os.path.join(root, fname)
            if path != big_file:
                try:
                    rest_total += os.path.getsize(path)
                except OSError:
                    pass
    size = os.path.getsize(big_file)
    total = rest_total + size
    state = {"done": 0}

    def report(done, text):
        if progress:
            progress(min(done, total), total, text)

    def rsync_log(line):
        log(line)
        name = line.strip()
        if not name or name.endswith("/"):
            return
        path = os.path.join(src_root, name)
        if os.path.isfile(path):  # header/summary lines never resolve to a file
            state["done"] += os.path.getsize(path)
            report(min(state["done"], rest_total), "Copying files...")

    rel_big = os.path.relpath(big_file, src_root)
    log("Copying files from the ISO to the USB drive (this can take several minutes)...")
    run_cmd(["rsync", "-rv", f"--exclude={rel_big}", src_root + "/", dst_root + "/"], rsync_log,
            cancel_event=cancel_event)
    report(rest_total, "Copying files...")
    check_canceled(cancel_event)

    # Same folder name as on the ISO (rsync created it); the drive's FAT32 ignores case anyway.
    target_sources = os.path.join(dst_root, os.path.dirname(rel_big))
    os.makedirs(target_sources, exist_ok=True)

    if size > FAT32_MAX_FILE_SIZE:
        log(f"{os.path.basename(big_file)} is {human_size(size)} (over 4GB). Splitting with wimlib-imagex...")
        if not shutil.which("wimlib-imagex"):
            raise RuntimeError(wimlib_hint)
        out_swm = os.path.join(target_sources, os.path.splitext(os.path.basename(big_file))[0] + ".swm")

        def split_log(line):
            log(line)
            m = re.search(r"(\d{1,3})%", line)
            if m:
                report(rest_total + size * min(int(m.group(1)), 100) // 100, "Splitting the install image...")

        run_cmd(["wimlib-imagex", "split", big_file, out_swm, "3800"], split_log, cancel_event=cancel_event)
    else:
        log(f"Copying {os.path.basename(big_file)} ({human_size(size)})...")
        copy_file_with_progress(
            big_file, target_sources,
            lambda n: report(rest_total + n, "Copying the install image..."),
            cancel_event=cancel_event)

    if extra_files:
        # Hardening files go on after the ISO's own files (they may replace one) and before the
        # remount, so the read-back below covers them too. `write_extra(root)` does the writing.
        report(total, "Adding hardening files...")
        log("Adding hardening files...")
        check_canceled(cancel_event)
        write_extra(dst_root)

    report(total, "Flushing data to the drive...")
    check_canceled(cancel_event)
    log("Syncing writes to disk...")
    run_cmd(["sync"], log, check=False)
    # Remount so the check reads from the device itself and not from the system cache.
    if reopen:
        dst_root = reopen()
    try:
        verify_windows_payload(src_root, dst_root, rel_big, big_file, log, progress, cancel_event=cancel_event,
                               **({"extra_files": extra_files} if extra_files else {}))
    except OperationCanceled as e:
        e.written = True  # everything was copied; only the final check was interrupted
        raise


def validate_download_url(raw_url):
    """Return a normalised URL, or raise ValueError explaining why it was rejected."""
    url = (raw_url or "").strip()
    if not url:
        raise ValueError("Paste the direct ISO link before downloading.")
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        # 'from None': the parser's internal message would only confuse the user.
        raise ValueError("That does not look like a valid link.") from None
    if parsed.scheme.lower() not in ALLOWED_URL_SCHEMES:
        raise ValueError(
            f"Only {'/'.join(s.upper() for s in ALLOWED_URL_SCHEMES)} links are accepted "
            f"(this one starts with '{parsed.scheme or '?'}://').\n\n"
            "An unencrypted link can be modified in transit, which would let someone "
            "replace the Windows image with a tampered one."
        )
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError("The link has no server address.")
    if url == CHROMEOS_FLEX_URL:
        return url, host, False  # Google's official ChromeOS Flex image (exact address only)
    if os.environ.get(ENV_ALLOW_ANY_HOST, "").strip().lower() in ("1", "true", "yes"):
        return url, host, False
    trusted = os.environ.get(ENV_TRUSTED_HOSTS)
    trusted_hosts = tuple(h.strip().lower() for h in trusted.split(",") if h.strip()) if trusted \
        else DEFAULT_TRUSTED_ISO_HOSTS
    is_trusted = any(host == t or host.endswith("." + t) for t in trusted_hosts)
    return url, host, not is_trusted


class OperationCanceled(RuntimeError):
    """The user canceled the USB creation. A RuntimeError so older handlers still cope.

    Contract for callers (the GUI reads these with getattr(e, "...", default)):

    * `drive_touched` (default True): False when the cancel happened before anything on the
      drive was changed (while hashing the ISO, or before the erase/write began). The drive
      is then exactly as it was and still usable; do NOT tell the user it is unusable.
    * `written` (default False): True when the whole image/payload had been written and the
      cancel came during the final verification. The drive holds the complete image but it
      was not verified.
    * With neither set, the operation stopped midway and the drive is left incomplete.
    """

    def __init__(self, message="Canceled by the user.", drive_touched=True, written=False):
        super().__init__(message)
        self.drive_touched = drive_touched
        self.written = written


def check_canceled(cancel_event, drive_touched=True, written=False):
    """Raise OperationCanceled if the user asked to stop. Cheap; call between steps.

    `drive_touched` / `written` describe the state of the drive at this point (see OperationCanceled).
    """
    if cancel_event is not None and cancel_event.is_set():
        raise OperationCanceled("Canceled by the user.", drive_touched=drive_touched, written=written)


def _hash_stream(fh, digest, limit=None, check=None, on_chunk=None, chunk=SHA256_CHUNK):
    """Feed `digest` from the open binary file `fh` in chunks (constant memory); return the bytes read.

    `limit` stops after that many bytes (None: read to the end). `check()` runs before every read and
    may raise to stop (a cancel). `on_chunk(done)` runs after every chunk. The one place where a file is
    read in blocks for hashing: sha256_file() and the resume of a partial download both use it.
    """
    done = 0
    while limit is None or done < limit:
        if check:
            check()
        block = fh.read(chunk if limit is None else min(chunk, limit - done))
        if not block:
            break
        digest.update(block)
        done += len(block)
        if on_chunk:
            on_chunk(done)
    return done


def sha256_file(path, cancel_event=None, progress=None, chunk=SHA256_CHUNK):
    """SHA-256 of a file, read in chunks (constant memory), as lowercase hex.

    `cancel_event` makes it raise OperationCanceled between chunks; `progress(done, total)` is called
    after each chunk. The one SHA-256-of-a-file routine: the GUI, the command line and the audit trail use it.
    """
    digest = hashlib.sha256()
    total = os.path.getsize(path) if progress else 0
    with open(path, "rb") as fh:
        _hash_stream(fh, digest, check=lambda: check_canceled(cancel_event),
                     on_chunk=(lambda done: progress(done, total)) if progress else None, chunk=chunk)
    return digest.hexdigest()


def _stop_process(proc, group=False):
    """Ask a child (or, with group=True, its whole process group) to stop; kill it if it does not."""
    def send(sig):
        if group:
            os.killpg(os.getpgid(proc.pid), sig)
        elif sig == signal.SIGTERM:
            proc.terminate()
        else:
            proc.kill()

    try:
        send(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            send(signal.SIGKILL)
    except (OSError, ProcessLookupError):
        pass


def run_cmd(args, log, check=True, timeout=None, cancel_event=None):
    """Run a command as the current user, streaming its output to `log`.

    `timeout` (seconds) kills a command that hangs. `cancel_event` makes it stop
    promptly when the user cancels: the process is terminated and OperationCanceled
    is raised. Passing neither keeps the original behaviour.
    """
    log(f"$ {' '.join(args)}")
    # errors="replace": a file name that is not valid UTF-8 (rsync -v lists them) must not abort the copy.
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            errors="replace", bufsize=1)
    state = {"timed_out": False, "canceled": False}
    finished = threading.Event()

    def watchdog():
        deadline = None if timeout is None else time.monotonic() + timeout
        while not finished.wait(0.2):
            if cancel_event is not None and cancel_event.is_set():
                state["canceled"] = True
            elif deadline is not None and time.monotonic() >= deadline:
                state["timed_out"] = True
            else:
                continue
            _stop_process(proc)
            return

    watcher = None
    if timeout is not None or cancel_event is not None:
        watcher = threading.Thread(target=watchdog, daemon=True)
        watcher.start()
    try:
        for line in proc.stdout:
            log(line.rstrip())
        proc.wait()
    finally:
        finished.set()
        if watcher is not None:
            watcher.join(10)
        if proc.stdout:
            proc.stdout.close()
    if state["canceled"]:
        raise OperationCanceled("Canceled by the user.")
    if state["timed_out"]:
        log(f"Command timed out after {timeout}s and was stopped: {args[0]}")
        if check:
            raise RuntimeError(f"Command timed out after {timeout}s: {' '.join(args)}")
        return proc.returncode if proc.returncode else -1
    if check and proc.returncode != 0:
        raise RuntimeError(f"Command failed (exit code {proc.returncode}): {' '.join(args)}")
    return proc.returncode


@contextlib.contextmanager
def cancel_flag(cancel_event):
    """Yield the path of a private flag file that appears when `cancel_event` is set.

    The privileged write script runs as root, so the app cannot signal it. Instead the
    script polls for this file and stops dd itself. The file lives in a fresh 0700
    directory owned by the user; the script only tests whether the path exists.
    """
    flag_dir = tempfile.mkdtemp(prefix="win11cancel_")
    path = os.path.join(flag_dir, "cancel")
    stop = threading.Event()

    def watch():
        while not stop.is_set():
            if cancel_event is None:
                return
            if cancel_event.wait(0.25):
                try:
                    open(path, "w").close()
                except OSError:
                    pass
                return

    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()
    try:
        yield path
    finally:
        stop.set()
        watcher.join(2)
        _silent_remove(path)
        _silent_rmdir(flag_dir)


@contextlib.contextmanager
def prevent_sleep(log=None):
    """Keep the computer awake while a write runs. Best effort: failures are ignored."""
    proc = None
    stopper = None
    try:
        if IS_MAC and shutil.which("caffeinate"):
            # -i: no idle sleep; -w: stop by itself when our process exits.
            cmd = ["caffeinate", "-i", "-w", str(os.getpid())]
        elif IS_LINUX and shutil.which("systemd-inhibit"):
            # A bounded sleep (not "infinity"): if the app is killed without cleanup, the
            # inhibitor still ends by itself instead of keeping the machine awake forever.
            cmd = ["systemd-inhibit", "--what=sleep:idle", f"--who={APP_NAME}",
                   "--why=Writing a USB drive", "sleep", str(SLEEP_INHIBIT_SECONDS)]
        else:
            cmd = None
        if cmd:
            # Own process group, so stopping it also stops systemd-inhibit's `sleep`.
            proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, start_new_session=True)
            try:
                proc.wait(timeout=SLEEP_INHIBIT_CHECK_SECONDS)
            except subprocess.TimeoutExpired:
                # Still running after the check: the inhibitor is really holding. Make sure it
                # is also stopped if the app exits without leaving this block.
                def stopper(p=proc):
                    _stop_process(p, group=True)

                atexit.register(stopper)
                if log:
                    log("Sleep is blocked while the drive is being written.")
            else:
                proc = None  # it exited at once (no session bus, unsupported, ...): nothing is held
    except (OSError, subprocess.SubprocessError):
        proc = None
    try:
        yield
    finally:
        if stopper is not None:
            atexit.unregister(stopper)
        if proc is not None:
            _stop_process(proc, group=True)


def platform_display_name():
    if IS_MAC:
        return "macOS"
    if IS_LINUX:
        try:
            info = platform.freedesktop_os_release()
            return info.get("PRETTY_NAME", "Linux")
        except Exception:
            return "Linux"
    return platform.system()


# ---- Modal dialogs. Built by hand instead of tkinter.simpledialog: on Tk 9 (current Homebrew Python on
# macOS) simpledialog raises TclError because it calls a removed Tcl command, which made the whole
# "Create" button fail silently. The three helpers below are all the two dialogs have in common. ----
def _new_dialog(parent, title):
    """An empty, fixed-size dialog window; the caller adds its content, buttons and then shows it."""
    top = tk.Toplevel(parent)
    top.title(title)
    top.resizable(False, False)
    return top


def _dialog_buttons(top, accept, accept_text, accept_state="normal"):
    """The Cancel / accept button row. Return accepts, Escape and the window's close button cancel.

    `accept(event=None)` is the caller's; cancelling just destroys the dialog. `accept_text` is already
    translated (it is a literal `_()` at the call site). Returns the accept button.
    """
    def cancel(_event=None):
        top.destroy()

    row = ttk.Frame(top)
    row.pack(padx=16, pady=14, anchor="e")
    ttk.Button(row, text=_("Cancel"), command=cancel).pack(side="left", padx=(0, 8))
    accept_btn = ttk.Button(row, text=accept_text, command=accept, state=accept_state)
    accept_btn.pack(side="left")
    top.bind("<Return>", accept)
    top.bind("<Escape>", cancel)
    top.protocol("WM_DELETE_WINDOW", cancel)
    return accept_btn


def _show_modal(parent, top, focus_widget, y_offset):
    """Show `top` over `parent` and block until it is closed.

    Centred horizontally, `y_offset` pixels below the parent's top edge. Always on top: a prompt hidden
    behind the main window looks like a freeze.
    """
    top.update_idletasks()
    x = parent.winfo_rootx() + max((parent.winfo_width() - top.winfo_reqwidth()) // 2, 0)
    y = parent.winfo_rooty() + y_offset
    top.geometry(f"+{x}+{y}")
    top.transient(parent)
    top.attributes("-topmost", True)
    top.lift()
    try:
        top.wait_visibility()
        top.grab_set()
    except tk.TclError:
        pass  # grab is a nicety; the dialog still works without it
    focus_widget.focus_force()
    parent.wait_window(top)


def ask_password(parent, title, prompt):
    """Modal password prompt. Returns the text, or None if canceled. GUI thread only.

    Built by hand, not with tkinter.simpledialog (see the note above _new_dialog).
    """
    top = _new_dialog(parent, title)
    result = {"pw": None}

    ttk.Label(top, text=prompt, justify="left", wraplength=420).pack(padx=16, pady=(16, 8), anchor="w")
    entry = ttk.Entry(top, show="*", width=44)
    entry.pack(padx=16, fill="x")

    def accept(_event=None):
        result["pw"] = entry.get()
        top.destroy()

    _dialog_buttons(top, accept, _("OK"))
    _show_modal(parent, top, entry, y_offset=80)
    return result["pw"]


def normalize_typed_identifier(text):
    """What the user typed as a disk identifier, with whitespace and a '/dev/' prefix removed.

    The window's confirmation dialog and the command line (--disk, the typed confirmation) both use it.
    """
    text = (text or "").strip()
    return text[len("/dev/"):] if text.startswith("/dev/") else text


def build_typed_confirmation_dialog(parent, title, message, expected, reasons=()):
    """Build (without showing it modally) the "type the drive identifier" dialog.

    Returns (top, entry, erase_btn, result). The Erase button follows the text through a
    StringVar write trace, so every way of changing the text counts: typing, a mouse paste,
    the Edit menu, drag and drop. Reacting to key releases only left it disabled after a mouse paste.
    """
    top = _new_dialog(parent, title)
    result = {"ok": False}

    ttk.Label(top, text=message, justify="left", wraplength=520).pack(padx=16, pady=(16, 8), anchor="w")
    if reasons:
        ttk.Label(top, text=_("This drive does not look like a spare USB stick:"), foreground="#c62828",
                  justify="left").pack(padx=16, anchor="w")
        for reason in reasons:
            ttk.Label(top, text="\u2022 " + reason, foreground="#c62828", justify="left",
                      wraplength=500).pack(padx=(28, 16), anchor="w")
    ttk.Label(top, text=_("To confirm, type the drive identifier exactly as shown ({expected}):").format(
        expected=expected), justify="left", wraplength=520).pack(padx=16, pady=(12, 4), anchor="w")
    typed = tk.StringVar(master=top)
    entry = ttk.Entry(top, width=30, textvariable=typed)
    entry.pack(padx=16, anchor="w")

    def matches():
        return normalize_typed_identifier(typed.get()) == expected

    def accept(_event=None):
        if matches():
            result["ok"] = True
            top.destroy()

    erase_btn = _dialog_buttons(top, accept, _("Erase this drive"), accept_state="disabled")
    typed.trace_add("write", lambda *_args: erase_btn.config(state="normal" if matches() else "disabled"))
    top._typed = typed  # keep the variable alive as long as the dialog
    return top, entry, erase_btn, result


def ask_typed_confirmation(parent, title, message, expected, reasons=()):
    """Modal "type the drive identifier to continue" dialog. Returns True only on an exact match.

    Used for high-risk drives. Built by hand (see ask_password): no simpledialog on Tk 9. The
    confirm button stays disabled until the text matches, so Enter cannot slip through.
    """
    top, entry, _erase_btn, result = build_typed_confirmation_dialog(parent, title, message, expected, reasons)
    _show_modal(parent, top, entry, y_offset=60)
    return result["ok"]


# ============================================================
# Privilege escalation (Linux always; macOS only for raw writes —
# diskutil/hdiutil need no root, but writing /dev/rdiskN does)
# ============================================================
def _sudo_refresh():
    """True if sudo accepts us without a password right now (`sudo -n -v`), which also renews its credential
    timestamp. Never raises."""
    try:
        proc = subprocess.run(["sudo", "-n", "-v"], stdin=subprocess.DEVNULL,
                              capture_output=True, timeout=SUDO_TIMEOUT)
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


def _sudo_refresh_loop(stop_event, max_seconds=None):
    """Keep sudo's credential timestamp alive while an operation runs (the thread body of both privilege
    helpers): refresh it every SUDO_KEEPALIVE_SECONDS until `stop_event` is set, or until `max_seconds`
    have passed (None: no limit)."""
    deadline = None if max_seconds is None else time.monotonic() + max_seconds
    while not stop_event.wait(SUDO_KEEPALIVE_SECONDS) and (deadline is None or time.monotonic() < deadline):
        _sudo_refresh()


class PrivilegeHelper:
    """Runs privileged scripts through sudo (or pkexec), asking for the password once.

    After the password is validated, sudo's own timestamp carries the authorization:
    scripts run with `sudo -n` (nothing on stdin) and a small keep-alive refreshes the
    timestamp while an operation runs, so the password is not held in memory for the
    whole write. If that does not work on this machine (for example `timestamp_timeout=0`
    or per-process tickets), the helper falls back to keeping the validated password
    and passing it on stdin. In every mode a script that fails is NEVER run again.
    """

    def __init__(self, app):
        self.app = app
        self.cached_password = None   # only set in the stdin fallback mode
        self._use_timestamp = False   # True: sudo's timestamp is armed, no password held
        self._keepalive_stop = None

    def _ask_password_on_main_thread(self, retry=False):
        result = {}
        done = threading.Event()
        prefix = _("That password was not accepted. Try again.\n\n") if retry else ""

        def ask():
            try:
                result["pw"] = ask_password(
                    self.app,
                    _("Administrator password"),
                    prefix +
                    _("Enter your sudo/administrator password to partition and format the drive.\n"
                      "It is used only to run local disk commands and is never stored or sent anywhere."),
                )
            finally:
                done.set()  # never leave the worker thread waiting forever

        self.app.after(0, ask)
        done.wait()
        return result.get("pw")

    def check_password(self, password):
        """True if `password` is accepted by sudo. Never raises, never logs the password.

        `-k` makes sudo ignore any cached credential, so a wrong password cannot slip
        through because a previous sudo session is still valid. The password goes to
        stdin only, as in run_script().
        """
        if not password:
            return False
        try:
            proc = subprocess.run(
                ["sudo", "-S", "-k", "-p", "", "true"],
                input=password + "\n", capture_output=True, text=True, timeout=SUDO_TIMEOUT)
        except (OSError, subprocess.SubprocessError):
            return False
        return proc.returncode == 0

    def needs_password(self):
        """Whether a sudo password must be collected before running privileged commands."""
        return os.geteuid() != 0 and bool(shutil.which("sudo"))

    # ---------- sudo timestamp (no password kept in memory) ----------
    def _sudo_probe(self):
        """True if sudo currently accepts us without a password (and refreshes its timestamp)."""
        return _sudo_refresh()

    def _arm_timestamp(self, password):
        """Validate with `sudo -S -v`, then confirm a fresh `sudo -n` process is accepted.

        The second step is what proves the timestamp is shared between our sudo calls on
        this machine; if it is not, the caller falls back to the stdin mode.
        """
        try:
            proc = subprocess.run(["sudo", "-S", "-v", "-p", ""], input=password + "\n",
                                  capture_output=True, text=True, timeout=SUDO_TIMEOUT)
        except (OSError, subprocess.SubprocessError):
            return False
        return proc.returncode == 0 and self._sudo_probe()

    def _start_keepalive(self):
        self._stop_keepalive()
        stop = threading.Event()
        self._keepalive_stop = stop
        threading.Thread(target=_sudo_refresh_loop, args=(stop, SUDO_KEEPALIVE_MAX_SECONDS), daemon=True).start()

    def _stop_keepalive(self):
        stop, self._keepalive_stop = self._keepalive_stop, None
        if stop is not None:
            stop.set()

    def _adopt(self, secret):
        """Take a validated password: arm sudo's timestamp and drop the string if that works."""
        if self._arm_timestamp(secret):
            self._use_timestamp = True
            self.cached_password = None
            self._start_keepalive()
        else:
            self._use_timestamp = False
            self.cached_password = secret

    def _ensure_auth(self, max_attempts=3):
        """Make sure scripts can run. Returns "ts" (sudo timestamp) or "pw" (stdin fallback).

        Passwords are validated here, BEFORE any script runs, so a wrong password is
        never discovered by re-running a script. Asks at most `max_attempts` times.
        """
        if self._use_timestamp:
            if self._sudo_probe():
                return "ts"
            self._use_timestamp = False  # expired or revoked: ask again
            self._stop_keepalive()
        if self.cached_password is not None:
            return "pw"
        for attempt in range(max_attempts):
            entered = self._ask_password_on_main_thread(retry=attempt > 0)
            if entered is None:
                raise RuntimeError("Administrator password entry canceled.")
            if self.check_password(entered):
                self._adopt(entered)
                entered = None
                return "ts" if self._use_timestamp else "pw"
        raise RuntimeError("The administrator password was not accepted after "
                           f"{max_attempts} attempts. Nothing was changed.")

    def authenticate(self, reason, max_attempts=3):
        """Ask for the administrator password up front and verify it. GUI thread only.

        Doing this before anything touches the drive means a wrong or missing password
        is caught while the drive is still untouched, instead of mid-operation.
        Returns True when privileges are available (sudo's timestamp is armed, or as a
        fallback the password is kept in memory for this operation).
        """
        if not self.needs_password():
            return True  # already root, or pkexec will show its own prompt
        for attempt in range(max_attempts):
            pw = ask_password(
                self.app,
                _("Administrator password"),
                _("{reason}\n\nEnter your administrator (sudo) password.\n"
                  "It is used only to run local disk commands and is never stored or sent anywhere.").format(
                      reason=reason),
            )
            if pw is None:
                return False  # canceled
            if self.check_password(pw):
                self._adopt(pw)
                pw = None  # the string is not needed any more
                return True
            if attempt < max_attempts - 1:
                messagebox.showerror(_("Wrong password"), _("That password was not accepted. Please try again."),
                                     parent=self.app)
        messagebox.showerror(_("Wrong password"), _("Too many incorrect attempts. Nothing was changed."),
                             parent=self.app)
        return False

    def clear_cached_password(self):
        """Forget the password and end the sudo session as soon as it is no longer needed."""
        self.cached_password = None
        self._stop_keepalive()
        if self._use_timestamp:
            self._use_timestamp = False
            try:
                subprocess.run(["sudo", "-k"], stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
            except (OSError, subprocess.SubprocessError):
                pass

    def run_script(self, script, log, args=None, max_attempts=3):
        """Run `script` with root privileges, exactly once.

        Values are NEVER interpolated into the script text. They are passed as
        positional shell parameters ("$1", "$2", ...) via `args`, so a filename
        containing quotes, semicolons or $(...) is treated as data, not as code.

        A script that exits non-zero raises RuntimeError and is never re-run: a failed
        mkfs or dd must not be repeated behind the user's back. Password problems are
        handled before the script starts (_ensure_auth). `max_attempts` is accepted for
        backward compatibility and limits only the password prompts.
        """
        args = [str(a) for a in (args or [])]
        # bash -c SCRIPT NAME ARG1 ARG2 ... -> inside SCRIPT: $0=NAME, $1=ARG1, ...
        bash_argv = ["bash", "-c", script, "win11_usb_creator"] + args

        sudo_prefix, use_stdin = [], False   # already root: no sudo
        if os.geteuid() == 0:
            pass
        elif shutil.which("sudo"):
            use_stdin = self._ensure_auth(max_attempts) != "ts"
            sudo_prefix = ["sudo", "-n"]   # used unless the stdin fallback is needed
        elif shutil.which("pkexec"):
            return run_cmd(["pkexec"] + bash_argv, log)
        else:
            raise RuntimeError(
                "Neither 'sudo' nor 'pkexec' was found. Install sudo (or run this app as root) "
                "so it can partition and format drives."
            )

        if use_stdin and self.cached_password is None:
            raise RuntimeError("The administrator session ended before the command started. "
                               "Nothing was changed; start the operation again.")
        popen_kw = {"stdout": subprocess.PIPE, "stderr": subprocess.STDOUT, "text": True,
                    "errors": "replace", "bufsize": 1}
        if use_stdin:
            proc = subprocess.Popen(["sudo", "-S", "-p", ""] + bash_argv, stdin=subprocess.PIPE, **popen_kw)
        else:
            proc = subprocess.Popen(sudo_prefix + bash_argv, stdin=subprocess.DEVNULL, **popen_kw)
        if use_stdin:
            # The password goes only to stdin: it never appears in the process
            # argument list (visible to other users via `ps`) nor in any log.
            password = self.cached_password
            proc.stdin.write(password + "\n")
            proc.stdin.flush()
            proc.stdin.close()
        log("$ sudo bash -c '<privileged script>' " + " ".join(repr(a) for a in args))
        refused = False
        for line in proc.stdout:
            line = line.rstrip()
            if "a password is required" in line and line.startswith("sudo:"):
                refused = True
            log(line)
        proc.wait()
        proc.stdout.close()
        if proc.returncode == 0:
            return None
        audit(f"Privileged script failed (exit {proc.returncode}); not retried", logging.ERROR)
        if refused:
            self._use_timestamp = False
            raise RuntimeError(
                "The administrator session expired before the command started, so it did not "
                "run and nothing was changed. Start the operation again.")
        raise RuntimeError(
            f"Privileged command failed (exit code {proc.returncode}). It was not run again; "
            "check the log above for the reason.")


# ============================================================
# Disk description and risk assessment (pure functions: no I/O, unit-testable)
#
# A disk dict always has `id`, `size`, `label`. The listing code adds, when it can:
#   model     str                 vendor + product name, e.g. "SanDisk Ultra"
#   volumes   list[dict] | None   what is on the drive (None = could not be inspected)
#             each: name, filesystem, size, used (bytes or None), mountpoint (or None)
#   identity  tuple of (key, value) pairs, stable identifiers (serial, WWN, DiskUUID, model)
# ============================================================
LARGE_DISK_BYTES = 256 * 1024 ** 3        # bigger than this is more likely a backup disk than a stick
SUBSTANTIAL_USED_BYTES = 16 * 1024 ** 3   # an old installer stick holds ~6 GB; more means real data
MANY_VOLUMES = 4
DATA_VOLUME_NAME_RE = re.compile(
    r"back\s*-?up|bkp|time\s*machine|archive|arquivo|photos?|fotos?|document|dados|\bdata\b|"
    r"storage|media|movies|music|clone|vault|\bhd\b|\bfiles\b", re.IGNORECASE)
DATA_DRIVE_MODEL_RE = re.compile(
    r"passport|elements|expansion|backup\s*plus|my\s*book|canvio|portable|\bssd\b|\bhdd\b|external|rugged",
    re.IGNORECASE)
MAX_VOLUMES_SHOWN = 8


def make_identity(**parts):
    """Normalise stable identifiers into a sorted tuple of (key, value); empty values are dropped."""
    return tuple(sorted((k, str(v).strip()) for k, v in parts.items() if v is not None and str(v).strip()))


def identity_mismatch(expected, actual):
    """Describe how `actual` differs from `expected`, or return None when it is the same drive.

    Every identifier recorded at listing time must still be present and equal. Identifiers
    that only show up now are ignored. With no recorded identity there is nothing to compare.
    """
    if not expected:
        return None
    now = dict(actual or ())
    for key, value in expected:
        if now.get(key) != value:
            return f"{key} changed"
    return None


def _text_for(translate):
    """`_` when the text is for the GUI, a pass-through for engine/CLI callers (always English)."""
    return _ if translate else (lambda text: text)


def format_volume_line(vol, translate=False):
    """One human-readable line describing a volume, e.g. 'Untitled (FAT32, 58.0 GB, 12.3 GB used)'.

    `translate=True` is for the GUI dialogs only; the default keeps the English text.
    """
    _ = _text_for(translate)
    bits = []
    if vol.get("filesystem"):
        bits.append(str(vol["filesystem"]))
    if vol.get("size"):
        bits.append(human_size(vol["size"]))
    if vol.get("used") is not None:
        bits.append(_("{size} used").format(size=human_size(vol["used"])))
    elif vol.get("mountpoint") is None:
        bits.append(_("not mounted, usage unknown"))
    name = vol.get("name") or _("(unnamed)")
    return f"{name} ({', '.join(bits)})" if bits else name


def build_disk_label(dev_path, model, size, volumes):
    """The text shown in the drive list: '/dev/disk4 — SanDisk Ultra — 58.6 GB — 2 volumes (...)'."""
    parts = [dev_path]
    if model:
        parts.append(model)
    parts.append(human_size(size))
    if volumes is None:
        parts.append("contents unknown")
    elif not volumes:
        parts.append("no volumes")
    else:
        names = [repr(v.get("name") or v.get("filesystem") or "unnamed") for v in volumes[:3]]
        if len(volumes) > 3:
            names.append("…")
        noun = "volume" if len(volumes) == 1 else "volumes"
        parts.append(f"{len(volumes)} {noun} ({', '.join(names)})")
    return " — ".join(parts)


def _disk_entry(dev_id, size, model, volumes, identity):
    """The record the drive list holds for one disk: id, size, label (built here), model, volumes, identity."""
    return {"id": dev_id, "size": size, "label": build_disk_label(f"/dev/{dev_id}", model, size, volumes),
            "model": model, "volumes": volumes, "identity": identity}


def assess_disk_risk(disk, translate=False):
    """Return (level, reasons): level is 'high' or 'normal'; reasons explain every 'high'.

    High means "this does not look like a spare USB stick": it is large, holds a lot of data,
    has a name that suggests backups/personal data, looks like an external HDD/SSD, has many
    partitions, or its contents could not be read. High-risk drives need the identifier typed
    before they can be erased. A disk dict without a 'volumes' key (not inspected at all) is not
    penalised for that; a 'volumes' of None (inspection failed) is. `translate=True` (GUI dialogs
    only) words the reasons in the active language; the default keeps them in English.
    """
    _ = _text_for(translate)
    reasons = []
    size = disk.get("size") or 0
    if size > LARGE_DISK_BYTES:
        reasons.append(_("It is large ({size}); installer sticks are usually much smaller. "
                         "This may be an external hard disk or SSD.").format(size=human_size(size)))
    model = disk.get("model") or ""
    if model and DATA_DRIVE_MODEL_RE.search(model):
        reasons.append(_("Its model name ({model}) suggests an external hard disk or SSD.").format(model=model))
    if "volumes" in disk:
        volumes = disk["volumes"]
        if volumes is None:
            reasons.append(_("What is stored on it could not be read, "
                             "so there is no way to tell what would be lost."))
        else:
            used = sum(v.get("used") or 0 for v in volumes)
            if used >= SUBSTANTIAL_USED_BYTES:
                reasons.append(_("It holds a lot of data ({size} in use).").format(size=human_size(used)))
            named = [v.get("name") for v in volumes if v.get("name") and DATA_VOLUME_NAME_RE.search(v["name"])]
            if named:
                reasons.append(_("Volume name(s) suggest personal data or backups: {names}.").format(
                    names=", ".join(repr(n) for n in named[:3])))
            if len(volumes) >= MANY_VOLUMES:
                reasons.append(_("It has {count} volumes, which is unusual for a USB stick.").format(
                    count=len(volumes)))
    return ("high" if reasons else "normal"), reasons


def describe_disk_for_confirmation(disk, translate=False):
    """Multi-line summary (model, size, every volume with its used space) for the final confirmation.

    `translate=True` is for the GUI dialog only; the default keeps the English text.
    """
    _ = _text_for(translate)
    lines = [_("Drive: /dev/{id}").format(id=disk.get("id"))]
    if disk.get("model"):
        lines.append(_("Model: {model}").format(model=disk["model"]))
    lines.append(_("Size: {size}").format(size=human_size(disk.get("size") or 0)))
    volumes = disk.get("volumes")
    if volumes is None:
        lines.append(_("Contents: could not be read"))
    elif not volumes:
        lines.append(_("Contents: no volumes found (the drive looks empty)"))
    else:
        lines.append(_("Contents that will be DESTROYED:"))
        lines.extend("  - " + format_volume_line(v, translate) for v in volumes[:MAX_VOLUMES_SHOWN])
        if len(volumes) > MAX_VOLUMES_SHOWN:
            lines.append(_("  - ... and {count} more").format(count=len(volumes) - MAX_VOLUMES_SHOWN))
    return "\n".join(lines)


# Identity recorded for the drive the user selected; checked again right before erasing.
# (Kept here, not in build_usb's signature, so the check cannot be forgotten by a caller.)
_pinned_identities = {}


def pin_target_identity(dev, identity):
    """Remember the identity of the drive the user confirmed; reverify_target_disk() enforces it."""
    if identity:
        _pinned_identities[dev] = tuple(identity)
    else:
        _pinned_identities.pop(dev, None)


# ============================================================
# macOS backend
# ============================================================
def _diskutil_plist(*args, timeout=QUERY_TIMEOUT):
    """Run `diskutil <args>` (an -plist query) and return the parsed property list.

    Raises whatever subprocess or plistlib raise; the callers decide what a failure means (the drive
    listing fails closed: a disk that cannot be queried is hidden, never offered).
    """
    return plistlib.loads(subprocess.check_output(["diskutil", *args], timeout=timeout))


def _diskutil_info(node):
    """`diskutil info -plist /dev/<node>` for a disk or partition identifier such as 'disk4' or 'disk4s1'."""
    return _diskutil_plist("info", "-plist", f"/dev/{node}")


def macos_usb_device_map():
    """Map BSD names ('disk4', 'disk4s1', ...) to the USB device that carries them.

    Parses `ioreg` (the only place macOS exposes the USB serial number). Best effort: returns
    {} on any failure, since this only enriches the description of a drive.
    """
    try:
        out = subprocess.check_output(["ioreg", "-a", "-r", "-c", "IOUSBHostDevice", "-l"],
                                      stderr=subprocess.DEVNULL, timeout=IOREG_TIMEOUT)
        roots = plistlib.loads(out)
    except Exception as e:
        audit(f"USB serial lookup unavailable ({type(e).__name__})", logging.WARNING)
        return {}
    found = {}

    def walk(node, usb):
        if not isinstance(node, dict):
            return
        if node.get("IOObjectClass") == "IOUSBHostDevice":
            usb = {
                "serial": node.get("kUSBSerialNumberString") or node.get("USB Serial Number") or "",
                "vendor": node.get("USB Vendor Name") or "",
                "product": node.get("USB Product Name") or "",
            }
        bsd = node.get("BSD Name")
        if usb is not None and isinstance(bsd, str):
            found[bsd] = usb
        for child in node.get("IORegistryEntryChildren", []) or []:
            walk(child, usb)

    for root in roots if isinstance(roots, list) else []:
        walk(root, None)
    return found


def macos_apfs_volumes_by_store():
    """Map the partition holding an APFS container ('disk4s2') to that container's volumes."""
    try:
        data = _diskutil_plist("list", "-plist")
    except Exception:
        return {}
    by_store = {}
    for entry in data.get("AllDisksAndPartitions", []):
        for store in entry.get("APFSPhysicalStores", []) or []:
            vols = []
            for v in entry.get("APFSVolumes", []) or []:
                vols.append({
                    "name": v.get("VolumeName") or "",
                    "filesystem": "APFS",
                    "size": entry.get("Size") or 0,
                    "used": v.get("CapacityInUse"),
                    "mountpoint": v.get("MountPoint") or None,
                })
            by_store[store.get("DeviceIdentifier")] = vols
    return by_store


def _used_bytes(mountpoint):
    """Bytes in use on a mounted filesystem, or None."""
    if not mountpoint:
        return None
    try:
        usage = shutil.disk_usage(mountpoint)
        return usage.total - usage.free
    except Exception:
        return None


def macos_describe_disk(entry, info, usb_map, apfs_map):
    """(model, volumes, identity) for one external disk. `volumes` is None if it cannot be read."""
    dev = entry.get("DeviceIdentifier")
    usb = usb_map.get(dev) or {}
    media = str(info.get("MediaName") or "").strip()
    vendor = str(usb.get("vendor") or "").strip()
    model = media or str(usb.get("product") or "").strip()
    if vendor and vendor.lower() not in model.lower():
        model = f"{vendor} {model}".strip()
    identity = make_identity(serial=usb.get("serial"), model=media or usb.get("product"),
                             diskuuid=info.get("DiskUUID"))
    volumes = []
    try:
        for part in entry.get("Partitions", []) or []:
            pid = part.get("DeviceIdentifier")
            if str(part.get("Content", "")).startswith("Apple_APFS") and apfs_map.get(pid):
                volumes.extend(apfs_map[pid])
                continue
            pinfo = _diskutil_info(pid)
            mountpoint = pinfo.get("MountPoint") or part.get("MountPoint") or None
            volumes.append({
                "name": part.get("VolumeName") or pinfo.get("VolumeName") or "",
                "filesystem": pinfo.get("FilesystemUserVisibleName") or pinfo.get("FilesystemName")
                              or str(part.get("Content") or ""),
                "size": part.get("Size") or 0,
                "used": _used_bytes(mountpoint),
                "mountpoint": mountpoint,
            })
    except Exception as e:
        audit(f"Could not inspect the volumes of {dev} ({type(e).__name__})", logging.WARNING)
        volumes = None
    return model, volumes, identity


def macos_get_external_disks():
    """List only EXTERNAL physical disks attached over USB (never the Mac's internal disk)."""
    data = _diskutil_plist("list", "-plist", "external", "physical")
    usb_map = None  # looked up lazily: only needed when at least one disk qualifies
    apfs_map = None
    disks = []
    for d in data.get("AllDisksAndPartitions", []):
        dev = d.get("DeviceIdentifier")
        if not dev or not MAC_DEVICE_RE.fullmatch(dev):
            continue
        size = d.get("Size") or 0
        if not isinstance(size, int) or size <= 0:
            # An empty card reader reports no media (0 bytes): there is nothing to write to.
            audit(f"Hiding {dev}: its size is zero or unreadable", logging.WARNING)
            continue
        try:
            info = _diskutil_info(dev)
        except Exception as e:
            # Fail closed: if we cannot confirm the disk is external, do not offer
            # it for erasure. Previously this fell back to {} and the Internal
            # check silently passed, which could expose the system disk.
            audit(f"Hiding {dev}: could not verify it is external ({type(e).__name__})", logging.WARNING)
            continue
        if info.get("Internal", False):
            continue  # extra safety: never list the internal disk
        if not info.get("Removable", True) and not info.get("Ejectable", True):
            continue
        if str(info.get("BusProtocol", "")).upper() != "USB":
            continue  # only USB drives are offered (no SD cards, Thunderbolt/NVMe enclosures, disk images)
        # Descriptive extras (model, volumes, identity). Failing to gather them never hides
        # or exposes a disk: the safety filters above have already decided that.
        if usb_map is None:
            usb_map = macos_usb_device_map()
            apfs_map = macos_apfs_volumes_by_store()
        model, volumes, identity = macos_describe_disk(d, info, usb_map, apfs_map)
        disks.append(_disk_entry(dev, size, model, volumes, identity))
    return disks


def macos_find_mountpoint_by_volname(dev, volname, retries=15):
    for _ in range(retries):
        data = _diskutil_plist("list", "-plist", f"/dev/{dev}")
        entries = data.get("AllDisksAndPartitions", [])
        parts = entries[0].get("Partitions", []) if entries else []
        for part in parts:
            if part.get("VolumeName", "").upper() == volname.upper():
                pid = part.get("DeviceIdentifier")
                info = _diskutil_info(pid)
                mp = info.get("MountPoint")
                if mp:
                    return mp
        time.sleep(1)
    raise RuntimeError("Could not find the USB drive's mount point after formatting.")


def macos_unmount(dev, log, check=True, force=False):
    """Unmount every volume of the whole disk (`diskutil unmountDisk`); `force` also takes busy ones.

    Returns run_cmd's exit code; with check=True a failure raises, with check=False it is only returned.
    """
    cmd = ["diskutil", "unmountDisk"] + (["force"] if force else []) + [f"/dev/{dev}"]
    return run_cmd(cmd, log, check=check, timeout=DISKUTIL_TIMEOUT)


def macos_build_usb(iso_path, dev, log, priv=None, progress=None, cancel_event=None, eject=True,
                    hardening_files=None):
    check_canceled(cancel_event, drive_touched=False)  # nothing has been changed yet
    log(f"Erasing and formatting /dev/{dev} as GPT + FAT32 ('{VOL_NAME}')...")
    run_cmd(["diskutil", "eraseDisk", "FAT32", VOL_NAME, "GPT", f"/dev/{dev}"], log, timeout=600)

    target = macos_find_mountpoint_by_volname(dev, VOL_NAME)
    log(f"USB drive ready at: {target}")
    check_canceled(cancel_event)

    mount_dir = tempfile.mkdtemp(prefix="win11iso_")
    log(f"Mounting the ISO at {mount_dir}...")
    try:
        run_cmd(["hdiutil", "attach", iso_path, "-nobrowse", "-readonly", "-mountpoint", mount_dir], log,
                timeout=300)
    except Exception:
        _silent_rmdir(mount_dir)
        raise

    try:
        def reopen():
            log("Remounting the drive to read it back from the device...")
            macos_unmount(dev, log)
            run_cmd(["diskutil", "mountDisk", f"/dev/{dev}"], log, timeout=DISKUTIL_TIMEOUT)
            return macos_find_mountpoint_by_volname(dev, VOL_NAME)

        copy_windows_payload(
            mount_dir, target, log, progress,
            "wimlib-imagex not found. Install it with: brew install wimlib "
            "(or use the 'Install missing dependencies' button).",
            reopen=reopen, cancel_event=cancel_event,
            **({"extra_files": hardening_files,
                "write_extra": lambda root: write_hardening_files(root, hardening_files, cancel_event)}
               if hardening_files else {}))
    except OperationCanceled as e:
        if e.written:
            log("Canceled during verification. Unmounting the drive; the files were copied completely "
                "but NOT verified.")
        else:
            log("Canceled. Unmounting the drive; it is left incomplete and unusable.")
        macos_unmount(dev, log, check=False)
        raise
    finally:
        log("Unmounting the ISO...")
        run_cmd(["hdiutil", "detach", mount_dir, "-force"], log, check=False, timeout=DISKUTIL_TIMEOUT)
        _silent_rmdir(mount_dir)

    ejected = macos_eject(dev, log) if eject else None
    log("Done! The USB drive is ready to install Windows 11.")
    report_eject(ejected, log, skipped=not eject)
    return ejected


def macos_eject(dev, log):
    """Eject the whole disk; if something holds it, force-unmount and retry. Returns True on success."""
    log("Ejecting the USB drive...")
    if run_cmd(["diskutil", "eject", f"/dev/{dev}"], log, check=False, timeout=DISKUTIL_TIMEOUT) == 0:
        return True
    log("The drive is busy — forcing the unmount and trying again...")
    macos_unmount(dev, log, check=False, force=True)
    time.sleep(1)
    return run_cmd(["diskutil", "eject", f"/dev/{dev}"], log, check=False, timeout=DISKUTIL_TIMEOUT) == 0


def linux_eject(dev_name, log, priv):
    """Flush, unmount and power the drive off. Best effort: returns True if it was ejected."""
    log("Ejecting the USB drive (administrator privileges required)...")
    # Always exits 0 so a drive that cannot be powered off is not reported as a failure;
    # the outcome is reported through the EJECTED / NOT_EJECTED marker line.
    script = (
        'set -eu\n'
        'sync\n'
        'for p in "$1"[0-9]* "$1"p[0-9]*; do umount "$p" 2>/dev/null || true; done\n'
        'if command -v eject >/dev/null 2>&1 && eject "$1" 2>/dev/null; then echo EJECTED; exit 0; fi\n'
        'if command -v udisksctl >/dev/null 2>&1 && udisksctl power-off -b "$1" 2>/dev/null; '
        'then echo EJECTED; exit 0; fi\n'
        'echo NOT_EJECTED\n'
        'exit 0\n'
    )
    seen = []

    def watch(line):
        seen.append(line.strip())
        log(line)

    try:
        priv.run_script(script, watch, args=[f"/dev/{dev_name}"])
    except Exception as e:
        log(f"Warning: could not run the eject step: {e}")
        return False
    return "EJECTED" in seen


def report_eject(ejected, log, skipped=False):
    if skipped:
        log("The drive was left connected, as requested. Eject it before unplugging.")
    elif ejected:
        log("Drive ejected — you can unplug it now.")
    else:
        log("Could not eject automatically. Eject the drive from the file manager before unplugging it.")


# Root scripts that write the image. Values arrive as "$1".."$n" (never pasted into the
# text). "$4" is a flag file: the app creates it to ask for a cancel, and the loop below
# (which polls it once a second) then stops dd and prints WRITE_CANCELED.
MACOS_RAW_SCRIPT = (
    'set -eu\n'
    # A terminal Ctrl-C also reaches this script (same process group). Ignoring it keeps the
    # script alive to stop dd itself through the flag file; otherwise dd would be orphaned.
    "trap '' INT\n"
    'dd if="$1" of="$2" bs="$3" &\n'
    'pid=$!\n'
    'canceled=0\n'
    # BSD dd has no status=progress: it prints the byte count when it receives
    # SIGINFO, so ask for it once a second until the copy ends.
    'while kill -0 "$pid" 2>/dev/null; do\n'
    '  if [ -e "$4" ]; then kill "$pid" 2>/dev/null || true; canceled=1; break; fi\n'
    '  kill -INFO "$pid" 2>/dev/null || true\n'
    '  sleep 1\n'
    'done\n'
    'if [ "$canceled" = 1 ]; then wait "$pid" 2>/dev/null || true; echo WRITE_CANCELED; exit 0; fi\n'
    'wait "$pid"\n'
    'sync\n'
)

# "$5" is "direct" (add oflag=direct) or "buffered"; the caller decides, the text never changes.
LINUX_RAW_SCRIPT = (
    'set -eu\n'
    "trap '' INT\n"
    'for p in "$2"[0-9]* "$2"p[0-9]*; do umount "$p" 2>/dev/null || true; done\n'
    'if [ "$5" = direct ]; then\n'
    '  dd if="$1" of="$2" bs="$3" conv=fsync status=progress oflag=direct &\n'
    'else\n'
    '  dd if="$1" of="$2" bs="$3" conv=fsync status=progress &\n'
    'fi\n'
    'pid=$!\n'
    'canceled=0\n'
    'while kill -0 "$pid" 2>/dev/null; do\n'
    '  if [ -e "$4" ]; then kill "$pid" 2>/dev/null || true; canceled=1; break; fi\n'
    '  sleep 1\n'
    'done\n'
    'if [ "$canceled" = 1 ]; then wait "$pid" 2>/dev/null || true; echo WRITE_CANCELED; exit 0; fi\n'
    'wait "$pid"\n'
    'sync\n'
)


def write_raw_image(priv, script, base_args, log, total, progress, cancel_event, extra_args=()):
    """Run a root write script (MACOS_RAW_SCRIPT / LINUX_RAW_SCRIPT). True if it stopped on request.

    The script runs as root, so the app cannot signal it; `cancel_flag` gives it a file to
    watch instead. `base_args` are "$1".."$3", the flag path becomes "$4", then `extra_args`.
    """
    state = {"canceled": False}
    dd_log = make_dd_log(log, total, progress)

    def watch(line):
        if line.strip() == RAW_CANCELED_MARKER:
            state["canceled"] = True
            log("The write was stopped at your request.")
            return
        dd_log(line)

    with cancel_flag(cancel_event) as flag:
        priv.run_script(script, watch, args=list(base_args) + [flag] + list(extra_args))
    return state["canceled"]


def macos_write_raw(iso_path, dev, log, priv, progress=None, cancel_event=None, eject=True):
    """Write the ISO byte-for-byte to the whole disk (Linux and other hybrid ISOs)."""
    validate_hybrid_iso(iso_path)
    check_canceled(cancel_event, drive_touched=False)
    log(f"Unmounting /dev/{dev}...")
    macos_unmount(dev, log)
    check_canceled(cancel_event, drive_touched=False)  # unmounting changes no data
    log(f"Writing the ISO to /dev/{dev} (administrator privileges required). "
        "This can take several minutes.")
    total = os.path.getsize(iso_path)
    # /dev/rdiskN (raw node) is several times faster than /dev/diskN.
    canceled = write_raw_image(priv, MACOS_RAW_SCRIPT,
                               [iso_path, f"/dev/r{dev}", RAW_WRITE_BLOCK["mac"]],
                               log, total, progress, cancel_event)
    if canceled:
        log("Canceled. The drive holds a partial image and is unusable until written again.")
        macos_unmount(dev, log, check=False)
        raise OperationCanceled("Canceled by the user.")
    if progress:
        progress(total, total, "Written")
    verify_raw_write(iso_path, f"/dev/r{dev}", log, priv, progress, cancel_event)
    log("Note: macOS cannot read Linux or ChromeOS (ISO 9660/ext) images, so this drive will not show up in "
        "Finder, and macOS may say the disk is 'not readable' — click Ignore, never Initialize. "
        "That is normal; the content was just verified byte-for-byte.")
    ejected = macos_eject(dev, log) if eject else None
    log("Done! The USB drive is ready to boot.")
    report_eject(ejected, log, skipped=not eject)
    return ejected


# ============================================================
# Linux backend
# ============================================================
def linux_root_disk():
    try:
        src = subprocess.check_output(["findmnt", "-no", "SOURCE", "/"], text=True, timeout=QUERY_TIMEOUT).strip()
        pk = subprocess.check_output(["lsblk", "-no", "PKNAME", src], text=True, timeout=QUERY_TIMEOUT).strip()
        return pk or None
    except Exception as e:
        audit(f"Could not determine the system disk ({type(e).__name__}); "
              "falling back to mountpoint inspection", logging.WARNING)
        return None


def linux_disks_holding_critical_mounts():
    """Names of whole disks that currently host a critical system mountpoint.

    This is the safety net for machines that boot from a device flagged as
    removable (a Raspberry Pi booting from its SD card, a USB-booted system):
    there, the 'removable' flag alone would happily offer the system disk for
    erasure. Returns a set; an empty set means "could not determine".
    """
    unsafe = set()
    try:
        out = subprocess.check_output(
            ["lsblk", "-J", "-b", "-o", "NAME,TYPE,MOUNTPOINT,PKNAME"], text=True, timeout=QUERY_TIMEOUT)
        data = json.loads(out)

        def walk(node, top):
            mp = node.get("mountpoint")
            if mp and (mp in CRITICAL_MOUNTPOINTS or mp.startswith("/boot")):
                unsafe.add(top)
            for child in node.get("children", []) or []:
                walk(child, top)

        for dev in data.get("blockdevices", []):
            if dev.get("type") != "disk":
                continue
            walk(dev, dev.get("name"))
    except Exception as e:
        audit(f"Critical-mountpoint scan unavailable ({type(e).__name__})", logging.WARNING)
    return unsafe


LSBLK_COLUMN_SETS = (
    # Richest first; older util-linux rejects unknown columns, so fall back step by step.
    "NAME,SIZE,TYPE,RM,TRAN,SERIAL,WWN,MODEL,VENDOR,FSTYPE,LABEL,MOUNTPOINT,FSUSED",
    "NAME,SIZE,TYPE,RM,TRAN,SERIAL,WWN,MODEL,VENDOR,FSTYPE,LABEL,MOUNTPOINT",
    "NAME,SIZE,TYPE,RM,TRAN",
)


def _as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def linux_lsblk_disks():
    """`lsblk -J` as a list of top-level devices, using the richest column set this lsblk supports."""
    last_error = None
    for columns in LSBLK_COLUMN_SETS:
        try:
            out = subprocess.check_output(["lsblk", "-J", "-b", "-o", columns], text=True,
                                          stderr=subprocess.DEVNULL, timeout=QUERY_TIMEOUT)
            return json.loads(out).get("blockdevices", [])
        except Exception as e:
            last_error = e
    raise last_error


def linux_describe_disk(dev):
    """(model, volumes, identity) from one lsblk disk node. volumes is None without partition info."""
    try:
        return _linux_describe_disk(dev)
    except Exception as e:  # descriptive only: never let it change which disks are offered
        audit(f"Could not describe {dev.get('name')} ({type(e).__name__})", logging.WARNING)
        return "", None, ()


def _linux_describe_disk(dev):
    vendor = (dev.get("vendor") or "").strip()
    product = (dev.get("model") or "").strip()
    model = f"{vendor} {product}".strip() if vendor.lower() not in product.lower() else product
    identity = make_identity(serial=dev.get("serial"), wwn=dev.get("wwn"), model=model)
    if "fstype" not in dev:
        return model, None, identity  # this lsblk is too old to report filesystems
    nodes = [c for c in dev.get("children") or [] if c.get("type") == "part"]
    if dev.get("fstype"):
        nodes.append(dev)  # a filesystem written straight onto the disk, with no partition table
    volumes = []
    for node in nodes:
        mountpoint = node.get("mountpoint") or None
        used = _as_int(node.get("fsused"))
        if used is None:
            used = _used_bytes(mountpoint)
        volumes.append({
            "name": node.get("label") or node.get("name") or "",
            "filesystem": node.get("fstype") or "",
            "size": _as_int(node.get("size")) or 0,
            "used": used,
            "mountpoint": mountpoint,
        })
    return model, volumes, identity


def linux_get_external_disks():
    root_disk = linux_root_disk()
    unsafe_disks = linux_disks_holding_critical_mounts()
    if root_disk:
        unsafe_disks.add(root_disk)
    disks = []
    if shutil.which("lsblk"):
        try:
            for dev in linux_lsblk_disks():
                if dev.get("type") != "disk":
                    continue
                name = dev.get("name")
                if not name or not LINUX_DEVICE_RE.fullmatch(name):
                    continue
                if name in unsafe_disks:
                    audit(f"Hiding {name}: it hosts the system or a critical mountpoint")
                    continue
                if name.startswith(("loop", "zram", "dm-")):
                    continue
                if (dev.get("tran") or "").lower() != "usb":
                    continue  # only USB drives are offered
                size = _as_int(dev.get("size")) or 0
                if size <= 0:
                    # An empty card reader (transport "usb", no media) reports 0 bytes.
                    audit(f"Hiding {name}: its size is zero or unreadable", logging.WARNING)
                    continue
                model, volumes, identity = linux_describe_disk(dev)
                disks.append(_disk_entry(name, size, model, volumes, identity))
            return disks
        except Exception as e:
            audit(f"lsblk enumeration failed ({type(e).__name__}); using /sys/block fallback",
                  logging.WARNING)

    # Fallback using /sys/block directly (works even without lsblk -J support)
    for name in sorted(os.listdir("/sys/block")):
        if name.startswith(("loop", "ram", "dm-", "sr", "zram")):
            continue
        if not LINUX_DEVICE_RE.fullmatch(name) or name in unsafe_disks:
            continue
        removable_path = f"/sys/block/{name}/removable"
        size_path = f"/sys/block/{name}/size"
        if not os.path.exists(removable_path):
            continue
        try:
            with open(removable_path) as fh:
                removable = fh.read().strip() == "1"
        except Exception:
            removable = False  # fail closed
        if not removable:
            continue
        # The sysfs device path of a USB drive passes through a "usb" bus node.
        if "/usb" not in os.path.realpath(f"/sys/block/{name}"):
            continue
        try:
            with open(size_path) as fh:
                sectors = int(fh.read().strip())
        except Exception:
            audit(f"Hiding {name}: could not read its size", logging.WARNING)
            continue  # fail closed: an unknown-size disk is not offered
        size = sectors * 512
        if size <= 0:
            audit(f"Hiding {name}: its size is zero", logging.WARNING)
            continue  # fail closed: a drive without media is not offered
        model = ""
        try:
            parts = []
            for attr in ("vendor", "model"):
                with open(f"/sys/block/{name}/device/{attr}") as fh:
                    parts.append(fh.read().strip())
            model = " ".join(p for p in parts if p)
        except Exception:  # noqa: S110 - purely descriptive, the disk is listed either way
            pass
        # No partition information here (volumes=None): the confirmation says so and treats it as high risk.
        disks.append(_disk_entry(name, size, model, None, make_identity(model=model)))
    return disks


def linux_partition_path(dev_name, n):
    if dev_name[-1].isdigit():
        return f"/dev/{dev_name}p{n}"
    return f"/dev/{dev_name}{n}"


def linux_detect_pkg_manager():
    for mgr in LINUX_INSTALL_CMD_TEMPLATE:  # in the order the managers are listed there
        if shutil.which(mgr):
            return mgr
    return None


def linux_build_install_command(mgr, missing_tools):
    """Build the package-install command from the fixed allow-list only.

    Only tools declared in LINUX_REQUIRED_TOOLS may be installed, and only under
    the package name mapped in LINUX_PKG_MAP. Nothing from user input or from the
    network can influence what gets installed with root privileges.
    """
    if mgr not in LINUX_INSTALL_CMD_TEMPLATE:
        raise ValueError(f"Unsupported package manager: {mgr!r}")
    pkgmap = LINUX_PKG_MAP.get(mgr, {})
    allowed = set(LINUX_REQUIRED_TOOLS)
    pkgs = sorted({pkgmap[t] for t in missing_tools if t in allowed and t in pkgmap})
    if not pkgs:
        raise ValueError("Nothing to install: no recognised missing dependency.")
    for pkg in pkgs:
        if not re.fullmatch(r"[A-Za-z0-9._+-]{1,64}", pkg):
            raise ValueError(f"Refusing to install suspicious package name: {pkg!r}")
    return LINUX_INSTALL_CMD_TEMPLATE[mgr].format(pkgs=" ".join(pkgs))


def linux_unmount_partitions(dev, log, priv):
    """Best effort: unmount every partition of `dev` (used after a cancel)."""
    script = (
        'set -eu\n'
        'for p in "$1"[0-9]* "$1"p[0-9]*; do umount "$p" 2>/dev/null || true; done\n'
    )
    try:
        priv.run_script(script, log, args=[dev])
    except Exception as e:
        log(f"Warning: could not unmount the drive: {e}")


def linux_write_raw(iso_path, dev_name, log, priv, progress=None, cancel_event=None, eject=True):
    """Write the ISO byte-for-byte to the whole disk (Linux and other hybrid ISOs)."""
    validate_hybrid_iso(iso_path)
    check_canceled(cancel_event, drive_touched=False)
    dev = f"/dev/{dev_name}"
    total = os.path.getsize(iso_path)
    # O_DIRECT bypasses the page cache (steadier speed, honest progress), but needs every
    # write block aligned; only use it when the image size is a multiple of the alignment.
    direct = "direct" if total % DIRECT_IO_ALIGNMENT == 0 else "buffered"
    log(f"Writing the ISO to {dev} (administrator privileges required)...")
    # Values arrive as "$1".."$5"; the glob expands only after the quoted device prefix.
    canceled = write_raw_image(priv, LINUX_RAW_SCRIPT,
                               [iso_path, dev, RAW_WRITE_BLOCK["linux"]],
                               log, total, progress, cancel_event, extra_args=[direct])
    if canceled:
        log("Canceled. The drive holds a partial image and is unusable until written again.")
        linux_unmount_partitions(dev, log, priv)
        raise OperationCanceled("Canceled by the user.")
    if progress:
        progress(total, total, "Written")
    verify_raw_write(iso_path, dev, log, priv, progress, cancel_event)
    ejected = linux_eject(dev_name, log, priv) if eject else None
    log("Done! The USB drive is ready to boot.")
    report_eject(ejected, log, skipped=not eject)
    return ejected


def linux_build_usb(iso_path, dev_name, log, priv, progress=None, cancel_event=None, eject=True,
                    hardening_files=None):
    check_canceled(cancel_event, drive_touched=False)  # nothing has been changed yet
    dev = f"/dev/{dev_name}"
    part = linux_partition_path(dev_name, 1)
    uid, gid = os.getuid(), os.getgid()
    # The hardening files are staged (private 0700 folder) before the drive is touched.
    stage = stage_hardening_files(hardening_files) if hardening_files else None
    try:
        iso_mount = tempfile.mkdtemp(prefix="win11iso_")
        usb_mount = tempfile.mkdtemp(prefix="win11usb_")
    except BaseException:
        _silent_rmtree(stage)
        raise

    log(f"Erasing and formatting {dev} as GPT + FAT32 (administrator privileges required)...")
    # Every value below arrives as a positional parameter ("$1".."$6"), never
    # pasted into the script text, so no filename can inject extra commands.
    prep_script = (
        'set -eu\n'
        'DEV="$1"; PART="$2"; ISO="$3"; ISO_MNT="$4"; USB_MNT="$5"; OWNER="$6"\n'
        # A desktop session may auto-mount partitions of the drive (before and after
        # we change them); unmount them so wipefs/mkfs/mount are not blocked.
        'umount_parts() { for p in "$DEV"[0-9]* "$DEV"p[0-9]*; do umount "$p" 2>/dev/null || true; done; }\n'
        'umount_parts\n'
        'wipefs -a "$DEV"\n'
        'parted -s "$DEV" mklabel gpt\n'
        'parted -s "$DEV" mkpart primary fat32 1MiB 100%\n'
        'parted -s "$DEV" set 1 esp on\n'
        'partprobe "$DEV"\n'
        # Wait for udev to create the new partition node instead of sleeping blindly.
        'udevadm settle --timeout=15 2>/dev/null || sleep 2\n'
        'i=0\n'
        'while [ ! -b "$PART" ] && [ "$i" -lt 20 ]; do sleep 1; i=$((i + 1)); done\n'
        '[ -b "$PART" ] || { echo "The new partition $PART did not appear." >&2; exit 1; }\n'
        'umount_parts\n'
        f'mkfs.vfat -F 32 -n {VOL_NAME} "$PART"\n'
        'udevadm settle --timeout=15 2>/dev/null || true\n'
        'umount_parts\n'
        # Microsoft's ISOs are UDF-bridge images: with the filesystem left to autodetection the
        # kernel may pick iso9660, which shows only a stub without sources/install.wim. Ask for
        # UDF first (iso9660 for plain images); autodetection stays as the last resort.
        'if ! mount -t udf,iso9660 -o loop,ro,uid="${OWNER%%:*}",gid="${OWNER##*:}" "$ISO" "$ISO_MNT"; then\n'
        'echo "Mounting the ISO as UDF/ISO 9660 failed; letting mount detect the type." >&2\n'
        'mount -o loop,ro,uid="${OWNER%%:*}",gid="${OWNER##*:}" "$ISO" "$ISO_MNT"\n'
        'fi\n'
        'mount -o uid="${OWNER%%:*}",gid="${OWNER##*:}" "$PART" "$USB_MNT"\n'
    )

    try:
        priv.run_script(prep_script, log,
                        args=[dev, part, iso_path, iso_mount, usb_mount, f"{uid}:{gid}"])
        check_canceled(cancel_event)

        def reopen():
            log("Remounting the drive read-only to read it back from the device...")
            remount = (
                'set -eu\n'
                'sync\n'
                'umount "$2"\n'
                '{ echo 3 > /proc/sys/vm/drop_caches; } 2>/dev/null || true\n'
                'mount -o ro,uid="${3%%:*}",gid="${3##*:}" "$1" "$2"\n'
            )
            priv.run_script(remount, log, args=[part, usb_mount, f"{uid}:{gid}"])
            return usb_mount

        copy_windows_payload(
            iso_mount, usb_mount, log, progress,
            "wimlib-imagex not found. Install it via your package manager "
            "(e.g. 'wimtools' on Debian/Ubuntu, 'wimlib-utils' on Fedora, 'wimlib' on "
            "Arch/openSUSE) or use the 'Install missing dependencies' button.",
            reopen=reopen, cancel_event=cancel_event,
            **({"extra_files": hardening_files,
                "write_extra": lambda root: copy_hardening_stage(priv, stage, root, log, cancel_event)}
               if hardening_files else {}))
    except OperationCanceled as e:
        if e.written:
            log("Canceled during verification. The files were copied completely but NOT verified.")
        else:
            log("Canceled. The drive is left incomplete and unusable.")
        raise
    finally:
        log("Unmounting...")
        cleanup_script = 'set -eu\numount "$1" || true\numount "$2" || true\n'
        try:
            priv.run_script(cleanup_script, log, args=[usb_mount, iso_mount])
        except Exception as cleanup_err:
            log(f"Warning: cleanup failed: {cleanup_err}")
        _silent_rmdir(iso_mount, usb_mount)
        _silent_rmtree(stage)

    ejected = linux_eject(dev_name, log, priv) if eject else None
    log("Done! The USB drive is ready to install Windows 11.")
    report_eject(ejected, log, skipped=not eject)
    return ejected


# ===== hardening: engine-windows =====
# Extra files for a Windows drive (autounattend.xml and a SetupComplete script, see
# hardening_files_windows). They are checked first, written after the ISO's own files, read back
# from the device and compared byte for byte.
def validate_hardening(mode, hardening):
    """Refuse an unknown profile, or a profile on an image type that cannot take extra files.

    Only the Windows type copies files onto the drive; a raw-written image (Linux, ChromeOS) has no
    room for them. Called before anything is hashed, listed or erased.
    """
    if hardening not in HARDENING_PROFILES:
        raise ValueError(f"Unknown hardening profile: {hardening!r}")
    if hardening != HARDENING_NONE and mode != MODE_WINDOWS:
        raise ValueError("Hardening files can only be added to a Windows drive; an image of this type is "
                         "written byte for byte and has no room for them. Nothing was changed.")


def collect_hardening_files(hardening):
    """The validated {relative posix path: bytes} to add for `hardening` ({} for none)."""
    if hardening == HARDENING_NONE:
        return {}
    # Both names belong to other parts of the hardening feature and are looked up here at call time
    # (the tests patch them), hence the noqa until every part is merged.
    files = validate_seed_files(hardening_files_windows(hardening))  # noqa: F821
    if not files:
        raise ValueError(f"The hardening profile {hardening!r} has no files to add. Nothing was changed.")
    return files


def hardening_audit_text(hardening, files):
    """What the audit START line says about the hardening files: the profile and the file names (no contents)."""
    if not files:
        return ""
    return f", hardening={hardening}, hardening files={sorted(files)}"


def _hardening_target(root, rel):
    """The path of `rel` (a relative posix path) below `root`; refuses anything that would leave `root`."""
    parts = rel.split("/")
    if not rel or rel.startswith("/") or "\\" in rel or "\0" in rel or any(p in ("", ".", "..") for p in parts):
        raise ValueError(f"Refusing an unsafe hardening file path: {rel!r}")
    real_root = os.path.realpath(root)
    target = os.path.join(real_root, *parts)
    if os.path.commonpath([real_root, os.path.realpath(target)]) != real_root:
        raise RuntimeError(f"Refusing to write outside the drive: {rel!r}")
    return target


def write_hardening_files(root, files, cancel_event=None):
    """Write `files` ({relative posix path: bytes}) below the directory `root`, as the current user.

    Plain file I/O: no shell, so a `$` in a name (sources/$OEM$/$$/...) is just a character. Parent
    folders are created; each file is flushed to the device. Raises OperationCanceled between files.
    """
    for rel in sorted(files):
        check_canceled(cancel_event)
        target = _hardening_target(root, rel)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        if os.path.islink(target):
            raise RuntimeError(f"Refusing to write over a symbolic link: {rel!r}")
        with open(target, "wb") as fh:
            fh.write(files[rel])
            fh.flush()
            os.fsync(fh.fileno())


def verify_hardening_files(root, files, log, cancel_event=None):
    """Read the hardening files back from `root` and compare each one byte for byte. Raises on any mismatch."""
    log("Verifying the hardening files (reading them back from the drive)...")
    bad = []
    for rel in sorted(files):
        check_canceled(cancel_event)
        expected = files[rel]
        path = _hardening_target(root, rel)
        try:
            if os.path.islink(path):
                raise OSError("symbolic link")
            with open(path, "rb") as fh:
                found = fh.read(len(expected) + 1)  # one byte more: a longer file must not pass
        except OSError:
            bad.append(f"{rel} (missing)")
            continue
        if found != expected:
            bad.append(f"{rel} (differs)")
    if bad:
        audit(f"VERIFICATION FAILED: {len(bad)} hardening file(s) differ", logging.ERROR)
        raise RuntimeError(
            f"Verification FAILED: {len(bad)} hardening file(s) on the drive are missing or differ from what "
            f"was written (for example: {bad[0]}).\n\nThe drive was NOT ejected and should not be used.")
    log(f"Hardening files verified: {len(files)} file(s) identical.")


def _silent_rmtree(path):
    """Best-effort cleanup of a staging folder (None: nothing to do)."""
    if path:
        shutil.rmtree(path, ignore_errors=True)


def stage_hardening_files(files, cancel_event=None):
    """Write `files` into a new private (0700) temporary folder and return its path.

    The privileged copy script takes this folder as `$1`; staging it as the user keeps every name
    out of the shell. The caller removes the folder (`_silent_rmtree`).
    """
    stage = tempfile.mkdtemp(prefix="win11hard_")
    try:
        os.chmod(stage, 0o700)
        write_hardening_files(stage, files, cancel_event)
    except BaseException:
        _silent_rmtree(stage)
        raise
    return stage


# Root script that puts a staged folder onto the mounted drive. Values arrive as "$1".."$3" (never
# pasted into the text): the staged folder, the mount point, and "$3", the cancel flag file the app
# creates to ask for a stop (HARDENING_CANCELED is printed when it appears). It never follows
# symbolic links: a link anywhere in the staged folder is refused, and cp copies links as links.
HARDENING_COPY_SCRIPT = (
    'set -eu\n'
    "trap '' INT\n"
    'STAGE="$1"; MNT="$2"; STOP="$3"\n'
    'if [ ! -d "$STAGE" ] || [ -L "$STAGE" ]; then echo "The staged folder is not a plain directory." >&2; exit 1; fi\n'
    'if [ ! -d "$MNT" ] || [ -L "$MNT" ]; then echo "The mount point is not a plain directory." >&2; exit 1; fi\n'
    'if [ -n "$(find "$STAGE" -type l)" ]; then echo "Refusing to copy: the staged folder holds a symbolic link." >&2; exit 1; fi\n'
    'if [ -e "$STOP" ]; then echo "HARDENING_CANCELED"; exit 0; fi\n'
    'cp -RP -- "$STAGE"/. "$MNT"/\n'
    'sync\n'
    'echo "HARDENING_COPIED"\n'
)


def copy_hardening_stage(priv, stage, mount_point, log, cancel_event=None):
    """Copy the staged hardening folder onto the mounted drive with HARDENING_COPY_SCRIPT (Linux).

    Both folders are checked here first. The script runs once and is never repeated on failure.
    Raises OperationCanceled when a cancel was asked for (the drive then holds an incomplete payload).
    """
    for folder in (stage, mount_point):
        if not os.path.isdir(folder) or os.path.islink(folder):
            raise ValueError(f"Not a plain directory: {folder!r}")
    check_canceled(cancel_event)
    seen = set()

    def watch(line):
        line = line.strip()
        if line in ("HARDENING_COPIED", "HARDENING_CANCELED"):
            seen.add(line)
        else:
            log(line)

    with cancel_flag(cancel_event) as flag:
        priv.run_script(HARDENING_COPY_SCRIPT, watch, args=[stage, mount_point, flag])
    if "HARDENING_CANCELED" in seen:
        raise OperationCanceled("Canceled by the user while the hardening files were being added.")
    if "HARDENING_COPIED" not in seen:
        raise RuntimeError("Could not confirm that the hardening files were copied. "
                           "Do not trust this drive; run the creation again.")
# ===== end hardening: engine-windows =====


# ============================================================
# Platform dispatch
# ============================================================
def get_external_disks():
    return macos_get_external_disks() if IS_MAC else linux_get_external_disks()


def reverify_target_disk(dev, expected_size, log, expected_identity=None):
    """Re-check, immediately before erasing, that `dev` is still the disk we listed.

    Device names are recycled by the operating system: if a drive is unplugged and
    another plugged in between listing and writing, '/dev/sdb' can point somewhere
    else entirely. Re-enumerating here closes that window.
    """
    validate_device_name(dev)
    # The identity the user confirmed: passed explicitly or pinned by the UI (see pin_target_identity).
    expected_identity = expected_identity or _pinned_identities.pop(dev, None)
    current = {d["id"]: d for d in get_external_disks()}
    if dev not in current:
        audit(f"ABORTED: {dev} is no longer an eligible external disk", logging.ERROR)
        raise RuntimeError(
            f"Aborted for safety: /dev/{dev} is no longer listed as an external drive.\n\n"
            "It may have been unplugged, or the name may now refer to a different disk. "
            "Click 'Refresh USB drives list' and select the drive again."
        )
    actual_size = current[dev]["size"]
    if expected_size and actual_size != expected_size:
        audit(f"ABORTED: {dev} size changed {expected_size} -> {actual_size}", logging.ERROR)
        raise RuntimeError(
            f"Aborted for safety: /dev/{dev} now reports a different size "
            f"({human_size(actual_size)} instead of {human_size(expected_size)}).\n\n"
            "This means the name now points to a different device. Refresh the list "
            "and select the drive again."
        )
    changed = identity_mismatch(expected_identity, current[dev].get("identity"))
    if changed:
        audit(f"ABORTED: {dev} identity changed ({changed})", logging.ERROR)
        raise RuntimeError(
            f"Aborted for safety: /dev/{dev} no longer looks like the drive you confirmed "
            f"({changed}).\n\n"
            "This means the name now points to a different device. Refresh the list "
            "and select the drive again."
        )
    log(f"Safety re-check passed: /dev/{dev} is still the same external drive "
        f"({human_size(actual_size)}).")


def hash_iso_for_audit(iso_path, log, progress, cancel_event):
    """SHA-256 of the ISO for the audit trail. Runs in the worker thread, before the drive is touched."""
    log("Hashing the ISO (recorded in the audit log)...")
    if progress:
        progress(0, 0, "Hashing the ISO...")
    try:
        digest = sha256_file(iso_path, cancel_event)
    except OSError as e:
        raise RuntimeError(f"Could not read the ISO file: {e.strerror or type(e).__name__}. "
                           "The drive was not modified.") from None
    log(f"ISO SHA-256: {digest}")
    return digest


def missing_dependencies_hint(missing):
    """One sentence telling the user how to get the missing tools on this system."""
    button = "or use the 'Install missing dependencies' button"
    if IS_MAC:
        if "wimlib-imagex" in missing:
            return f"Install wimlib with: brew install wimlib ({button})."
        return "They are part of macOS; the system looks incomplete."
    try:
        cmd = linux_build_install_command(linux_detect_pkg_manager(), missing)
    except ValueError:
        return f"Install them with your package manager ({button})."
    return f"Install them with: sudo {cmd} ({button})."


def validate_image_for_mode(iso_path, mode, expected_size=None):
    """Check, before anything is touched, that the image suits the chosen type and fits the drive.

    Also refuses, with a message that says how to fix it, when a tool the chosen type needs is
    missing: otherwise that would only be discovered after the drive had been erased.
    """
    if mode not in ALL_MODES:
        raise ValueError(f"Unknown image type: {mode!r}")
    iso_path = validate_iso_path(iso_path)
    if mode == MODE_LINUX:
        validate_hybrid_iso(iso_path)
    elif mode == MODE_CHROMEOS:
        validate_disk_image(iso_path)
    # Raw modes write the image as it is; Windows mode copies its contents. Either way it must
    # fit (the copy of a Windows ISO needs at least the ISO's size).
    image_size = os.path.getsize(iso_path)
    if image_exceeds_drive(image_size, expected_size):
        raise ValueError(f"The image ({human_size(image_size)}) is larger than the "
                         f"drive ({human_size(expected_size)}). Nothing was changed.")
    missing = get_missing_dependencies(mode)
    if missing:
        raise ValueError(f"Cannot continue: required tool(s) not found: {', '.join(missing)}. "
                         f"{missing_dependencies_hint(missing)} Nothing was changed.")
    return iso_path


def build_usb(iso_path, dev, log, priv, expected_size=None, mode=MODE_WINDOWS, progress=None,
              cancel_event=None, eject=True, hardening=HARDENING_NONE):
    """Create the bootable drive. Raises OperationCanceled on a cancel (see its docstring:
    `drive_touched` is False when nothing on the drive was changed).
    `hardening` (Windows mode only) adds the hardening files, validated before the drive is touched."""
    validate_hardening(mode, hardening)
    hardening_files = collect_hardening_files(hardening)
    iso_path = validate_image_for_mode(iso_path, mode, expected_size)
    validate_device_name(dev)
    try:
        iso_sha = hash_iso_for_audit(iso_path, log, progress, cancel_event)
        reverify_target_disk(dev, expected_size, log)
        check_canceled(cancel_event, drive_touched=False)
    except OperationCanceled:
        # Hashing and the safety re-check change nothing: the drive is exactly as it was.
        audit(f"OPERATION CANCELED by the user before the drive was touched (/dev/{dev}); nothing was changed",
              logging.WARNING)
        raise OperationCanceled("Canceled by the user before the drive was touched.",
                                drive_touched=False) from None
    audit(f"DESTRUCTIVE OPERATION START: erasing /dev/{dev} and writing {mode} image "
          f"(iso sha256={iso_sha}, size={os.path.getsize(iso_path)})" + hardening_audit_text(hardening, hardening_files))
    extra = {"hardening_files": hardening_files} if hardening_files else {}
    try:
        with prevent_sleep(log):
            if mode in RAW_MODES:
                if IS_MAC:
                    ejected = macos_write_raw(iso_path, dev, log, priv, progress, cancel_event, eject)
                else:
                    ejected = linux_write_raw(iso_path, dev, log, priv, progress, cancel_event, eject)
            elif IS_MAC:
                ejected = macos_build_usb(iso_path, dev, log, progress=progress, cancel_event=cancel_event,
                                         eject=eject, **extra)
            else:
                ejected = linux_build_usb(iso_path, dev, log, priv, progress, cancel_event, eject, **extra)
    except OperationCanceled as e:
        if not e.drive_touched:
            audit(f"DESTRUCTIVE OPERATION CANCELED by the user on /dev/{dev} before the drive was touched; "
                  "nothing was changed", logging.WARNING)
        elif e.written:
            audit(f"DESTRUCTIVE OPERATION CANCELED by the user on /dev/{dev} during verification; "
                  "the image was written but NOT verified", logging.WARNING)
        else:
            audit(f"DESTRUCTIVE OPERATION CANCELED by the user on /dev/{dev}; the drive was left unusable",
                  logging.WARNING)
        raise
    except Exception as e:
        audit(f"DESTRUCTIVE OPERATION FAILED on /dev/{dev}: {type(e).__name__}", logging.ERROR)
        raise
    audit(f"DESTRUCTIVE OPERATION COMPLETED on /dev/{dev} (ejected={bool(ejected)})")
    return bool(ejected)


def needs_admin(mode):
    """Whether writing a drive in `mode` needs administrator rights: always on Linux, and on macOS
    only for the byte-for-byte modes (diskutil and hdiutil need no root, writing /dev/rdiskN does)."""
    return IS_LINUX or mode in RAW_MODES


def image_exceeds_drive(image_size, drive_size):
    """True when an image of `image_size` bytes cannot fit a drive of `drive_size` bytes.

    An unknown size (0 or None) is never a reason to refuse. Pure: the window and the command line each
    word the refusal themselves (translated in the window, English on the command line).
    """
    return bool(image_size and drive_size and image_size > drive_size)


# ===== hardening: linux script =====
# The text of harden-linux.sh, the script a hardened Linux setup runs on the NEW system (from the seed
# drive, or inside the installer's chroot). Debian/Ubuntu (apt) and Fedora/RHEL (dnf). It is only ever
# written to a drive as a file; this program never runs it. Settings are inspired by common baselines.
# Tests: tests/test_hardening_linux.py (shellcheck, fake-root runs, dry-run, undo, idempotence).
_HARDEN_LINUX_SH = r"""#!/usr/bin/env bash
# harden-linux.sh - recommended security settings for a fresh Linux install.
#
# Part of EPMA USB CREATOR ("Hardened (recommended settings)"). For Debian/Ubuntu (apt) and the
# Fedora/RHEL family (dnf). The settings are inspired by common hardening baselines and kept
# conservative on purpose. It is a convenience script: it makes no claim to meet any standard.
#
# Usage:  sudo bash harden-linux.sh [--dry-run] [--yes] [--undo] [--chroot] [--help]
#         bash -s -- --chroot --yes < harden-linux.sh        (also works when read from stdin)
#
# What it does NOT do: it never partitions or formats anything, never creates users or passwords,
# never touches SELinux/AppArmor modes, never disables USB storage and never makes a network
# request of its own (only your package manager does, to install a few security packages).
#
# Every file it changes is copied once to <file>.epma-bak first. Running it twice changes nothing
# the second time. --undo puts the backups back and removes the files this script created.
#
# Layout note: everything below is a function and the very last line calls main. That keeps the
# script safe to run through "bash -s" (no command can swallow the rest of the script from stdin)
# and lets the script write a working copy of itself for the first-boot service.
set -euo pipefail

usage() {
  cat <<'EOF'
harden-linux.sh - recommended security settings for a fresh Debian/Ubuntu or Fedora/RHEL install

Usage: sudo bash harden-linux.sh [options]

Options:
  --dry-run   show what would be done; change NOTHING (no file, package, service or log entry)
  --yes       do not ask for confirmation (needed when there is no terminal)
  --undo      restore the .epma-bak copies and remove the files this script created
  --chroot    run inside an installer chroot: write configuration files only, skip everything that
              acts on a running system, and install a one-shot service that runs this script again
              on the first boot of the installed system
  --help      show this text

Exit status: 0 done, 1 some step failed (see the [WARN] lines), 2 cannot run (not root,
unsupported system, bad option).
Log file: /var/log/epma-hardening.log
EOF
}

die() {
  local code="$1"
  shift
  printf 'harden-linux.sh: %s\n' "$*" >&2
  exit "$code"
}

init_globals() {
  DRY=0
  YES=0
  UNDO=0
  CHROOT=0
  HELP=0
  N_OK=0
  N_SKIP=0
  N_WARN=0
  N_CHANGE=0
  N_ERR=0
  NOTICES=""
  R=""
  TESTMODE=0
  WORK=""
  FAMILY=""
  DISTRO_NAME=""
  LOG_FILE=""
  LOG_ENABLED=0
  CHANGED_LAST=0
  SKIPPED_KEYS=""
  PKG_REFRESHED=0
  KEYS_ANY=0
  KEYS_CALLER=0
  UNIT_NAME="epma-hardening-firstboot.service"
}

# ---------------------------------------------------------------------------------------------
# Output and log
# ---------------------------------------------------------------------------------------------

log_line() {
  if [ "$LOG_ENABLED" = 1 ]; then
    printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >>"$LOG_FILE" 2>/dev/null || true
  fi
}

say() {
  printf '%s\n' "$1"
  log_line "$1"
}

ok() {
  N_OK=$((N_OK + 1))
  say "[OK]     $*"
}

skip() {
  N_SKIP=$((N_SKIP + 1))
  say "[SKIP]   $*"
}

warn() {
  N_WARN=$((N_WARN + 1))
  say "[WARN]   $*"
}

change() {
  N_CHANGE=$((N_CHANGE + 1))
  if [ "$DRY" = 1 ]; then
    say "[CHANGE] (dry-run) $*"
  else
    say "[CHANGE] $*"
  fi
}

notice() {
  NOTICES="${NOTICES}  - $1
"
}

# ---------------------------------------------------------------------------------------------
# Environment, test hooks, helpers
# ---------------------------------------------------------------------------------------------

# EPMA_HARDEN_TEST_ROOT is a hidden hook for the automated tests: every path is taken below that
# directory, live-system commands are looked up in <root>/stubs only (never in PATH), and
# EPMA_HARDEN_TEST_UID may pretend to be root. Without the variable none of this is active.
setup_env() {
  local uid
  R="${EPMA_HARDEN_TEST_ROOT:-}"
  if [ -n "$R" ]; then
    case "$R" in
      /*) ;;
      *) die 2 "EPMA_HARDEN_TEST_ROOT must be an absolute path" ;;
    esac
    R="${R%/}"
    if [ -z "$R" ] || [ ! -d "$R" ]; then
      die 2 "EPMA_HARDEN_TEST_ROOT must be an existing directory other than /"
    fi
    TESTMODE=1
  else
    PATH="${PATH:-/usr/bin:/bin}:/usr/local/sbin:/usr/sbin:/sbin"
    export PATH
  fi
  umask 022
  export DEBIAN_FRONTEND=noninteractive
  uid="$(id -u)"
  if [ "$TESTMODE" = 1 ] && [ -n "${EPMA_HARDEN_TEST_UID:-}" ]; then
    uid="$EPMA_HARDEN_TEST_UID"
  fi
  if [ "$uid" != 0 ]; then
    die 2 "this script must run as root (try: sudo bash harden-linux.sh ...)"
  fi
}

init_paths() {
  STATE_DIR="$R/var/lib/epma-hardening"
  LOG_FILE="$R/var/log/epma-hardening.log"
  OS_RELEASE="$R/etc/os-release"
  if [ ! -f "$OS_RELEASE" ]; then
    OS_RELEASE="$R/usr/lib/os-release"
  fi
}

# Run a command that acts on, or asks questions of, the live system. In test mode only the stubs
# in <root>/stubs are ever run, so a test can never reach the real apt, systemctl, ufw and so on.
sysrun() {
  if [ "$TESTMODE" = 1 ]; then
    case "$1" in
      */* | '') return 127 ;;
    esac
    if [ -x "$R/stubs/$1" ]; then
      "$R/stubs/$1" "${@:2}" </dev/null
      return $?
    fi
    return 127
  fi
  "$@" </dev/null
}

have_cmd() {
  if [ "$TESTMODE" = 1 ]; then
    [ -x "$R/stubs/$1" ]
  else
    command -v "$1" >/dev/null 2>&1
  fi
}

file_mode() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null || echo 644
}

shown() {
  local p="$1"
  printf '%s' "${p#"$R"}"
}

record_state() {
  # record_state created|modified PATH
  local f="$STATE_DIR/$1.list"
  mkdir -p "$STATE_DIR"
  chmod 700 "$STATE_DIR"
  if [ ! -f "$f" ] || ! grep -qxF -- "$2" "$f"; then
    printf '%s\n' "$2" >>"$f"
  fi
}

unrecord_created() {
  local f="$STATE_DIR/created.list"
  if [ -f "$f" ]; then
    grep -vxF -- "$1" "$f" >"$f.new" || true
    mv -f "$f.new" "$f"
  fi
}

# put_file DEST NEWFILE MODE: install NEWFILE as DEST when it differs. The original is copied to
# DEST.epma-bak once. Sets CHANGED_LAST=1 when DEST was (or would be) written.
put_file() {
  local dest="$1" new="$2" mode="$3" name
  name="$(shown "$dest")"
  if [ -e "$dest" ] && cmp -s "$new" "$dest"; then
    ok "$name is already as wanted"
    return 0
  fi
  CHANGED_LAST=1
  if [ "$DRY" = 1 ]; then
    if [ -e "$dest" ]; then
      change "$name: would be updated (original kept as $name.epma-bak)"
    else
      change "$name: would be created"
    fi
    return 0
  fi
  mkdir -p "$(dirname "$dest")"
  if [ -e "$dest" ]; then
    mode="$(file_mode "$dest")"
    if [ ! -e "$dest.epma-bak" ]; then
      cp -p "$dest" "$dest.epma-bak"
      record_state modified "$dest"
    fi
    cp "$new" "$dest.epma-new"
    chmod "$mode" "$dest.epma-new"
    mv -f "$dest.epma-new" "$dest"
    change "$name: updated (original kept as $name.epma-bak)"
  else
    cp "$new" "$dest.epma-new"
    chmod "$mode" "$dest.epma-new"
    mv -f "$dest.epma-new" "$dest"
    record_state created "$dest"
    change "$name: created"
  fi
}

# act DESCRIPTION COMMAND...: run a live-system command. A failure is counted as an error.
act() {
  local desc="$1" out
  shift
  if [ "$DRY" = 1 ]; then
    change "would: $desc"
    return 0
  fi
  if [ "$CHROOT" = 1 ]; then
    skip "$desc (not done inside a chroot; the first boot takes care of it)"
    return 0
  fi
  if out="$(sysrun "$@" 2>&1)"; then
    change "$desc"
    return 0
  fi
  warn "FAILED: $desc"
  log_line "output: $out"
  N_ERR=$((N_ERR + 1))
  return 1
}

# act_soft: like act, but a failure is only a warning (reloads that may legitimately fail).
act_soft() {
  local desc="$1" out
  shift
  if [ "$DRY" = 1 ]; then
    change "would: $desc"
    return 0
  fi
  if [ "$CHROOT" = 1 ]; then
    skip "$desc (not done inside a chroot; it applies at the next boot)"
    return 0
  fi
  if out="$(sysrun "$@" 2>&1)"; then
    change "$desc"
    return 0
  fi
  warn "$desc did not work: $out"
  return 0
}

pkg_installed() {
  local out
  if [ "$FAMILY" = apt ]; then
    out="$(sysrun dpkg -s "$1" 2>/dev/null)" || return 1
    case "$out" in
      *"Status: install ok installed"*) return 0 ;;
    esac
    return 1
  fi
  sysrun rpm -q "$1" >/dev/null 2>&1
}

# pkg_install PKG: returns 0 when PKG is installed or (dry-run) would be; 1 when it is not.
pkg_install() {
  if pkg_installed "$1"; then
    ok "package $1 is already installed"
    return 0
  fi
  if [ "$CHROOT" = 1 ]; then
    skip "package $1: installing is left to the first boot"
    return 1
  fi
  if [ "$DRY" = 1 ]; then
    change "would: install package $1"
    return 0
  fi
  if [ "$FAMILY" = apt ]; then
    if [ "$PKG_REFRESHED" = 0 ]; then
      PKG_REFRESHED=1
      act_soft "refresh the package lists" apt-get update
    fi
    act "install package $1" apt-get install -y --no-install-recommends "$1" || return 1
  else
    act "install package $1" dnf -y install "$1" || return 1
  fi
  return 0
}

service_active() {
  sysrun systemctl is-active --quiet "$1" >/dev/null 2>&1
}

service_enabled() {
  sysrun systemctl is-enabled --quiet "$1" >/dev/null 2>&1
}

enable_service() {
  if service_enabled "$1" && service_active "$1"; then
    ok "service $1 is enabled and running"
    return 0
  fi
  act "enable and start service $1" systemctl enable --now "$1"
}

# ---------------------------------------------------------------------------------------------
# Start of the run: distribution, confirmation, scratch space
# ---------------------------------------------------------------------------------------------

os_value() {
  awk -F= -v k="$1" '$1 == k { sub(/^[^=]*=/, ""); print; exit }' "$OS_RELEASE" | tr -d "\"'" | tr '[:upper:]' '[:lower:]'
}

detect_distro() {
  local id like w
  if [ ! -f "$OS_RELEASE" ]; then
    die 2 "cannot tell which Linux this is: no /etc/os-release"
  fi
  id="$(os_value ID)"
  like="$(os_value ID_LIKE)"
  DISTRO_NAME="$(awk -F= '$1 == "PRETTY_NAME" { sub(/^[^=]*=/, ""); print; exit }' "$OS_RELEASE" | tr -d "\"'")"
  if [ -z "$DISTRO_NAME" ]; then
    DISTRO_NAME="$id"
  fi
  FAMILY=""
  for w in $id $like; do
    if [ -n "$FAMILY" ]; then
      break
    fi
    case "$w" in
      debian | ubuntu) FAMILY=apt ;;
      fedora | rhel | centos) FAMILY=dnf ;;
    esac
  done
  if [ -z "$FAMILY" ]; then
    die 2 "unsupported system '${DISTRO_NAME}' (ID=${id}, ID_LIKE=${like}). Supported: Debian/Ubuntu and Fedora/RHEL families."
  fi
}

print_plan() {
  say "EPMA hardening (recommended settings) for: $DISTRO_NAME  [package manager: $FAMILY]"
  if [ "$UNDO" = 1 ]; then
    say "Mode: UNDO - restore the .epma-bak copies and remove the files this script created."
  elif [ "$DRY" = 1 ]; then
    say "Mode: DRY RUN - nothing will be changed."
  elif [ "$CHROOT" = 1 ]; then
    say "Mode: CHROOT - configuration files only; the rest runs once on the first boot."
  else
    say "Mode: APPLY"
    say "It will write configuration for: kernel settings, SSH (if installed), firewall, automatic"
    say "security updates, audit logging, rarely used kernel modules, core dumps, password quality"
    say "for new passwords, new-account defaults and file permissions. It never touches disks."
  fi
}

confirm_run() {
  local ans=""
  if [ "$DRY" = 1 ] || [ "$YES" = 1 ]; then
    return 0
  fi
  printf 'Continue? [y/N] ' >&2
  if { read -r ans </dev/tty; } 2>/dev/null; then
    :
  else
    printf '\n' >&2
    die 2 "no terminal to ask on; run again with --yes"
  fi
  case "$ans" in
    y | Y | yes | YES | Yes) ;;
    *)
      printf 'Cancelled. Nothing was changed.\n'
      exit 0
      ;;
  esac
}

setup_work() {
  local base="${TMPDIR:-/tmp}"
  if [ "$TESTMODE" = 1 ]; then
    base="$R/tmp"
    mkdir -p "$base"
  fi
  WORK="$(mktemp -d "$base/epma-harden.XXXXXX")"
}

# shellcheck disable=SC2329  # called through "trap cleanup EXIT" in main
cleanup() {
  if [ -n "$WORK" ] && [ -d "$WORK" ]; then
    rm -rf -- "${WORK:?}"
  fi
}

init_log() {
  if [ "$DRY" = 1 ]; then
    return 0
  fi
  if mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null && : >>"$LOG_FILE" 2>/dev/null; then
    LOG_ENABLED=1
    log_line "---- harden-linux.sh start (dry=$DRY undo=$UNDO chroot=$CHROOT) on $DISTRO_NAME ----"
  else
    printf '[WARN]   cannot write the log file %s\n' "$LOG_FILE"
  fi
}

# ---------------------------------------------------------------------------------------------
# Kernel settings (sysctl)
# ---------------------------------------------------------------------------------------------

sysctl_key_ok() {
  # sysctl_key_ok KEY req|opt: is the key present on this kernel? Without /proc/sys (an installer
  # chroot without /proc) every key is kept except the ones only some kernels have.
  local path
  path="$R/proc/sys/$(printf '%s' "$1" | tr . /)"
  if [ -d "$R/proc/sys" ]; then
    [ -e "$path" ]
  else
    [ "$2" != opt ]
  fi
}

build_sysctl() {
  local key val opt desc
  printf '%s\n' "# Managed by harden-linux.sh (EPMA USB CREATOR). Remove this file, or run the script with"
  printf '%s\n' "# --undo, to go back to the system defaults. Values are conservative on purpose."
  while IFS='|' read -r key val opt desc; do
    if [ -z "$key" ]; then
      continue
    fi
    if sysctl_key_ok "$key" "$opt"; then
      printf '\n# %s\n%s = %s\n' "$desc" "$key" "$val"
    else
      SKIPPED_KEYS="$SKIPPED_KEYS $key"
    fi
  done <<'EOF'
kernel.kptr_restrict|2|req|Hide kernel memory addresses from everybody (makes kernel exploits harder to write).
kernel.dmesg_restrict|1|req|Only root may read the kernel log, which can contain addresses and hardware details.
kernel.randomize_va_space|2|req|Full address space layout randomization (usually already on; makes sure nobody turned it down).
kernel.yama.ptrace_scope|1|opt|A process may only trace its own children, so one program cannot read another one's memory. Only where the kernel has the Yama module.
net.ipv4.conf.all.rp_filter|2|req|Drop packets whose source address could not be reached through the interface they came in on. Loose mode (2) stays safe with VPNs and several network cards.
net.ipv4.conf.default.rp_filter|2|req|Same, for interfaces created later.
net.ipv4.conf.all.accept_redirects|0|req|Ignore ICMP redirects (a way to silently reroute your traffic).
net.ipv4.conf.default.accept_redirects|0|req|Same, for interfaces created later.
net.ipv6.conf.all.accept_redirects|0|req|Ignore ICMPv6 redirects.
net.ipv6.conf.default.accept_redirects|0|req|Same, for interfaces created later.
net.ipv4.conf.all.send_redirects|0|req|This machine is not a router, so it never sends ICMP redirects.
net.ipv4.conf.default.send_redirects|0|req|Same, for interfaces created later.
net.ipv4.conf.all.accept_source_route|0|req|Ignore packets that choose their own route through the network (source routing).
net.ipv4.conf.default.accept_source_route|0|req|Same, for interfaces created later.
net.ipv6.conf.all.accept_source_route|0|req|Ignore IPv6 source routing.
net.ipv6.conf.default.accept_source_route|0|req|Same, for interfaces created later.
net.ipv4.tcp_syncookies|1|req|Keep the machine answering real clients during a SYN flood.
fs.protected_symlinks|1|req|Do not follow symlinks in sticky world-writable directories (like /tmp) unless the owner matches; blocks a class of temp-file attacks.
fs.protected_hardlinks|1|req|Only allow hard links to files you own or can write to.
fs.protected_fifos|1|opt|Restrict opening foreign FIFOs in sticky world-writable directories. Needs kernel 4.19 or newer.
fs.protected_regular|1|opt|Restrict opening foreign regular files in sticky world-writable directories. Needs kernel 4.19 or newer.
fs.suid_dumpable|0|req|Programs running with raised privileges never write core dumps (they may hold secrets).
EOF
}

do_sysctl() {
  local dest="$R/etc/sysctl.d/99-epma-hardening.conf"
  SKIPPED_KEYS=""
  build_sysctl >"$WORK/sysctl.new"
  CHANGED_LAST=0
  put_file "$dest" "$WORK/sysctl.new" 644
  if [ -n "$SKIPPED_KEYS" ]; then
    skip "sysctl: not available on this kernel, left out:$SKIPPED_KEYS"
  fi
  if [ "$CHANGED_LAST" = 1 ]; then
    act_soft "load the sysctl settings now (sysctl --system)" sysctl --system
  fi
}

# ---------------------------------------------------------------------------------------------
# Rarely used kernel modules
# ---------------------------------------------------------------------------------------------

# Deliberately NOT listed: squashfs and udf (live media and Windows ISOs need them), iso9660, vfat,
# exfat, ntfs and usb-storage (this tool is about USB drives). Modules that are already loaded stay
# loaded until the next boot.
build_modprobe() {
  local mod desc
  printf '%s\n' "# Managed by harden-linux.sh (EPMA USB CREATOR). Remove this file, or run the script with --undo,"
  printf '%s\n' "# if you ever need one of these. A module listed here cannot be loaded by accident or by an"
  printf '%s\n' "# unprivileged program that triggers autoloading."
  while IFS='|' read -r mod desc; do
    if [ -z "$mod" ]; then
      continue
    fi
    printf '\n# %s\ninstall %s /bin/false\nblacklist %s\n' "$desc" "$mod" "$mod"
  done <<'EOF'
cramfs|Old compressed read-only filesystem, practically unused.
freevxfs|Filesystem of old SCO/HP-UX systems.
hfs|Old Apple filesystem. Remove these two lines if you read old Mac disks on this machine.
hfsplus|Apple HFS+ filesystem. Remove these two lines if you read Mac disks on this machine.
jffs2|Flash filesystem for embedded devices.
dccp|Rarely used network protocol with a history of kernel bugs.
sctp|Rarely used network protocol. Remove these two lines if you run telephony or WebRTC services.
rds|Rarely used cluster network protocol with a history of kernel bugs.
tipc|Rarely used cluster network protocol with a history of kernel bugs.
EOF
}

do_modprobe() {
  build_modprobe >"$WORK/modprobe.new"
  put_file "$R/etc/modprobe.d/epma-hardening.conf" "$WORK/modprobe.new" 644
}

# ---------------------------------------------------------------------------------------------
# Core dumps
# ---------------------------------------------------------------------------------------------

do_coredumps() {
  # A core dump is a copy of a crashed program's memory; it can contain passwords and keys.
  {
    printf '%s\n' "# Managed by harden-linux.sh (EPMA USB CREATOR): no core dump files for any user."
    printf '%s\n' "*    hard    core    0"
  } >"$WORK/limits.new"
  put_file "$R/etc/security/limits.d/99-epma-hardening.conf" "$WORK/limits.new" 644
  if [ -d "$R/usr/lib/systemd" ] || [ -d "$R/lib/systemd" ]; then
    {
      printf '%s\n' "# Managed by harden-linux.sh (EPMA USB CREATOR): systemd-coredump keeps nothing."
      printf '%s\n' "[Coredump]"
      printf '%s\n' "Storage=none"
      printf '%s\n' "ProcessSizeMax=0"
    } >"$WORK/coredump.new"
    put_file "$R/etc/systemd/coredump.conf.d/99-epma-hardening.conf" "$WORK/coredump.new" 644
  else
    skip "systemd-coredump: this system does not use systemd"
  fi
}

# ---------------------------------------------------------------------------------------------
# Permissions of the account files (only ever tightened, ownership untouched)
# ---------------------------------------------------------------------------------------------

do_perms() {
  local spec f mask cur new changed=0 pfile="$STATE_DIR/perms.list"
  for spec in "shadow 027" "gshadow 027" "shadow- 027" "gshadow- 027" "passwd 022" "group 022" "passwd- 022" "group- 022"; do
    f="$R/etc/${spec% *}"
    mask="${spec#* }"
    if [ ! -f "$f" ]; then
      continue
    fi
    cur="$(file_mode "$f")"
    case "$cur" in
      '' | *[!0-7]*) continue ;;
    esac
    new="$(printf '%o' $((8#$cur & ~8#$mask)))"
    if [ "$((8#$cur))" -eq "$((8#$new))" ]; then
      continue
    fi
    changed=1
    if [ "$DRY" = 1 ]; then
      change "$(shown "$f"): permissions $cur would become $new"
      continue
    fi
    mkdir -p "$STATE_DIR"
    chmod 700 "$STATE_DIR"
    if [ ! -f "$pfile" ] || ! grep -q -F -- " $f" "$pfile"; then
      printf '%s %s\n' "$cur" "$f" >>"$pfile"
    fi
    chmod "$new" "$f"
    change "$(shown "$f"): permissions $cur -> $new"
  done
  if [ "$changed" = 0 ]; then
    ok "permissions of the account files (passwd, group, shadow, gshadow) are fine"
  fi
}

# ---------------------------------------------------------------------------------------------
# New-account defaults and password quality
# ---------------------------------------------------------------------------------------------

set_key_value() {
  # set_key_value FILE KEY VALUE: replace the first uncommented "KEY ..." line, or append one.
  awk -v k="$2" -v v="$3" '
    $1 == k && !done { print k "\t" v; done = 1; next }
    { print }
    END { if (!done) print k "\t" v }' "$1" >"$1.tmp"
  mv -f "$1.tmp" "$1"
}

do_logindefs() {
  # These keys are read by useradd when it creates an account, so only NEW accounts are affected;
  # existing accounts keep what they have. UMASK is deliberately left alone: it changes the
  # behaviour of every login session.
  local f="$R/etc/login.defs" kv key val cur
  if [ ! -f "$f" ]; then
    skip "/etc/login.defs not found"
    return 0
  fi
  cp "$f" "$WORK/login.defs.new"
  for kv in "PASS_MAX_DAYS 365" "PASS_WARN_AGE 14" "HOME_MODE 0750"; do
    key="${kv% *}"
    val="${kv#* }"
    cur="$(awk -v k="$key" '$1 == k { print $2; exit }' "$WORK/login.defs.new")"
    if [ "$cur" != "$val" ]; then
      set_key_value "$WORK/login.defs.new" "$key" "$val"
    fi
  done
  put_file "$f" "$WORK/login.defs.new" 644
}

do_pwquality() {
  # Applies when a password is next set or changed; no existing password is touched or expired.
  if [ ! -f "$R/etc/security/pwquality.conf" ]; then
    skip "password quality: libpwquality is not installed"
    return 0
  fi
  {
    printf '%s\n' "# Managed by harden-linux.sh (EPMA USB CREATOR). Applies to passwords set from now on."
    printf '%s\n' "# At least 12 characters, from at least 3 of the 4 classes (lower, upper, digit, other),"
    printf '%s\n' "# and no more than 3 identical characters in a row."
    printf '%s\n' "minlen = 12"
    printf '%s\n' "minclass = 3"
    printf '%s\n' "maxrepeat = 3"
  } >"$WORK/pwquality.new"
  put_file "$R/etc/security/pwquality.conf.d/99-epma-hardening.conf" "$WORK/pwquality.new" 644
}

# ---------------------------------------------------------------------------------------------
# SSH server (only when installed)
# ---------------------------------------------------------------------------------------------

sshd_installed() {
  have_cmd sshd || [ -x "$R/usr/sbin/sshd" ]
}

ssh_wanted() {
  local u
  if [ -n "${SSH_CONNECTION:-}" ]; then
    return 0
  fi
  for u in ssh sshd ssh.socket sshd.socket; do
    if service_active "$u" || service_enabled "$u"; then
      return 0
    fi
  done
  return 1
}

# Print the TCP ports of the SSH server that must stay reachable (nothing when SSH is not in use).
ssh_ports() {
  local list="" p out="" fromconn
  if ! ssh_wanted; then
    return 0
  fi
  if have_cmd sshd; then
    list="$(sysrun sshd -T 2>/dev/null | awk '$1 == "port" { print $2 }')" || list=""
  fi
  if [ -z "$list" ]; then
    list=22
  fi
  if [ -n "${SSH_CONNECTION:-}" ]; then
    fromconn="$(printf '%s' "$SSH_CONNECTION" | awk '{ print $4 }')"
    list="$list $fromconn"
  fi
  for p in $list; do
    case "$p" in
      '' | *[!0-9]*) continue ;;
    esac
    if [ "$p" -lt 1 ] || [ "$p" -gt 65535 ]; then
      continue
    fi
    case " $out " in
      *" $p "*) continue ;;
    esac
    out="$out $p"
  done
  printf '%s\n' "${out# }"
}

scan_authorized_keys() {
  local caller="${SUDO_USER:-root}" name home f
  KEYS_ANY=0
  KEYS_CALLER=0
  if [ ! -f "$R/etc/passwd" ]; then
    return 0
  fi
  while IFS=: read -r name _ _ _ _ home _; do
    if [ -z "$home" ]; then
      continue
    fi
    f="$R$home/.ssh/authorized_keys"
    if [ -f "$f" ] && grep -qvE '^[[:space:]]*(#|$)' "$f"; then
      KEYS_ANY=1
      if [ "$name" = "$caller" ]; then
        KEYS_CALLER=1
      fi
    fi
  done <"$R/etc/passwd"
}

has_regular_user() {
  # A normal login account (UID 1000-59999 with a real shell) exists, so root may be refused.
  [ -f "$R/etc/passwd" ] || return 1
  awk -F: '$3 >= 1000 && $3 < 60000 && $7 !~ /(nologin|false)$/ { found = 1 } END { exit !found }' "$R/etc/passwd"
}

build_sshd() {
  # $1 = PermitRootLogin value, $2 = 1 to turn password logins off
  printf '%s\n' "# Managed by harden-linux.sh (EPMA USB CREATOR). Remove this file, or run the script with --undo,"
  printf '%s\n' "# to go back. Note: sshd uses the FIRST value it reads for a keyword, so an earlier file in"
  printf '%s\n' "# this directory can win over this one (the script warns when that happens)."
  printf '\n%s\n%s\n' "# Nobody logs in directly as root over the network." "PermitRootLogin $1"
  printf '\n%s\n%s\n' "# No graphical-session forwarding (a rarely needed way to attack a client)." "X11Forwarding no"
  printf '\n%s\n%s\n' "# Fewer guesses per connection." "MaxAuthTries 4"
  printf '\n%s\n%s\n' "# Drop connections that have not logged in after 30 seconds." "LoginGraceTime 30"
  printf '\n%s\n%s\n' "# Never accept an account with an empty password." "PermitEmptyPasswords no"
  printf '\n%s\n%s\n%s\n' "# Probe silent clients and drop the dead ones after about 10 minutes (live sessions stay open)." "ClientAliveInterval 300" "ClientAliveCountMax 2"
  if [ "$2" = 1 ]; then
    printf '\n%s\n%s\n%s\n' "# Written because at least one account already has an authorized_keys file:" "# key logins keep working, password logins are refused." "PasswordAuthentication no"
  fi
}

reload_ssh() {
  local u
  for u in ssh sshd; do
    if service_active "$u"; then
      act_soft "reload the SSH server ($u)" systemctl reload "$u"
      return 0
    fi
  done
  skip "SSH server is not running; the new settings apply when it starts"
}

ssh_effective_check() {
  # sshd -T prints the effective configuration; warn when a value is not what this script asked for.
  local dump k want have
  dump="$(sysrun sshd -T 2>/dev/null)" || return 0
  if [ -z "$dump" ]; then
    return 0
  fi
  for k in "permitrootlogin $1" "x11forwarding no" "maxauthtries 4" "logingracetime 30" "permitemptypasswords no"; do
    want="${k#* }"
    have="$(printf '%s\n' "$dump" | awk -v key="${k% *}" '$1 == key { print $2; exit }')"
    if [ -n "$have" ] && [ "$have" != "$want" ]; then
      warn "SSH: ${k% *} is $have, not $want: an earlier configuration file overrides ours; edit that file"
    fi
  done
}

revert_sshd_dropin() {
  # revert_sshd_dropin DEST HAD_PREV
  if [ "$2" = 1 ]; then
    cp "$WORK/sshd.prev" "$1"
  else
    rm -f -- "${1:?}"
    unrecord_created "$1"
  fi
}

do_ssh() {
  local dest="$R/etc/ssh/sshd_config.d/99-epma-hardening.conf" main="$R/etc/ssh/sshd_config"
  local had_prev=0 rootlogin=no pwoff=0 err
  if ! sshd_installed; then
    skip "SSH: the SSH server is not installed, nothing to configure"
    return 0
  fi
  if [ ! -f "$main" ]; then
    skip "SSH: $(shown "$main") not found"
    return 0
  fi
  if ! grep -Eqi '^[[:space:]]*Include[[:space:]]+.*sshd_config\.d' "$main"; then
    warn "SSH: $(shown "$main") does not include sshd_config.d; not touching the main file, SSH left as it is"
    return 0
  fi
  if ! has_regular_user; then
    rootlogin=prohibit-password
    warn "SSH: no normal user account exists yet, so root keeps key-only login (PermitRootLogin prohibit-password)"
    notice "Create a normal user, then run this script again to refuse root logins over SSH."
  fi
  scan_authorized_keys
  if [ "$KEYS_ANY" = 1 ]; then
    if [ -n "${SSH_CONNECTION:-}" ] && [ "$KEYS_CALLER" = 0 ]; then
      warn "SSH: you are connected over SSH but your own account has no authorized_keys; password login left as it is"
    else
      pwoff=1
    fi
  fi
  build_sshd "$rootlogin" "$pwoff" >"$WORK/sshd.new"
  if [ -e "$dest" ]; then
    cp "$dest" "$WORK/sshd.prev"
    had_prev=1
  fi
  CHANGED_LAST=0
  put_file "$dest" "$WORK/sshd.new" 644
  if [ "$pwoff" = 1 ]; then
    if [ "$CHANGED_LAST" = 1 ]; then
      warn "SSH PASSWORD LOGIN IS NOW OFF: at least one account has authorized_keys, so PasswordAuthentication is set to no. Make sure you can log in with your key BEFORE you close this session."
      notice "SSH password login is OFF. Test your key from a second terminal before closing this one."
    else
      ok "SSH password login is off (authorized_keys found)"
    fi
  fi
  if [ "$DRY" = 1 ]; then
    if [ "$CHANGED_LAST" = 1 ]; then
      change "would: check the SSH configuration with sshd -t, undo the change if it fails, then reload the SSH server"
    fi
    return 0
  fi
  # Validate (even when nothing changed). sshd needs /run/sshd to exist for -t on Debian/Ubuntu.
  mkdir -p "$R/run/sshd" 2>/dev/null || true
  if err="$(sysrun sshd -t 2>&1)"; then
    ok "sshd -t accepts the SSH configuration"
  else
    revert_sshd_dropin "$dest" "$had_prev"
    warn "SSH: sshd -t rejected the configuration, so the change was reverted: $err"
    if [ "$CHROOT" = 0 ]; then
      N_ERR=$((N_ERR + 1))
    else
      notice "SSH settings were not applied inside the installer (sshd -t failed there); the first boot tries again."
    fi
    return 0
  fi
  if [ "$CHANGED_LAST" = 1 ]; then
    if [ "$CHROOT" = 1 ]; then
      skip "reload the SSH server (not done inside a chroot)"
    else
      reload_ssh
    fi
  fi
  if [ "$CHROOT" = 0 ]; then
    ssh_effective_check "$rootlogin"
  fi
}

# ---------------------------------------------------------------------------------------------
# Firewall
# ---------------------------------------------------------------------------------------------

firewall_ufw() {
  local status ports p ufw_ok=1 have_it=0
  if service_active firewalld; then
    skip "firewall: firewalld is active, ufw is not added next to it"
    return 0
  fi
  if pkg_installed ufw; then
    have_it=1
  fi
  pkg_install ufw || return 0
  if [ "$have_it" = 0 ] && [ "$DRY" = 1 ]; then
    change "(dry-run) ufw would be set to: deny incoming, allow outgoing, allow SSH when the SSH server is in use, then enabled"
    return 0
  fi
  status="$(sysrun ufw status verbose 2>&1)" || status=""
  case "$status" in
    *"Status: active"*)
      ok "firewall: ufw is already active; its rules are left as they are"
      case "$status" in
        *"deny (incoming)"* | *"reject (incoming)"*) ;;
        *) warn "firewall: ufw is active but incoming traffic is not denied by default" ;;
      esac
      return 0
      ;;
  esac
  ports="$(ssh_ports)"
  act "ufw: deny incoming connections by default" ufw default deny incoming || ufw_ok=0
  act "ufw: allow outgoing connections by default" ufw default allow outgoing || ufw_ok=0
  for p in $ports; do
    act "ufw: allow SSH on port $p/tcp" ufw allow "$p/tcp" || ufw_ok=0
  done
  if [ "$ufw_ok" = 0 ]; then
    warn "firewall: a ufw step failed, so ufw is NOT being enabled (to avoid cutting you off)"
    return 0
  fi
  act "ufw: enable the firewall" ufw --force enable || true
}

firewall_firewalld() {
  local zone ports p was_on=0 have_it=0
  if pkg_installed firewalld; then
    have_it=1
  fi
  pkg_install firewalld || return 0
  if [ "$have_it" = 0 ] && [ "$DRY" = 1 ]; then
    change "(dry-run) firewalld would be enabled and started, SSH kept reachable when the SSH server is in use"
    return 0
  fi
  if service_enabled firewalld && service_active firewalld; then
    was_on=1
  fi
  if [ "$was_on" = 1 ]; then
    ok "firewall: firewalld is enabled and running; its zones are left as they are"
    return 0
  fi
  enable_service firewalld || return 0
  if [ "$DRY" = 1 ]; then
    return 0
  fi
  ports="$(ssh_ports)"
  if [ -z "$ports" ]; then
    return 0
  fi
  zone="$(sysrun firewall-cmd --get-default-zone 2>/dev/null)" || zone=""
  if [ -z "$zone" ]; then
    warn "firewall: could not read the default firewalld zone; check by hand that SSH is allowed"
    return 0
  fi
  for p in $ports; do
    if [ "$p" = 22 ]; then
      if ! sysrun firewall-cmd --zone="$zone" --query-service=ssh >/dev/null 2>&1; then
        act "firewalld: allow the ssh service in zone $zone (now)" firewall-cmd --zone="$zone" --add-service=ssh || true
        act "firewalld: allow the ssh service in zone $zone (permanent)" firewall-cmd --permanent --zone="$zone" --add-service=ssh || true
      fi
    elif ! sysrun firewall-cmd --zone="$zone" --query-port="$p/tcp" >/dev/null 2>&1; then
      act "firewalld: allow port $p/tcp in zone $zone (now)" firewall-cmd --zone="$zone" --add-port="$p/tcp" || true
      act "firewalld: allow port $p/tcp in zone $zone (permanent)" firewall-cmd --permanent --zone="$zone" --add-port="$p/tcp" || true
    fi
  done
}

do_firewall() {
  if [ "$CHROOT" = 1 ]; then
    skip "firewall: set up on the first boot"
    return 0
  fi
  if [ "$FAMILY" = apt ]; then
    firewall_ufw
  else
    firewall_firewalld
  fi
}

# ---------------------------------------------------------------------------------------------
# Automatic security updates
# ---------------------------------------------------------------------------------------------

do_updates() {
  local timer unit listing pkg candidates
  if [ "$FAMILY" = apt ]; then
    {
      printf '%s\n' "// Managed by harden-linux.sh (EPMA USB CREATOR): refresh the package lists and run"
      printf '%s\n' "// unattended-upgrades every day."
      printf '%s\n' 'APT::Periodic::Update-Package-Lists "1";'
      printf '%s\n' 'APT::Periodic::Unattended-Upgrade "1";'
    } >"$WORK/auto-upgrades.new"
    put_file "$R/etc/apt/apt.conf.d/20auto-upgrades" "$WORK/auto-upgrades.new" 644
    cat >"$WORK/uu-origins.new" <<'EOF'
// Managed by harden-linux.sh (EPMA USB CREATOR): install SECURITY updates only, never other updates
// and never an automatic reboot. This replaces the distribution's default list of origins.
#clear Unattended-Upgrade::Allowed-Origins;
#clear Unattended-Upgrade::Origins-Pattern;
Unattended-Upgrade::Origins-Pattern {
        "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
        "origin=Debian,codename=${distro_codename},label=Debian-Security";
        "origin=Ubuntu,archive=${distro_codename}-security";
        "origin=UbuntuESMApps,codename=${distro_codename}-apps-security";
        "origin=UbuntuESM,codename=${distro_codename}-infra-security";
};
Unattended-Upgrade::Automatic-Reboot "false";
EOF
    put_file "$R/etc/apt/apt.conf.d/52epma-hardening-unattended" "$WORK/uu-origins.new" 644
    pkg_install unattended-upgrades || true
  else
    cat >"$WORK/dnf-automatic.new" <<'EOF'
# Managed by harden-linux.sh (EPMA USB CREATOR): download and install SECURITY updates only,
# never reboot by itself, and write the report to the journal.
[commands]
upgrade_type = security
download_updates = yes
apply_updates = yes
random_sleep = 360

[emitters]
emit_via = stdio
EOF
    put_file "$R/etc/dnf/automatic.conf" "$WORK/dnf-automatic.new" 644
    # Fedora 41 and newer ship dnf5 (package dnf5-plugin-automatic); RHEL and older Fedora use dnf-automatic.
    pkg=dnf-automatic
    candidates="dnf-automatic-install.timer dnf-automatic.timer"
    if pkg_installed dnf5; then
      pkg=dnf5-plugin-automatic
      candidates="dnf5-automatic.timer dnf-automatic-install.timer"
    fi
    if pkg_install "$pkg"; then
      timer=""
      listing="$(sysrun systemctl list-unit-files 2>/dev/null)" || listing=""
      for unit in $candidates; do
        if [ -z "$timer" ]; then
          case "$listing" in
            *"$unit"*) timer="$unit" ;;
          esac
        fi
      done
      if [ -z "$timer" ]; then
        timer="${candidates%% *}"
      fi
      if [ "$CHROOT" = 0 ]; then
        enable_service "$timer" || true
      fi
    fi
  fi
}

# ---------------------------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------------------------

build_audit_rules() {
  local path
  printf '%s\n' "# Managed by harden-linux.sh (EPMA USB CREATOR): a small set of audit watches. Only paths that"
  printf '%s\n' "# exist are listed (auditctl refuses a watch on a missing path). No immutable flag is set."
  for path in "/etc/passwd identity" "/etc/group identity" "/etc/shadow identity" "/etc/gshadow identity" \
    "/etc/sudoers sudoers" "/etc/sudoers.d/ sudoers" "/etc/ssh/sshd_config sshd" "/etc/ssh/sshd_config.d/ sshd" \
    "/var/log/lastlog logins"; do
    if [ -e "$R${path% *}" ]; then
      printf -- '-w %s -p wa -k %s\n' "${path% *}" "${path#* }"
    fi
  done
}

do_audit() {
  local pkg=auditd rules="$R/etc/audit/rules.d/99-epma-hardening.rules"
  if [ "$FAMILY" = dnf ]; then
    pkg=audit
  fi
  if pkg_install "$pkg"; then
    build_audit_rules >"$WORK/audit.new"
    CHANGED_LAST=0
    put_file "$rules" "$WORK/audit.new" 640
    if [ "$CHROOT" = 0 ]; then
      enable_service auditd || true
      if [ "$CHANGED_LAST" = 1 ]; then
        act_soft "load the audit rules now (augenrules --load)" augenrules --load
      fi
    fi
  else
    # Still write the rules where the package will find them.
    build_audit_rules >"$WORK/audit.new"
    put_file "$rules" "$WORK/audit.new" 640
  fi
}

# ---------------------------------------------------------------------------------------------
# AppArmor / SELinux: report only
# ---------------------------------------------------------------------------------------------

report_mac() {
  local state cfg runtime=""
  if [ "$FAMILY" = apt ]; then
    skip "SELinux: not used by this distribution family"
    if [ -r "$R/sys/module/apparmor/parameters/enabled" ]; then
      state="$(cat "$R/sys/module/apparmor/parameters/enabled" 2>/dev/null || true)"
      if [ "$state" = Y ]; then
        ok "AppArmor is enabled"
      else
        warn "AppArmor is built in but NOT enabled (boot parameter apparmor=1 security=apparmor). Reported only, not changed."
      fi
    else
      warn "AppArmor does not appear to be active in the running kernel. Reported only, not changed."
    fi
    return 0
  fi
  skip "AppArmor: not used by this distribution family"
  cfg="$(awk -F= '$1 == "SELINUX" { print $2; exit }' "$R/etc/selinux/config" 2>/dev/null | tr -d ' "' | tr '[:upper:]' '[:lower:]')" || cfg=""
  if [ "$CHROOT" = 0 ] && have_cmd getenforce; then
    runtime="$(sysrun getenforce 2>/dev/null | tr '[:upper:]' '[:lower:]')" || runtime=""
  fi
  if [ "$runtime" = enforcing ] || { [ -z "$runtime" ] && [ "$cfg" = enforcing ]; }; then
    ok "SELinux is enforcing"
  else
    warn "SELinux is not enforcing (running: ${runtime:-unknown}, configured: ${cfg:-unknown}). Reported only, not changed."
  fi
}

# ---------------------------------------------------------------------------------------------
# First boot service (installer chroot only)
# ---------------------------------------------------------------------------------------------

emit_self() {
  # A working copy of this script, rebuilt from the functions that are loaded (used when the
  # script came in through "bash -s" and there is no file to copy).
  printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail'
  declare -f
  printf '%s\n' 'main "$@"'
}

self_copy() {
  # self_copy DEST: write a copy of this script to DEST.
  if [ -f "$0" ] && [ -r "$0" ] && [ "$(head -c 2 "$0")" = '#!' ] && grep -q '^emit_self()' "$0"; then
    cp "$0" "$1"
  else
    emit_self >"$1"
  fi
}

do_firstboot_install() {
  local unit="$R/etc/systemd/system/$UNIT_NAME" sbin="$R/usr/local/sbin/epma-harden-linux.sh"
  local wants="$R/etc/systemd/system/multi-user.target.wants/$UNIT_NAME"
  local marker="$STATE_DIR/firstboot.pending"
  self_copy "$WORK/self.sh"
  put_file "$sbin" "$WORK/self.sh" 755
  cat >"$WORK/unit.new" <<'EOF'
# Managed by harden-linux.sh (EPMA USB CREATOR). Runs the hardening script once on the first boot
# of the installed system (packages, firewall and services cannot be set up inside the installer),
# then turns itself off. If a step fails (for example there is no network yet) it tries again at
# the next boot.
[Unit]
Description=EPMA hardening (first boot)
Wants=network-online.target
After=network-online.target
ConditionPathExists=/var/lib/epma-hardening/firstboot.pending

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/epma-harden-linux.sh --yes
TimeoutStartSec=1800

[Install]
WantedBy=multi-user.target
EOF
  put_file "$unit" "$WORK/unit.new" 644
  if [ "$DRY" = 1 ]; then
    change "would: arm the first-boot service ($UNIT_NAME) and its marker file"
    return 0
  fi
  if [ ! -f "$marker" ]; then
    mkdir -p "$STATE_DIR"
    chmod 700 "$STATE_DIR"
    printf '%s\n' "pending" >"$marker"
    record_state created "$marker"
    change "$(shown "$marker"): created"
  fi
  if [ ! -L "$wants" ]; then
    mkdir -p "$(dirname "$wants")"
    ln -s "../$UNIT_NAME" "$wants"
    record_state created "$wants"
    change "$UNIT_NAME: enabled for the first boot ($(shown "$wants"))"
  else
    ok "$UNIT_NAME is already enabled"
  fi
}

finish_firstboot() {
  # After a clean real run on the installed system: switch the one-shot service off for good.
  local marker="$STATE_DIR/firstboot.pending" wants="$R/etc/systemd/system/multi-user.target.wants/$UNIT_NAME"
  if [ ! -f "$marker" ]; then
    return 0
  fi
  if [ "$DRY" = 1 ]; then
    change "would: switch the first-boot service off (hardening finished)"
    return 0
  fi
  if [ "$N_ERR" -gt 0 ]; then
    warn "the first-boot service stays on and will try again at the next boot"
    return 0
  fi
  act_soft "disable $UNIT_NAME" systemctl disable "$UNIT_NAME"
  rm -f -- "${marker:?}"
  if [ -L "$wants" ]; then
    rm -f -- "${wants:?}"
  fi
  change "first-boot service switched off: hardening is finished"
}

# ---------------------------------------------------------------------------------------------
# Undo
# ---------------------------------------------------------------------------------------------

undo_path_ok() {
  case "$1" in
    "$R"/etc/* | "$R"/usr/local/sbin/* | "$R"/var/lib/epma-hardening/*) ;;
    *) return 1 ;;
  esac
  case "$1" in
    *..*) return 1 ;;
  esac
  return 0
}

do_undo() {
  local p bak mode f done_any=0
  f="$STATE_DIR/created.list"
  if [ -f "$f" ]; then
    while IFS= read -r p; do
      if [ -z "$p" ]; then
        continue
      fi
      if ! undo_path_ok "$p"; then
        warn "undo: ignoring an unexpected path in the state file: $p"
        continue
      fi
      if [ -e "$p" ] || [ -L "$p" ]; then
        done_any=1
        if [ "$DRY" = 1 ]; then
          change "$(shown "$p"): would be removed (created by this script)"
        else
          rm -f -- "${p:?}"
          change "$(shown "$p"): removed (created by this script)"
        fi
      fi
    done <"$f"
  fi
  f="$STATE_DIR/modified.list"
  if [ -f "$f" ]; then
    while IFS= read -r p; do
      if [ -z "$p" ]; then
        continue
      fi
      if ! undo_path_ok "$p"; then
        warn "undo: ignoring an unexpected path in the state file: $p"
        continue
      fi
      bak="$p.epma-bak"
      if [ -e "$bak" ]; then
        done_any=1
        if [ "$DRY" = 1 ]; then
          change "$(shown "$p"): would be restored from $(shown "$bak")"
        else
          mv -f "$bak" "$p"
          change "$(shown "$p"): restored from $(shown "$bak")"
        fi
      fi
    done <"$f"
  fi
  f="$STATE_DIR/perms.list"
  if [ -f "$f" ]; then
    while IFS=' ' read -r mode p; do
      if [ -z "$p" ] || [ ! -e "$p" ]; then
        continue
      fi
      if ! undo_path_ok "$p"; then
        continue
      fi
      case "$mode" in
        '' | *[!0-7]*) continue ;;
      esac
      done_any=1
      if [ "$DRY" = 1 ]; then
        change "$(shown "$p"): permissions would go back to $mode"
      else
        chmod "$mode" "$p"
        change "$(shown "$p"): permissions back to $mode"
      fi
    done <"$f"
  fi
  if [ "$done_any" = 0 ]; then
    ok "nothing to undo: no changes by this script were found"
  elif [ "$DRY" = 0 ]; then
    rm -f -- "${STATE_DIR:?}/created.list" "${STATE_DIR:?}/modified.list" "${STATE_DIR:?}/perms.list"
    rmdir "$STATE_DIR" 2>/dev/null || true
    warn "kernel settings that were already loaded stay until the next boot; packages and services that were installed or enabled (ufw, firewalld, auditd, automatic updates) are left as they are"
  fi
}

# ---------------------------------------------------------------------------------------------
# Summary and main
# ---------------------------------------------------------------------------------------------

summary() {
  say ""
  say "Summary: $N_OK ok, $N_CHANGE changed, $N_SKIP skipped, $N_WARN warnings, $N_ERR errors"
  if [ "$DRY" = 1 ]; then
    say "Dry run: nothing was changed (no file, package, service or log entry)."
  else
    say "Log: $(shown "$LOG_FILE")"
    if [ "$UNDO" = 0 ]; then
      say "To go back: sudo bash harden-linux.sh --undo"
    fi
  fi
  if [ -n "$NOTICES" ]; then
    say "Please read:"
    printf '%s' "$NOTICES"
    log_line "notices: $NOTICES"
  fi
}

main() {
  init_globals
  parse_args "$@"
  if [ "$HELP" = 1 ]; then
    usage
    exit 0
  fi
  setup_env
  init_paths
  detect_distro
  trap cleanup EXIT
  print_plan
  confirm_run
  init_log
  setup_work
  if [ "$UNDO" = 1 ]; then
    do_undo
  else
    do_sysctl
    do_modprobe
    do_coredumps
    do_perms
    do_logindefs
    do_pwquality
    do_ssh
    do_firewall
    do_updates
    do_audit
    report_mac
    if [ "$CHROOT" = 1 ]; then
      do_firstboot_install
    else
      finish_firstboot
    fi
  fi
  summary
  if [ "$N_ERR" -gt 0 ]; then
    exit 1
  fi
  exit 0
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --dry-run) DRY=1 ;;
      --yes | -y) YES=1 ;;
      --undo) UNDO=1 ;;
      --chroot) CHROOT=1 ;;
      --help | -h) HELP=1 ;;
      --) ;;
      *)
        printf 'harden-linux.sh: unknown option: %s\n\n' "$1" >&2
        usage >&2
        exit 2
        ;;
    esac
    shift
  done
}

main "$@"
"""


def linux_hardening_script(profile):
    """The text of `harden-linux.sh` for `profile` (pure ASCII). HARDENING_NONE has nothing to harden."""
    if profile == HARDENING_NONE:
        raise ValueError("nothing to harden: the profile is 'none'")
    if profile != HARDENING_BASELINE:
        raise ValueError(f"unknown hardening profile: {profile!r}")
    return _HARDEN_LINUX_SH


# ===== end hardening: linux script =====


def chromeos_drive_too_small(mode, drive_size):
    """True when ChromeOS Flex is going to a drive below the 16 GB Google asks for (a warning, not a refusal)."""
    return mode == MODE_CHROMEOS and bool(drive_size) and drive_size < CHROMEOS_MIN_USB_BYTES


def get_missing_dependencies(mode=MODE_WINDOWS):
    if mode in RAW_MODES:
        return [] if shutil.which("dd") else ["dd"]  # raw write needs nothing else
    if IS_MAC:
        return [] if shutil.which("wimlib-imagex") else ["wimlib-imagex"]
    return [t for t in LINUX_REQUIRED_TOOLS if not shutil.which(t)]


# ===== hardening: windows content =====
# What the "Hardened setup" option adds to the Windows 11 install media. Everything here is PURE: text in, bytes
# out. Nothing touches a drive and nothing is executed on this computer. The files are plain ASCII so no
# encoding surprise can reach the target PC.
#
# Honest naming: these are "recommended settings inspired by common baselines", NOT a compliance profile.
WINDOWS_HARDENING_LOG = "%windir%\\Temp\\epma-hardening.log"  # where SetupComplete.cmd and harden.ps1 write
WINDOWS_HARDENING_AUTOUNATTEND = "autounattend.xml"
WINDOWS_HARDENING_SCRIPTS_DIR = "sources/$OEM$/$$/Setup/Scripts"  # `$$` is copied to %windir% by Windows Setup
WINDOWS_HARDENING_CMD = WINDOWS_HARDENING_SCRIPTS_DIR + "/SetupComplete.cmd"
WINDOWS_HARDENING_PS1 = WINDOWS_HARDENING_SCRIPTS_DIR + "/harden.ps1"

# One row per setting: (id, short text, risk note). The id is also the marker in harden.ps1 ("# setting: <id>");
# the script header and describe_hardening_windows() are generated from these rows, and a test checks that every
# row has a code block and every code block has a row. The baseline is kept SMALL: anything that commonly
# breaks home or office use is left out (see WINDOWS_HARDENING_NOT_CHANGED).
WINDOWS_HARDENING_SETTINGS = (
    ("smb1", "Turn off SMBv1 (obsolete file-sharing protocol)",
     "Very old NAS boxes, scanners or Windows XP-era PCs that only speak SMBv1 can no longer connect."),
    ("llmnr", "Turn off LLMNR name lookups",
     "Single-word names that only resolve through LLMNR stop resolving on networks without proper DNS."),
    ("autorun", "Turn off AutoRun and AutoPlay on every drive type",
     "Inserted USB sticks and discs no longer start installers or show the AutoPlay prompt; open them from File Explorer."),
    ("firewall", "Windows Firewall on for all network profiles, inbound blocked unless a rule allows it",
     "A program that must accept incoming connections (game server, file sharing, remote tools) needs an allow rule."),
    ("defender_cloud", "Defender: block potentially unwanted apps and turn cloud protection on",
     "Some bundled freeware may be flagged, and cloud protection sends file metadata to Microsoft. Fails harmlessly when another antivirus is active."),
    ("asr_lsass", "Defender attack surface rule in Block mode: no credential stealing from LSASS",
     "Rarely, security or backup tools that read LSASS memory are blocked and Defender shows a notification."),
    ("asr_audit", "Defender attack surface rules in Audit mode (log only): email executable content, Office child processes, obfuscated scripts, script-launched downloads",
     "Audit mode only writes events and blocks nothing. Review the Defender event log before switching any rule to Block."),
    ("wdigest", "Do not keep plain-text WDigest credentials in memory",
     "Only legacy digest authentication against very old web servers is affected."),
    ("ps_logging", "PowerShell script block logging",
     "Adds events to the PowerShell log; secrets typed inside a script would be logged as well."),
    ("ps2", "Remove the PowerShell 2.0 optional feature",
     "Very old scripts or tools that insist on running with -Version 2 stop working."),
    ("remote_assist", "Turn off Remote Assistance invitations",
     "Old-style Remote Assistance invitations stop working; Quick Assist and Remote Desktop are not changed."),
    ("audit", "Basic audit policy: sign-ins, account lockouts, account and group changes, audit-policy changes, process creation",
     "The Security event log fills faster; Windows overwrites the oldest events when it is full."),
    ("uac", "Keep User Account Control switched on",
     "Only acts when UAC was switched off; takes effect after the next restart."),
)

# Deliberately NOT done, with the reason (shown in the script header and available to the README / help text).
WINDOWS_HARDENING_NOT_CHANGED = (
    ("bitlocker", "BitLocker is not turned on automatically",
     "It needs a TPM, a choice of where the recovery key goes and the owner's consent; a wrong default can lock someone out of their own data."),
    ("ntlm", "NTLM authentication levels are left as they are",
     "Stricter levels can break access to older file shares, printers and NAS devices without any warning."),
    ("accounts_disks", "Accounts, passwords, disks, language, licence and product key",
     "Windows Setup stays fully interactive; the answer file never touches them."),
)


def _windows_hardening_check(profile):
    """Validate the profile name; True when there is something to add (anything but HARDENING_NONE)."""
    if profile not in HARDENING_PROFILES:
        raise ValueError(f"unknown hardening profile: {profile!r}")
    return profile != HARDENING_NONE


def describe_hardening_windows(profile):
    """Human-readable lines (English, ASCII) saying what the Windows hardening changes and what it risks.

    One line per setting: "<text> -- risk: <note>". Empty for HARDENING_NONE; unknown profile -> ValueError.
    """
    if not _windows_hardening_check(profile):
        return []
    return [f"{text} -- risk: {risk}" for _sid, text, risk in WINDOWS_HARDENING_SETTINGS]


def _windows_autounattend_xml():
    # A deliberately tiny answer file. Windows Setup stays interactive: no disk selection, no licence
    # acceptance, no keys, no accounts, no language or region forcing, no requirement bypasses and no
    # shutdown or seal action. The only thing it sets is the most protective privacy choice of the first-run
    # screens that still lets the person create an account normally.
    # ProtectYourPC = 1 means "recommended": automatic updates and SmartScreen stay ON (the value 3 would turn
    # automatic updates OFF, so it must never be used). Recent Windows 11 builds may ignore the element, which
    # is harmless. The component is listed for both processor families because Setup ignores the one that does
    # not match the media; the SetupComplete script under sources does the real work.
    component = (
        '    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="{arch}"'
        ' publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"'
        ' xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"'
        ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\n'
        "      <OOBE>\n"
        "        <ProtectYourPC>1</ProtectYourPC>\n"
        "      </OOBE>\n"
        "    </component>\n"
    )
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        "<!-- EPMA USB CREATOR: optional hardened setup (recommended settings). Setup stays interactive. -->\n"
        "<!-- Edit or delete this file freely; the media installs fine without it. -->\n"
        '<unattend xmlns="urn:schemas-microsoft-com:unattend">\n'
        '  <settings pass="oobeSystem">\n'
        + component.format(arch="amd64")
        + component.format(arch="arm64")
        + "  </settings>\n"
        "</unattend>\n"
    ).encode("utf-8")


def _windows_setupcomplete_cmd():
    # SetupComplete.cmd runs once as SYSTEM at the very end of Setup (before the first sign-in), from
    # %windir%\Setup\Scripts. It must never make Setup fail, so every path ends in `exit /b 0`. No parenthesised
    # blocks on purpose: %errorlevel% inside one is expanded too early.
    lines = (
        "@echo off",
        "rem EPMA USB CREATOR - optional hardened setup. Runs harden.ps1 once, logs, never fails the setup.",
        'set "EPMA_LOG=' + WINDOWS_HARDENING_LOG + '"',
        'echo [%date% %time%] SetupComplete.cmd: starting >> "%EPMA_LOG%"',
        'if not exist "%~dp0harden.ps1" goto missing',
        'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0harden.ps1" >> "%EPMA_LOG%" 2>&1',
        'echo [%date% %time%] SetupComplete.cmd: harden.ps1 exit code %errorlevel% (ignored) >> "%EPMA_LOG%"',
        "goto done",
        ":missing",
        'echo [SKIP] harden.ps1 not found next to SetupComplete.cmd >> "%EPMA_LOG%"',
        ":done",
        "exit /b 0",
    )
    return ("\r\n".join(lines) + "\r\n").encode("ascii")


# PowerShell code for each setting. A block runs inside its own try/catch, logs exactly one line
# ([OK], [SKIP] or [FAIL]), and can run again without changing anything. `@WHAT@` is replaced by the setting's
# text from WINDOWS_HARDENING_SETTINGS. Only PowerShell 5.1 syntax; no network access, no downloads.
_WINDOWS_PS_CODE = {
    "smb1": r"""
try {
    $c1 = Set-RegDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1' -Value 0
    $note = 'server side already off'
    if ($c1) { $note = 'server side turned off' }
    $feature = Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction SilentlyContinue
    if ($null -eq $feature) {
        $note = $note + '; optional feature not present'
    } elseif ($feature.State -eq 'Enabled') {
        Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -NoRestart | Out-Null
        $note = $note + '; optional feature removed'
    } else {
        $note = $note + '; optional feature already off'
    }
    Write-Result 'OK' '@WHAT@' $note
} catch {
    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message
}
""",
    "llmnr": r"""
try {
    $c1 = Set-RegDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 0
    Write-Result 'OK' '@WHAT@' (Get-ChangeText $c1)
} catch {
    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message
}
""",
    "autorun": r"""
try {
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    $c1 = Set-RegDword -Path $key -Name 'NoDriveTypeAutoRun' -Value 255
    $c2 = Set-RegDword -Path $key -Name 'NoAutorun' -Value 1
    Write-Result 'OK' '@WHAT@' (Get-ChangeText ($c1 -or $c2))
} catch {
    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message
}
""",
    "firewall": r"""
try {
    $profiles = @(Get-NetFirewallProfile -Profile Domain,Private,Public)
    $todo = @($profiles | Where-Object { ($_.Enabled -ne 'True') -or ($_.DefaultInboundAction -ne 'Block') })
    if ($todo.Count -eq 0) {
        Write-Result 'OK' '@WHAT@' 'already set'
    } else {
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block
        Write-Result 'OK' '@WHAT@' ('changed on ' + $todo.Count + ' profile(s)')
    }
} catch {
    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message
}
""",
    "defender_cloud": r"""
try {
    if (-not (Get-Command Set-MpPreference -ErrorAction SilentlyContinue)) {
        Write-Result 'SKIP' '@WHAT@' 'Defender cmdlets not available'
    } else {
        $pref = Get-MpPreference
        $changed = @()
        if ([int]$pref.PUAProtection -ne 1) {
            Set-MpPreference -PUAProtection Enabled
            $changed += 'PUA protection'
        }
        if ([int]$pref.MAPSReporting -ne 2) {
            Set-MpPreference -MAPSReporting Advanced
            $changed += 'cloud protection'
        }
        if ($changed.Count -eq 0) {
            Write-Result 'OK' '@WHAT@' 'already set'
        } else {
            Write-Result 'OK' '@WHAT@' ('turned on: ' + ($changed -join ', '))
        }
    }
} catch {
    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message
}
""",
    "asr_lsass": r"""
try {
    if (-not (Get-Command Add-MpPreference -ErrorAction SilentlyContinue)) {
        Write-Result 'SKIP' '@WHAT@' 'Defender cmdlets not available'
    } else {
        $r = Set-AsrRule -Id '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' -Action 'Enabled'
        Write-Result 'OK' '@WHAT@' $r
    }
} catch {
    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message
}
""",
    "asr_audit": r"""
try {
    if (-not (Get-Command Add-MpPreference -ErrorAction SilentlyContinue)) {
        Write-Result 'SKIP' '@WHAT@' 'Defender cmdlets not available'
    } else {
        $rules = @(
            'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550',
            'd4f940ab-401b-4efc-aadc-ad5f3c50688a',
            '5beb7efe-fd9a-4556-801d-275e5ffc04cc',
            'd3e037e1-3eb8-44c8-a917-57927947596d'
        )
        $applied = 0
        foreach ($id in $rules) {
            $r = Set-AsrRule -Id $id -Action 'AuditMode'
            if ($r -eq 'changed') { $applied++ }
        }
        Write-Result 'OK' '@WHAT@' ('' + $applied + ' of ' + $rules.Count + ' rules changed, the others were already set')
    }
} catch {
    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message
}
""",
    "wdigest": r"""
try {
    $c1 = Set-RegDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value 0
    Write-Result 'OK' '@WHAT@' (Get-ChangeText $c1)
} catch {
    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message
}
""",
    "ps_logging": r"""
try {
    $c1 = Set-RegDword -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1
    Write-Result 'OK' '@WHAT@' (Get-ChangeText $c1)
} catch {
    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message
}
""",
    "ps2": r"""
try {
    $found = $false
    $removed = $false
    foreach ($name in @('MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2')) {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $name -ErrorAction SilentlyContinue
        if ($null -ne $feature) {
            $found = $true
            if ($feature.State -eq 'Enabled') {
                Disable-WindowsOptionalFeature -Online -FeatureName $name -NoRestart | Out-Null
                $removed = $true
            }
        }
    }
    if (-not $found) {
        Write-Result 'SKIP' '@WHAT@' 'feature not present on this Windows build'
    } elseif ($removed) {
        Write-Result 'OK' '@WHAT@' 'feature removed'
    } else {
        Write-Result 'OK' '@WHAT@' 'already off'
    }
} catch {
    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message
}
""",
    "remote_assist": r"""
try {
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'
    $c1 = Set-RegDword -Path $key -Name 'fAllowToGetHelp' -Value 0
    $c2 = Set-RegDword -Path $key -Name 'fAllowFullControl' -Value 0
    Write-Result 'OK' '@WHAT@' (Get-ChangeText ($c1 -or $c2))
} catch {
    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message
}
""",
    "audit": r"""
try {
    # Subcategories are addressed by GUID because their names are translated on non-English Windows.
    # Logon, Account Lockout, User Account Management, Security Group Management, Audit Policy Change
    # (success and failure); Process Creation (success only, no command-line capture).
    $items = @(
        @('{0CCE9215-69AE-11D9-BED3-505054503030}', '/success:enable', '/failure:enable'),
        @('{0CCE9217-69AE-11D9-BED3-505054503030}', '/success:enable', '/failure:enable'),
        @('{0CCE9235-69AE-11D9-BED3-505054503030}', '/success:enable', '/failure:enable'),
        @('{0CCE9237-69AE-11D9-BED3-505054503030}', '/success:enable', '/failure:enable'),
        @('{0CCE922F-69AE-11D9-BED3-505054503030}', '/success:enable', '/failure:enable'),
        @('{0CCE922B-69AE-11D9-BED3-505054503030}', '/success:enable', '')
    )
    $bad = 0
    foreach ($item in $items) {
        if ($item[2] -eq '') {
            & auditpol.exe /set ('/subcategory:' + $item[0]) $item[1] | Out-Null
        } else {
            & auditpol.exe /set ('/subcategory:' + $item[0]) $item[1] $item[2] | Out-Null
        }
        if ($LASTEXITCODE -ne 0) { $bad++ }
    }
    if ($bad -gt 0) {
        Write-Result 'FAIL' '@WHAT@' ('auditpol failed for ' + $bad + ' of ' + $items.Count + ' subcategories')
    } else {
        Write-Result 'OK' '@WHAT@' ('' + $items.Count + ' subcategories set')
    }
} catch {
    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message
}
""",
    "uac": r"""
try {
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $cur = (Get-ItemProperty -LiteralPath $key -Name 'EnableLUA' -ErrorAction SilentlyContinue).EnableLUA
    if (($null -ne $cur) -and ([int]$cur -eq 0)) {
        Set-RegDword -Path $key -Name 'EnableLUA' -Value 1 | Out-Null
        Write-Result 'OK' '@WHAT@' 'was off, turned on (effective after the next restart)'
    } else {
        Write-Result 'OK' '@WHAT@' 'already on, left unchanged'
    }
} catch {
    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message
}
""",
}

_WINDOWS_PS_HELPERS = r"""
$ErrorActionPreference = 'Stop'
$script:CountOk = 0
$script:CountSkip = 0
$script:CountFail = 0

# One log line per setting: [OK], [SKIP] or [FAIL], what it was, and why. SetupComplete.cmd appends the
# output of this script to the log file, so nothing here opens the log itself.
function Write-Result {
    param([string]$Status, [string]$What, [string]$Why)
    if ($Status -eq 'OK') { $script:CountOk++ }
    elseif ($Status -eq 'SKIP') { $script:CountSkip++ }
    else { $script:CountFail++ }
    Write-Host ('[' + $Status + '] ' + $What + ' (' + $Why + ')')
}

function Get-ChangeText {
    param([bool]$Changed)
    if ($Changed) { return 'changed' }
    return 'already set'
}

# Writes one DWORD only when it differs. Returns $true when it changed something.
function Set-RegDword {
    param([string]$Path, [string]$Name, [int]$Value)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    $current = $null
    $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $item) { $current = $item.$Name }
    if (($null -ne $current) -and ([int]$current -eq $Value)) { return $false }
    New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
    return $true
}

# Attack surface reduction rule: 'Enabled' (Block) or 'AuditMode'. A rule that is already Block or Warn is
# never weakened to Audit. Returns 'changed' or 'already set'.
function Set-AsrRule {
    param([string]$Id, [string]$Action)
    $pref = Get-MpPreference
    $ids = @()
    $actions = @()
    if ($null -ne $pref.AttackSurfaceReductionRules_Ids) {
        $ids = @($pref.AttackSurfaceReductionRules_Ids)
        $actions = @($pref.AttackSurfaceReductionRules_Actions)
    }
    $wanted = 2
    if ($Action -eq 'Enabled') { $wanted = 1 }
    for ($i = 0; $i -lt $ids.Count; $i++) {
        if ([string]$ids[$i] -ieq $Id) {
            $current = [int]$actions[$i]
            if ($current -eq $wanted) { return 'already set' }
            if (($wanted -eq 2) -and (($current -eq 1) -or ($current -eq 6))) { return 'already set' }
        }
    }
    if ($wanted -eq 1) {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $Id -AttackSurfaceReductionRules_Actions Enabled
    } else {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $Id -AttackSurfaceReductionRules_Actions AuditMode
    }
    return 'changed'
}
"""


def _windows_ps_comment_lines(rows):
    out = []
    for sid, text, note in rows:
        out.append(f"#   {sid}: {text}")
        out.append(f"#       risk/why: {note}")
    return out


def _windows_harden_ps1():
    if [s[0] for s in WINDOWS_HARDENING_SETTINGS] != list(_WINDOWS_PS_CODE):
        raise RuntimeError("PowerShell code blocks and hardening settings do not match")
    head = [
        "# EPMA USB CREATOR - optional hardened setup for Windows 11 (recommended settings inspired by common",
        "# baselines; this is NOT a compliance profile). Runs once from SetupComplete.cmd as SYSTEM, can be run",
        "# again at any time and changes nothing that is already set. PowerShell 5.1; no network access, no",
        "# downloads, no extra tools (auditpol.exe is part of Windows). Every setting has its own error handler",
        "# and writes one line: [OK], [SKIP] or [FAIL], what it is, and why. Output goes to",
        "# " + WINDOWS_HARDENING_LOG + " (appended by SetupComplete.cmd). The exit code is always 0.",
        "#",
        "# Settings, each with the risk it carries:",
        *_windows_ps_comment_lines(WINDOWS_HARDENING_SETTINGS),
        "#",
        "# Deliberately NOT changed:",
        *_windows_ps_comment_lines(WINDOWS_HARDENING_NOT_CHANGED),
    ]
    body = []
    for sid, text, _risk in WINDOWS_HARDENING_SETTINGS:
        code = _WINDOWS_PS_CODE[sid].replace("@WHAT@", text.replace("'", "''")).strip("\n")
        body.append(f"\n# setting: {sid}\n{code}\n")
    tail = (
        "\nWrite-Host ('[DONE] ' + $script:CountOk + ' ok, ' + $script:CountSkip + ' skipped, '"
        " + $script:CountFail + ' failed')\n"
        "exit 0\n"
    )
    text = (
        "\n".join(head) + "\n"
        + _WINDOWS_PS_HELPERS
        + "\nWrite-Host ('[START] EPMA hardening ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))\n"
        + "".join(body) + tail
    )
    return b"\xef\xbb\xbf" + text.replace("\n", "\r\n").encode("ascii")  # BOM: PowerShell 5.1 reads ANSI without it


def hardening_files_windows(profile):
    """The files the Windows 11 install media gets for the hardened setup: {relative posix path: bytes}.

    autounattend.xml (tiny, Setup stays interactive), sources/$OEM$/$$/Setup/Scripts/SetupComplete.cmd and
    harden.ps1 (applied once at the end of Setup, logged to %windir%\\Temp\\epma-hardening.log).
    Empty for HARDENING_NONE; an unknown profile raises ValueError.
    """
    if not _windows_hardening_check(profile):
        return {}
    return {
        WINDOWS_HARDENING_AUTOUNATTEND: _windows_autounattend_xml(),
        WINDOWS_HARDENING_CMD: _windows_setupcomplete_cmd(),
        WINDOWS_HARDENING_PS1: _windows_harden_ps1(),
    }
# ===== end hardening: windows content =====


# ===== hardening: seed content =====
# The files of the "seed drive": a small second USB that is plugged in next to a Linux installer USB.
# Nothing here selects a disk, creates an account or stores a secret: storage, accounts and the final
# summary stay interactive in every installer. The hardening script is embedded as base64 inside the
# seed itself (so the seed works even when the other files are not read) and is also written as a
# plain file for reading and for running by hand. Output is deterministic: same input, same bytes.
SEED_LABELS = {SEED_UBUNTU: "CIDATA", SEED_FEDORA: "OEMDRV", SEED_DEBIAN: "EPMA-SEED"}
SEED_SCRIPT_NAME = "harden-linux.sh"
SEED_LOG_NAME = "epma-hardening.log"  # written inside the installed system, in /var/log
SEED_BASE64_WIDTH = 76
SEED_README_WIDTH = 78
SEED_README_TITLES = {
    SEED_UBUNTU: "Ubuntu (autoinstall)",
    SEED_FEDORA: "Fedora / RHEL / Rocky / Alma (kickstart)",
    SEED_DEBIAN: "Debian (script + preseed)",
}
# The installer screens that stay interactive for Ubuntu (autoinstall decides every section that is
# not listed here). Storage and identity must always be in this list.
SEED_UBUNTU_INTERACTIVE = ("locale", "keyboard", "network", "storage", "identity", "timezone")
SEED_PACKAGES_DEB = ("ufw", "auditd", "unattended-upgrades")
SEED_PACKAGES_RPM = ("firewalld", "audit", "dnf-automatic")


def _seed_check_args(target, profile):
    if target not in SEED_TARGETS:
        raise ValueError(f"Unknown seed target: {target!r} (use one of {', '.join(SEED_TARGETS)})")
    if profile == HARDENING_NONE:
        raise ValueError("The 'none' hardening profile has no seed files")
    if profile not in HARDENING_PROFILES:
        raise ValueError(f"Unknown hardening profile: {profile!r}")


def _seed_b64_lines(data):
    """The base64 text of `data` cut into short lines (plain ASCII: no '%', no quotes, no spaces)."""
    import base64
    text = base64.b64encode(data).decode("ascii")
    return [text[i:i + SEED_BASE64_WIDTH] for i in range(0, len(text), SEED_BASE64_WIDTH)]


def _seed_failure_echo(log):
    return ('echo "EPMA hardening failed (exit status $?); the installation goes on. Run it again later '
            'with: sudo bash /root/' + SEED_SCRIPT_NAME + '" >> ' + log)


def _seed_ubuntu_user_data(script):
    log = "/target/var/log/" + SEED_LOG_NAME
    lines = [
        "#cloud-config",
        "# EPMA hardening seed for the Ubuntu installer (autoinstall). Read README.txt first.",
        "# The sections under interactive-sections are asked on screen as usual. No disk layout,",
        "# no account, no password and no key is stored in this file.",
        "autoinstall:",
        "  version: 1",
        "  interactive-sections:",
    ]
    lines += ["    - " + name for name in SEED_UBUNTU_INTERACTIVE]
    lines.append("  packages:")
    lines += ["    - " + name for name in SEED_PACKAGES_DEB]
    lines += [
        "  late-commands:",
        "    - |",
        "      mkdir -p /target/root /target/var/log",
        "      base64 -d > /target/root/" + SEED_SCRIPT_NAME + " <<'EPMA_B64'",
    ]
    lines += ["      " + chunk for chunk in _seed_b64_lines(script)]
    lines += [
        "      EPMA_B64",
        "      chmod 700 /target/root/" + SEED_SCRIPT_NAME,
        "      true",
        "    - |",
        "      if curtin in-target --target=/target -- /bin/bash /root/" + SEED_SCRIPT_NAME
        + " --yes --chroot >> " + log + " 2>&1; then",
        '        echo "EPMA hardening finished" >> ' + log,
        "      else",
        "        " + _seed_failure_echo(log),
        "      fi",
        "      true",
    ]
    return "\n".join(lines) + "\n"


def _seed_ubuntu_meta_data():
    return "instance-id: epma-hardening-seed\nlocal-hostname: epma-ubuntu\n"


def _seed_fedora_ks(script):
    log = "/var/log/" + SEED_LOG_NAME
    lines = [
        "# EPMA hardening seed for Anaconda (kickstart). Read README.txt first.",
        "# This file only adds a few packages and runs the hardening script after the install.",
        "# Language, keyboard, disk, accounts and the summary are still asked on screen.",
        "",
        "%packages --ignoremissing",
    ]
    lines += list(SEED_PACKAGES_RPM)
    lines += [
        "%end",
        "",
        "# Runs inside the new system (the default). A failure here never stops the install.",
        "%post",
        "mkdir -p /root /var/log",
        "base64 -d > /root/" + SEED_SCRIPT_NAME + " <<'EPMA_B64'",
    ]
    lines += _seed_b64_lines(script)
    lines += [
        "EPMA_B64",
        "chmod 700 /root/" + SEED_SCRIPT_NAME,
        "if /bin/bash /root/" + SEED_SCRIPT_NAME + " --yes --chroot >> " + log + " 2>&1; then",
        '  echo "EPMA hardening finished" >> ' + log,
        "else",
        "  " + _seed_failure_echo(log),
        "fi",
        "exit 0",
        "%end",
    ]
    return "\n".join(lines) + "\n"


def _seed_debian_preseed(script):
    log = "/var/log/" + SEED_LOG_NAME
    b64 = "/target/root/harden-linux.b64"
    inner = (
        "base64 -d /root/harden-linux.b64 > /root/" + SEED_SCRIPT_NAME
        + " && chmod 700 /root/" + SEED_SCRIPT_NAME
        + " && rm -f /root/harden-linux.b64"
        + " && /bin/bash /root/" + SEED_SCRIPT_NAME + " --yes --chroot >> " + log + " 2>&1"
        + " && echo EPMA-hardening-finished >> " + log
        + " || echo EPMA-hardening-failed-installation-goes-on >> " + log
    )
    lines = [
        "# EPMA hardening seed for the Debian installer (preseed). Read README.txt first.",
        "# Debian's installer does not find this drive by itself: see README.txt.",
        "# Only non-disk, language-neutral settings are here; disk, accounts and the rest are asked.",
        "d-i pkgsel/include string " + " ".join(SEED_PACKAGES_DEB),
        "d-i pkgsel/update-policy select unattended-upgrades",
        "# The script is carried as base64 text and rebuilt inside the new system. Any failure",
        "# is logged and ignored, so the installation always finishes.",
        "d-i preseed/late_command string \\",
        "    mkdir -p /target/root; \\",
        "    : > " + b64 + "; \\",
    ]
    lines += ["    echo " + chunk + " >> " + b64 + "; \\" for chunk in _seed_b64_lines(script)]
    lines += [
        "    in-target /bin/sh -c '" + inner + "'; \\",
        "    true",
    ]
    return "\n".join(lines) + "\n"


def _seed_readme(target):
    import textwrap
    out = []

    def para(text, bullet="", indent=""):
        first = indent + bullet
        rest = indent + " " * len(bullet)
        out.extend(textwrap.wrap(text, SEED_README_WIDTH, initial_indent=first, subsequent_indent=rest,
                                 break_on_hyphens=False, break_long_words=False))

    def blank():
        out.append("")

    def code(*commands):
        out.extend("    " + c for c in commands)

    def heading(text):
        blank()
        out.append(text.upper())

    out.append("EPMA HARDENING SEED - " + SEED_README_TITLES[target])
    out.append("=" * 60)
    heading("What this drive is")
    para("A small helper drive made by EPMA USB CREATOR. It holds settings files that make a fresh "
         "Linux install start from safer settings (a firewall, audit logging, automatic security "
         "updates and similar). It is not an installer and it does not boot by itself.")
    heading("Use it as a SECOND USB")
    para("Keep your normal installer USB (the one you wrote the Linux ISO to) and plug this drive in "
         "next to it, before you start the installer.")
    heading("What it does NOT do")
    para("Nothing here selects a disk, partitions, formats or erases anything, and nothing creates "
         "an account or sets a password or key. You still choose the disk and create your own "
         "account in the installer. Check each screen before you confirm it.")
    heading("How to use it")
    if target == SEED_UBUNTU:
        para("Meant for the Ubuntu Server live installer (autoinstall). Other Ubuntu flavours "
             "may ignore it. The drive is named CIDATA, which the installer looks for.")
        blank()
        para("Plug in both USB drives and start the computer from the installer USB.", "1. ")
        para("At the GRUB boot menu, press e to edit the boot entry.", "2. ")
        para("On the line that starts with linux, add the word autoinstall before the --- "
             "(leave the rest as it is).", "3. ")
        para("Press F10 (or Ctrl+X) to boot.", "4. ")
        blank()
        para("Without the word autoinstall the installer asks you to confirm before it uses these "
             "files. It still asks for language, keyboard, network, disk, your account and "
             "time zone, as usual.")
        blank()
        para("An internet connection during the install is recommended: the packages ufw, auditd "
             "and unattended-upgrades are fetched then. Some settings finish on the first boot.")
        blank()
        para("A log is kept in the installed system: /var/log/" + SEED_LOG_NAME + ". If the script "
             "fails, the installation still finishes.")
    elif target == SEED_FEDORA:
        para("For Fedora, RHEL, Rocky Linux and AlmaLinux (Anaconda). The drive is named OEMDRV, "
             "which Anaconda detects by itself and reads ks.cfg from.")
        blank()
        para("Plug in both USB drives and start the computer from the installer USB.", "1. ")
        para("Anaconda opens as usual. Choose the language, the install destination (disk), "
             "your root/user accounts and, if asked, the software selection.", "2. ")
        para("Check the summary and start the installation yourself.", "3. ")
        blank()
        para("The kickstart adds the packages firewalld, audit and dnf-automatic and runs the script "
             "inside the new system at the end. A log is kept in /var/log/" + SEED_LOG_NAME
             + ". If the script fails, the installation still finishes.")
    else:
        para("Debian's installer does NOT detect this drive by itself. Pick one of these:")
        blank()
        para("(a) Recommended. Install Debian normally. When it is done and you are logged in, "
             "plug this drive in (a desktop usually mounts it under /media; otherwise mount it "
             "yourself), open a terminal in the drive's folder and run:")
        code("sudo bash harden-linux.sh")
        blank()
        para("(b) Advanced. preseed.cfg is an example you can hand to the Debian installer with "
             "boot parameters such as auto=true priority=critical file=... Read the official "
             "Debian installation guide chapter on preseeding first: how the file is found "
             "depends on your Debian version and on how you boot.")
        blank()
        para("preseed.cfg holds no disk, account or password settings. Its last step rebuilds "
             "the script inside the new system and runs it; if that fails, the install still "
             "finishes and the log is in /var/log/" + SEED_LOG_NAME + ".")
    heading("What the script changes")
    para("harden-linux.sh is a plain text file on this drive: read it before you use it. It prints "
         "every change it makes. Typical changes:")
    for item in ("a firewall that blocks unsolicited incoming connections",
                 "audit logging of security-relevant events",
                 "automatic security updates",
                 "safer kernel and network settings",
                 "conservative SSH server settings that keep your own login working"):
        para(item, "- ", "  ")
    para("Every file it edits is first copied once to a .epma-bak backup, running it twice "
         "changes nothing more, and --dry-run shows what it would do without changing anything.")
    heading("How to undo")
    para("On the installed system run:")
    code("sudo bash harden-linux.sh --undo")
    if target == SEED_DEBIAN:
        para("(with the preseed of option (b), a copy of the script is also kept in /root/"
             + SEED_SCRIPT_NAME + ").")
    else:
        para("(a copy of the script is also kept in /root/" + SEED_SCRIPT_NAME
             + " on the installed system).")
    heading("A note on the word 'hardened'")
    para("These settings are inspired by common security baselines. They are a sensible starting "
         "point, not a compliance claim, certification or guarantee.")
    return "\n".join(out) + "\n"


def hardening_files_seed(target, profile):
    """(FAT32 volume label, {relative_path: bytes}) of the seed drive for `target`.

    target: SEED_UBUNTU, SEED_FEDORA or SEED_DEBIAN. profile: HARDENING_BASELINE (HARDENING_NONE has no
    files and raises ValueError, as do unknown targets and profiles). The files never choose a disk and
    never contain a password, hash or key; harden-linux.sh is exactly linux_hardening_script(profile)."""
    _seed_check_args(target, profile)
    text = linux_hardening_script(profile)  # noqa: F821  (written by the linux-script part of this feature)
    if not isinstance(text, str) or not text.strip():
        raise ValueError("The hardening script is empty")
    script = text.encode("utf-8")
    if target == SEED_UBUNTU:
        texts = {"user-data": _seed_ubuntu_user_data(script), "meta-data": _seed_ubuntu_meta_data()}
    elif target == SEED_FEDORA:
        texts = {"ks.cfg": _seed_fedora_ks(script)}
    else:
        texts = {"preseed.cfg": _seed_debian_preseed(script)}
    files = {name: body.encode("ascii") for name, body in texts.items()}
    files[SEED_SCRIPT_NAME] = script
    files["README.txt"] = _seed_readme(target).encode("ascii")
    return SEED_LABELS[target], files
# ===== end hardening: seed content =====


# ============================================================
# Download
# ============================================================
class _DownloadCanceled(RuntimeError):
    """The user canceled; the partial file is kept so the download can be resumed."""


class _DownloadInterrupted(RuntimeError):
    """The connection kept failing; the partial file is kept so the download can be resumed."""


class _RestartDownload(Exception):  # noqa: N818 - internal control flow, not an error
    """The server's answer cannot extend the partial file; it was discarded, start from zero."""


class DownloadThread(threading.Thread):
    """Downloads one file over HTTPS, resuming and retrying where that is safe.

    * The data goes to `<dest>.part` (owner-only). On cancel or a network error the part
      file is KEPT; the next run resumes it with a Range request. The SHA-256 always
      covers the whole file (the bytes already on disk are hashed first).
    * A resume is only attempted when the first response carried a strong ETag or a
      Last-Modified date (saved beside the part file) and is sent with If-Range, so a file
      that changed on the server is downloaded again from scratch instead of being
      stitched together. A server that ignores Range also leads to a clean restart.
    * Transient errors are retried (DOWNLOAD_MAX_ATTEMPTS, with backoff).
    * A checksum mismatch or an unexpected failure deletes the part file.
    """

    def __init__(self, url, dest_path, progress_cb, done_cb, error_cb, cancel_event,
                 expected_sha256=None, allowed_hosts=None):
        super().__init__(daemon=True)
        self.allowed_hosts = tuple(h.lower() for h in allowed_hosts) if allowed_hosts else None
        self.url = url
        self.dest_path = dest_path
        self.progress_cb = progress_cb
        self.done_cb = done_cb
        self.error_cb = error_cb
        self.cancel_event = cancel_event
        self.expected_sha256 = expected_sha256

    # ---------- partial-file bookkeeping ----------
    def _meta_path(self):
        return self.dest_path + ".part.meta"

    def _read_validator(self):
        try:
            fd = os.open(self._meta_path(), os.O_RDONLY | O_NOFOLLOW)  # never through a symlink
            with os.fdopen(fd, encoding="utf-8") as fh:
                value = json.load(fh).get("validator")
        except (OSError, ValueError, AttributeError):
            return None
        return value if isinstance(value, str) and value else None

    def _write_validator(self, validator):
        try:
            fd = os.open(self._meta_path(), os.O_CREAT | os.O_WRONLY | os.O_TRUNC | O_NOFOLLOW,
                         PRIVATE_FILE_MODE)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"validator": validator}, fh)
        except OSError:
            pass  # without it the next run simply restarts instead of resuming

    def _discard_partial(self, tmp_path):
        _silent_remove(tmp_path, self._meta_path())  # removes a symlink itself, never what it points to

    @staticmethod
    def _strong_validator(headers):
        etag = headers.get("ETag")
        if etag and not etag.startswith("W/"):
            return etag
        return headers.get("Last-Modified") or None

    def _check_cancel(self):
        if self.cancel_event.is_set():
            raise _DownloadCanceled(
                "Download canceled by user. The partial file was kept, so downloading the same "
                "file again to the same location resumes where it stopped.")

    def _hash_part(self, tmp_path, digest, size):
        with os.fdopen(os.open(tmp_path, os.O_RDONLY | O_NOFOLLOW), "rb") as fh:
            if _hash_stream(fh, digest, limit=size, check=self._check_cancel, chunk=CHUNK_SIZE) < size:
                raise OSError("the partial file is shorter than expected")

    def _open(self, offset, validator):
        headers = {"User-Agent": "Mozilla/5.0"}
        if offset:
            headers["Range"] = f"bytes={offset}-"
            headers["If-Range"] = validator
        # noqa S310 below: the scheme is restricted to HTTPS by validate_download_url()
        # and re-checked after redirects; file:// and friends cannot reach here.
        req = urllib.request.Request(self.url, headers=headers)  # noqa: S310
        return urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT_SECONDS)  # noqa: S310

    # ---------- one connection ----------
    def _attempt(self, tmp_path):
        """Download (or resume) once. Returns (bytes, sha256, expected). Raises on any problem."""
        # A symlink where the part/meta file should be is never followed: it is simply dropped.
        if os.path.islink(tmp_path) or os.path.islink(self._meta_path()):
            audit("A symlink was found in place of a partial download file; it was discarded", logging.WARNING)
            self._discard_partial(tmp_path)
        original_untrusted = validate_download_url(self.url)[2]
        offset = os.path.getsize(tmp_path) if os.path.isfile(tmp_path) else 0
        validator = self._read_validator() if offset else None
        if offset and not validator:
            self._discard_partial(tmp_path)  # nothing proves it belongs to this file
            offset = 0
        digest = hashlib.sha256()
        if offset:
            self._hash_part(tmp_path, digest, offset)
        try:
            resp = self._open(offset, validator)
        except urllib.error.HTTPError as e:
            if e.code != 416 or not offset:
                raise
            # Range not satisfiable: the part file does not fit the file on the server.
            self._discard_partial(tmp_path)
            offset, digest = 0, hashlib.sha256()
            resp = self._open(0, None)

        with resp:
            # urlopen follows redirects; make sure we were not downgraded to
            # an unencrypted connection along the way.
            final_url = resp.geturl()
            final_untrusted = False
            if final_url != self.url:
                final_untrusted = validate_download_url(final_url)[2]
                audit(f"Download redirected to host: {urllib.parse.urlparse(final_url).hostname}")
            if self.allowed_hosts is None and final_untrusted and not original_untrusted:
                # The link was on a trusted host, but the server sent us somewhere that is not:
                # that is exactly what the trusted-host list exists to prevent.
                final_host = (urllib.parse.urlparse(final_url).hostname or "").lower()
                audit(f"Download REFUSED: redirected from a trusted host to an untrusted one ({final_host})",
                      logging.WARNING)
                self._discard_partial(tmp_path)
                raise RuntimeError(
                    f"The server redirected the download to an address that is not trusted ({final_host}), "
                    "so it was stopped and what had arrived was discarded.\n\nIf you do trust that server, "
                    "copy the final link and download it directly (you will be asked to confirm the host).")
            if self.allowed_hosts is not None:
                final_host = (urllib.parse.urlparse(final_url).hostname or "").lower()
                if final_host not in self.allowed_hosts:
                    audit(f"Download REFUSED: redirected to unexpected host {final_host}", logging.WARNING)
                    raise RuntimeError(
                        f"The server redirected the download to an unexpected address ({final_host}), "
                        "so it was stopped and what had arrived was discarded.")
            status = getattr(resp, "status", None) or resp.getcode()
            length = int(resp.headers.get("Content-Length", 0) or 0)
            if offset and status == 206:
                m = re.match(r"bytes (\d+)-\d+/(\d+|\*)", resp.headers.get("Content-Range", ""))
                if not m or int(m.group(1)) != offset:
                    self._discard_partial(tmp_path)
                    raise _RestartDownload()
                total = int(m.group(2)) if m.group(2).isdigit() else offset + length
                audit(f"Download resumed at {human_size(offset)}")
            else:
                if offset:  # the server ignored Range (or the file changed): start over cleanly
                    audit("Server did not honour the resume request; restarting the download")
                    offset, digest = 0, hashlib.sha256()
                    self._discard_partial(tmp_path)
                total = length
                fresh_validator = self._strong_validator(resp.headers)
                if fresh_validator:
                    self._write_validator(fresh_validator)
                else:
                    _silent_remove(self._meta_path())  # never leave a stale validator behind

            downloaded = offset
            start = time.time()
            # Create the partial file readable only by its owner.
            flags = os.O_CREAT | os.O_WRONLY | O_NOFOLLOW | (os.O_APPEND if offset else os.O_TRUNC)
            fd = os.open(tmp_path, flags, PRIVATE_FILE_MODE)
            with os.fdopen(fd, "ab" if offset else "wb") as f:
                while True:
                    self._check_cancel()
                    chunk = resp.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    f.write(chunk)
                    digest.update(chunk)
                    downloaded += len(chunk)
                    elapsed = max(time.time() - start, 0.001)
                    self.progress_cb(downloaded, total, (downloaded - offset) / elapsed)
        if total and downloaded < total:
            raise _DownloadInterrupted(
                f"Incomplete download: received {human_size(downloaded)} of {human_size(total)}.")
        if total and downloaded > total:
            self._discard_partial(tmp_path)
            raise RuntimeError("The server sent more data than announced. The file was discarded.")
        sha256 = digest.hexdigest()
        expected = (self.expected_sha256 or "").strip().lower()
        if expected and expected != sha256:
            audit("Downloaded ISO FAILED SHA-256 verification", logging.ERROR)
            self._discard_partial(tmp_path)
            raise RuntimeError(
                "SHA-256 verification FAILED — the downloaded file is NOT the one you "
                "expected and was discarded.\n\n"
                f"Expected: {expected}\nReceived: {sha256}\n\n"
                "Do not use this file. Download it again from the official Microsoft page."
            )
        os.replace(tmp_path, self.dest_path)
        _silent_remove(self._meta_path())
        return downloaded, sha256, expected

    def _local_write_message(self, err):
        """User-facing text for a local write error that must not be retried."""
        folder = os.path.dirname(os.path.abspath(self.dest_path))
        if err.errno in (errno.ENOSPC, getattr(errno, "EDQUOT", None)):
            return (f"There is not enough free space in {folder}. The download was stopped and the "
                    "partial file was deleted to free the space. Free up space or choose another "
                    "folder or drive, then download again.")
        if err.errno == errno.EROFS:
            return (f"{folder} is read-only, so the file cannot be saved there. The download was "
                    "stopped; choose another folder.")
        return (f"The program is not allowed to write in {folder}. The download was stopped; "
                "choose a folder you can write to.")

    # ---------- retry loop ----------
    def run(self):
        tmp_path = self.dest_path + ".part"
        try:
            # The URL was validated before this thread started; re-check here so
            # the guarantee holds even if this class is reused elsewhere.
            validate_download_url(self.url)
            attempt = 0
            restarts = 0
            while True:
                attempt += 1
                try:
                    downloaded, sha256, expected = self._attempt(tmp_path)
                    break
                except _RestartDownload:
                    restarts += 1
                    if restarts > 2:
                        raise RuntimeError("The server keeps answering the resume request with "
                                           "unusable data. Try the download again.") from None
                    attempt -= 1
                    continue
                except urllib.error.HTTPError as e:
                    if e.code < 500 and e.code not in (408, 429):
                        raise _DownloadInterrupted(
                            f"The server refused the download (HTTP {e.code}). If the link has "
                            "expired, copy a fresh one from the Microsoft page; the partial file "
                            "is kept and will be resumed if it is the same file.") from None
                    problem = f"HTTP {e.code}"
                except (urllib.error.URLError, OSError, http.client.HTTPException,
                        _DownloadInterrupted) as e:
                    if not isinstance(e, urllib.error.URLError) and getattr(e, "errno", None) in DOWNLOAD_FATAL_ERRNOS:
                        # A problem with the destination, not the network: retrying cannot help.
                        raise RuntimeError(self._local_write_message(e)) from None
                    if isinstance(e, urllib.error.URLError) and e.reason is not None:
                        problem = str(e.reason)
                    else:
                        problem = str(e) or type(e).__name__
                if attempt >= DOWNLOAD_MAX_ATTEMPTS:
                    raise _DownloadInterrupted(
                        f"The download was interrupted ({problem}) and could not be continued after "
                        f"{attempt} attempts. The partial file was kept; start the download again "
                        "to resume it.")
                delay = DOWNLOAD_BACKOFF_SECONDS[min(attempt - 1, len(DOWNLOAD_BACKOFF_SECONDS) - 1)]
                audit(f"Download attempt {attempt} failed; retrying in {delay}s")
                if self.cancel_event.wait(delay):
                    self._check_cancel()
            audit(f"ISO downloaded ({human_size(downloaded)}) sha256={sha256}"
                  + (" [verified against expected value]" if expected else " [not verified]"))
            self.done_cb(self.dest_path, sha256, bool(expected))
        except (_DownloadCanceled, _DownloadInterrupted) as e:
            self.error_cb(str(e))  # the partial file stays on disk for a later resume
        except Exception as e:
            self._discard_partial(tmp_path)
            self.error_cb(str(e))


# ============================================================
# GUI
# ============================================================
def set_macos_app_name(name):
    """Make the macOS menu bar and Dock say `name` instead of "Python".

    The name comes from the running bundle's Info.plist (CFBundleName), which for a
    script is Python.app's. Overriding it in memory before the first window is created
    needs no extra packages (plain ctypes into the Objective-C runtime) and changes
    nothing on disk. Purely cosmetic, so any failure is ignored.
    """
    if not IS_MAC:
        return
    try:
        import ctypes
        import ctypes.util

        objc = ctypes.cdll.LoadLibrary(ctypes.util.find_library("objc"))
        objc.objc_getClass.restype = ctypes.c_void_p
        objc.objc_getClass.argtypes = [ctypes.c_char_p]
        objc.sel_registerName.restype = ctypes.c_void_p
        objc.sel_registerName.argtypes = [ctypes.c_char_p]

        def send(obj, selector, *args):
            fn = objc.objc_msgSend
            fn.restype = ctypes.c_void_p
            fn.argtypes = [ctypes.c_void_p, ctypes.c_void_p] + [ctypes.c_void_p] * len(args)
            return fn(obj, objc.sel_registerName(selector.encode()), *args)

        def nsstring(text):
            return send(objc.objc_getClass(b"NSString"), "stringWithUTF8String:", text.encode())

        bundle = send(objc.objc_getClass(b"NSBundle"), "mainBundle")
        info = send(bundle, "infoDictionary")
        if info:
            for key in ("CFBundleName", "CFBundleDisplayName"):
                send(info, "setObject:forKey:", nsstring(name), nsstring(key))
        send(send(objc.objc_getClass(b"NSProcessInfo"), "processInfo"), "setProcessName:", nsstring(name))
    except Exception:  # noqa: S110 - cosmetic only; never block the app over a label
        pass


def _image_label(mode, other):
    """The window's name for what `mode` writes; `other` (already translated) names a Linux or other ISO."""
    return {MODE_WINDOWS: _("Windows 11"), MODE_CHROMEOS: _("ChromeOS Flex")}.get(mode, other)


_TkBase = tk.Tk if tk else object  # lets the module import (engine, CLI) without Tk


# ============================================================
# Built-in documentation (Help menu)
#
# The text lives here, as data, so tests can check it against the code: every command
# line command, exit code, environment variable and risk threshold it mentions comes
# from the same constants the program uses. The documentation is in English only.
# ============================================================
def help_sections():
    """Return the documentation as a list of (title, body). Lines starting with "## " are
    sub-headings and lines starting with "• " are bullets (see App._render_help)."""
    audit_path = audit_log_path()
    large_gb = LARGE_DISK_BYTES // 1024 ** 3
    used_gb = SUBSTANTIAL_USED_BYTES // 1024 ** 3
    hosts = ", ".join(DEFAULT_TRUSTED_ISO_HOSTS)
    critical_mounts = ", ".join(CRITICAL_MOUNTPOINTS)
    retries = DOWNLOAD_MAX_ATTEMPTS - 1
    audit_mb = f"{AUDIT_LOG_MAX_BYTES / 1_000_000:g}"
    return [
        ("Overview", f"""EPMA USB CREATOR {__version__} writes a bootable USB drive from an ISO image on macOS and Linux.

## Four image types (the four cards)
• Google Chrome — ChromeOS Flex, Google's free ChromeOS for PCs and Macs. The disk image is written byte for byte, like a Linux ISO. The program can download Google's official image for you.
• Windows 11 — erases the drive, creates a GPT partition table with one FAT32 partition (label {VOL_NAME}) and copies the files of the ISO. The result boots on UEFI computers. Windows' install.wim / install.esd is usually larger than the 4 GB FAT32 limit, so it is split into .swm parts with wimlib-imagex.
• Linux and Other ISO — both write the ISO byte for byte to the whole drive (like dd). Use Linux for Ubuntu, Debian, Fedora, Mint, Arch and other "hybrid" images, and Other ISO for any other bootable image. An ISO that cannot boot from a USB drive is refused before anything is erased.

## What always happens
• Only drives attached over USB are offered. The system disk and internal disks are never listed.
• Everything on the selected drive is erased. Nothing is kept.
• After writing, the drive is read back and compared with the ISO. Only a drive that passes is ejected.

## The window, from top to bottom
• The top row shows the program name and version, a status chip for the tools it needs ("Ready" in green, "Missing tools" in amber with "Install missing dependencies" next to it) and "Help", which opens this documentation (F1 does the same).
• The page has three numbered steps. 1 Image type: four equal cards choose the type of image (Google Chrome (ChromeOS Flex), Windows 11, Linux and Other ISO).
• 2 Image: the panel under the cards changes with the card and shows where to get that kind of image. "Select existing ISO file..." picks the image you already have; the chosen file is shown with its name, folder, size and the type the program recognised (Windows 11, Linux, ChromeOS Flex or Unknown), with an optional SHA-256 check behind a link.
• 3 USB drive: the list of USB drives (read when the program starts and whenever you return to the window) and "Refresh USB drives list".
• "Create Bootable USB Drive" (the blue button), the one "Cancel" button for whatever is running (a download, an extraction or the write), its progress bar, and "Show details", which opens the log.
• Results appear under the Create button instead of in pop-up windows: a red box for a failed download, extraction, drive listing or tool installation (with "Try again" where it makes sense, and "Dismiss"), and a green box when the drive was written, verified and ejected, with "Make another" to start over. A failed or canceled write also keeps its pop-up, because the state of the drive matters.
• Help menu: this documentation, the audit log folder, the project page and About."""),

        ("Quick start: Windows 11", """## 1. Get the ISO (card "Windows 11")
• Click "Open Microsoft's official page". Under "Download Windows 11 Disk Image (ISO)" choose "Windows 11 (multi-edition ISO)", pick the language and confirm.
• Right-click the blue 64-bit button and choose "Copy Link Address". Do not click it to download in the browser.
• Paste the link into "Direct ISO link". If Microsoft shows a SHA-256 checksum, paste it into "Expected SHA-256" so the download is checked automatically.
• Click "Download ISO" and choose where to save it.
• Already have the ISO? Click "Select existing ISO file..." instead.

## 2. Write the drive
• The chip at the top right must say "Ready". If it says "Missing tools", click "Install missing dependencies" next to it.
• Plug in the USB drive (8 GB or more) and click "Refresh USB drives list". Select your drive.
• The "Windows 11" card is chosen for you when the ISO is a Windows installer.
• Click "Create Bootable USB Drive", read the confirmation (model, size, volumes) and confirm.
• Wait for the progress bar. When the log says the drive was verified and ejected, unplug it.

## 3. Boot from it
• The computer must start in UEFI mode (not Legacy/CSM). The drive is UEFI + GPT only.
• This tool does not bypass the Windows 11 requirements (TPM 2.0, Secure Boot)."""),

        ("Quick start: Linux and other ISOs", """## 1. Choose the ISO (card "Linux" or "Other ISO")
• Download the ISO from your distribution's website, then click "Select existing ISO file...". "Linux" and "Other ISO" write the image the same way; "Other ISO" is for any other bootable image.
• Optional but recommended: click "Verify the selected ISO (SHA-256)" under the file name, paste the checksum published by the distribution (or the whole line from its SHA256SUMS file) and click "Calculate SHA-256". Continue only on MATCH.

## 2. Write the drive
• The "Linux" card is chosen for you when the contents are a bootable ISO that is not a Windows installer.
• Plug in the drive, click "Refresh USB drives list", select it, and click "Create Bootable USB Drive".
• Confirm. The administrator password is requested before the drive is touched.
• The ISO is written, then read back and compared, then the drive is ejected.

## 3. On macOS: the drive will not appear in Finder
• macOS cannot read Linux (ISO 9660 / ext) images, so Finder shows nothing and macOS may say "The disk you attached was not readable".
• Click "Ignore". Never click "Initialize" — it would erase what was just written.
• This is normal. The content was already verified byte for byte."""),

        ("ChromeOS Flex", """## What it is
• ChromeOS Flex is Google's free version of ChromeOS for PCs and Macs. It is the official way to run ChromeOS on a computer you already own: Google does not publish regular ChromeOS for ordinary computers, so this program does not offer it.
• ChromeOS Flex is provided by Google under Google's own terms. This program only downloads Google's official image and writes it to your drive.

## What you need
• A USB drive of 16 GB or larger. Everything on it is erased. Google notes that some drives (certain Sandisk models, for example) may not work as installers.
• On the computer you will install it on: an Intel or AMD 64-bit processor, 4 GB of RAM, 16 GB of internal storage, and the ability to boot from USB. Google only guarantees ChromeOS Flex on certified models; other computers may work without guarantees.
• Google's guide: @GUIDE@
• Google's requirements: @REQUIREMENTS@

## Steps
• Choose the "Google Chrome" card and click "Download ChromeOS Flex from Google". Choose where to save the file. The download is resumable. The ZIP is extracted automatically; the ZIP that this program downloaded is deleted afterwards (a ZIP you selected yourself is kept).
• Already have latest.bin.zip, or the .bin inside it? Use "Select existing image..." (a ZIP is extracted for you).
• Then plug in the USB drive, click "Refresh USB drives list", select the drive and click "Create Bootable USB Drive". The confirmation, the administrator password, the progress bar and the Cancel button work as for any other image.
• The image is written, read back and compared with the file, and the drive is ejected.
• Boot the computer from the USB drive and follow Google's guide for the next steps.

## Notes
• The image is about 9.5 GB once extracted and the download about 1.4 GB: keep roughly 12 GB free on the computer while preparing it (a warning appears when there is less). The drive must be at least as large as the image, otherwise nothing is touched; a drive below 16 GB shows a warning first.
• The official address redirects to a versioned file on dl.google.com. A redirect to any other server is refused and what arrived is discarded.
• The administrator password is asked on macOS as well, because the whole drive is written directly.
• On macOS the finished drive does not appear in Finder, as with Linux images (see "Quick start: Linux and other ISOs").
• The download link is only accepted when it is Google's official address (@URL@).
• Command line: fetch-chromeos downloads and extracts the image; write --mode chromeos writes it.""".replace(
            "@GUIDE@", CHROMEOS_FLEX_GUIDE_URL).replace("@REQUIREMENTS@", CHROMEOS_FLEX_REQUIREMENTS_URL).replace(
            "@URL@", CHROMEOS_FLEX_URL)),

        ("Getting the image", """## Windows 11: direct ISO link
• Only https:// links are accepted: an unencrypted link could be altered on the way.
• Links to servers outside Microsoft's known download hosts (@HOSTS@) show a warning. Download Windows only from Microsoft.

## Expected SHA-256 (optional)
• 64 hexadecimal characters. If the downloaded file does not match, it is discarded.

## Download controls
• The bar shows percentage, speed and time left.
• "Cancel" keeps the partial file. Downloading to the same file again resumes where it stopped when the server supports it, and temporary network errors are retried automatically (up to @RETRIES@ retries, @ATTEMPTS@ attempts in all).
• A file that fails the checksum is deleted.

## Select existing ISO file...
• Picks an image you already have (.iso, .bin or .img; a ChromeOS Flex .zip is extracted for you). The card (Windows, Linux or Google Chrome) is chosen from the contents of the image, not from its name. You can still click another card.
• If the file clearly does not match the card (for example a Linux ISO under "Windows 11"), the program asks before erasing anything; a file that is not a ChromeOS Flex image under "Google Chrome" is refused.

## Verify the selected ISO (SHA-256)
• A link under the file name, shown once an image is selected; click it to open the panel. Paste the expected hash, or the whole line from a SHA256SUMS file (the file name picks the right line), and click "Calculate SHA-256".
• MATCH (green): the file is identical to the published one. MISMATCH (red): do not use it.
• With no expected value it only shows the hash so you can compare it yourself.""".replace("@HOSTS@", hosts).replace(
            "@RETRIES@", str(retries)).replace("@ATTEMPTS@", str(DOWNLOAD_MAX_ATTEMPTS))),

        ("The drive and the Create button", f"""## The cards
• Google Chrome (ChromeOS Flex, disk image written directly), Windows 11 (GPT + FAT32, files copied), Linux and Other ISO (the ISO is written directly). The card is chosen from the image contents when you select a file; you can change it.

## Dependencies
• Windows mode needs wimlib (macOS: brew install wimlib). On Linux it also needs parted, mkfs.vfat (dosfstools), wipefs, partprobe, rsync and wimlib-imagex.
• The Google Chrome, Linux and Other ISO cards need nothing extra.
• The dependencies are checked before anything is erased. When one is missing, the Create button stays disabled and a hint says what to install.
• "Install missing dependencies" uses your package manager (apt-get, dnf, yum, pacman, zypper, apk or Homebrew) and asks for the administrator password on Linux.

## The drive list
• Each drive is a row with a USB badge, its model, size, device and volumes, for example "SanDisk Ultra — 58.6 GB — /dev/disk4 · 2 volumes (Untitled, EFI)". The chosen row is highlighted; click a row, or use the Up and Down arrow keys, to choose another. While the drives are being read, two grey rows stand in; when there are none, the list says "No USB drive found". The list is read when the program starts and whenever you return to the window; click "Refresh USB drives list" if a drive you just plugged in is missing. While "Create Bootable USB Drive" is disabled, a line under it says what is missing.

## The confirmation
• The dialog shows model, size and every volume with its used space, so you can recognise the drive.
• Drives that do not look like a spare stick need you to type their identifier (for example disk4). That applies to drives larger than {large_gb} GB, with {used_gb} GB or more in use, with a name that suggests backups or personal data, that look like an external hard disk or SSD, with {MANY_VOLUMES} or more volumes, or whose contents could not be read.

## Administrator password
• Needed on Linux, and on macOS for the direct-write cards (Google Chrome, Linux and Other ISO). It is asked right after you confirm and checked before the drive is touched: a wrong or canceled password changes nothing.
• It is checked once. Normally it is then dropped and sudo's own credential timestamp carries the operation; only if this computer does not keep that timestamp does the password stay in memory, until the operation ends. It is used only to run local disk commands and is never logged, written to disk or sent anywhere.

## Progress, Cancel and the log
• The bar shows the percentage, speed and time left while writing and while verifying. Some steps (comparing files) show a moving bar without a percentage.
• "Cancel" stops the running operation (a download, an extraction or the write). If it is pressed during the write before the drive is touched, the log says so and nothing changed; otherwise the drive is left unusable until it is written again.
• Closing the window while a drive is being written asks you first, because stopping halfway leaves the drive unusable.
• "Show details" opens a box with every command that runs; it opens by itself when a write fails. Keep its text if you need to report a problem."""),

        ("Safety", f"""## What protects you
• Only USB drives are listed. If the program cannot confirm that a disk is external and safe, it hides the disk instead of offering it. On Linux, disks that hold the system ({critical_mounts}, or anything under /boot) are never listed.
• You see the model, size and contents before erasing. Large or data-filled drives need the identifier typed.
• Right before erasing, the drive is looked up again and must still be the same device (size, serial number, model). If it was swapped, the operation stops.
• A privileged command that fails is never run a second time on its own.
• The result is verified before the drive is ejected.
• The administrator password is checked up front, before the drive is touched. Normally it is then dropped and sudo's own credential timestamp is used; only if this computer does not keep that timestamp does the password stay in memory, until the operation ends. It is never logged or written to disk.
• Missing dependencies are detected before anything is erased, and a Windows ISO that is larger than the drive is refused up front.
• Closing the window during a write asks for confirmation first.

## What it cannot do for you
• It cannot tell which of your USB drives you meant. Read the model, size and volumes in the confirmation every time.
• It erases the whole drive, including partitions macOS or Linux may not show.
• A drive that was canceled or interrupted mid-write is not usable until written again."""),

        ("Verification and eject", """## Verification
• Linux and ChromeOS Flex modes: the whole image is read back from the drive and compared byte for byte with the file.
• Windows mode: the drive is unmounted and mounted again so it is read from the device, then every file is compared by checksum with the ISO. A split install image is also checked with wimlib-imagex verify.
• Verification cannot be skipped. If anything differs, the drive is NOT ejected, the message says so, and the drive must not be used. Write it again; if it keeps failing, try another USB port or another drive.

## Eject
• After a successful verification the drive is ejected. If it is busy, the program unmounts it by force and tries again.
• The green box under the Create button says the drive was verified and ejected. If the eject failed the box is amber and tells you to eject the drive from Finder or your file manager before unplugging.
• The log ends with "Drive ejected — you can unplug it now." When it says the drive could not be ejected, eject it from Finder or your file manager before unplugging.
• Always wait for that message before pulling the drive out."""),

        ("Command line", f"""The same engine works without the window. Run the program with a command (no Tkinter needed):

## Commands
• list [--json] — USB drives that can be used.
• detect ISO [--json] — prints windows, linux, chromeos or unknown.
• fetch-chromeos [--dest DIR] [--keep-zip] [--json] — downloads ChromeOS Flex from Google and extracts the disk image. It does not write a drive.
• sha256 ISO [--expected HASH] [--json] — checksum of an ISO; exits {EXIT_VERIFY_FAILED} when it differs from --expected.
• write --iso ISO --disk DISK [--mode auto|windows|linux|chromeos] [--dry-run] [--yes] [--no-eject] [--json] [-v] — write a drive.
• gui, or no command — open this window.
• --version, --help — program version and the full help.

## write
• --dry-run shows the plan and changes nothing. It is the safest way to try a command.
• Without --yes you are asked to type the disk identifier. When there is no terminal, --yes is required.
• Verification is always performed. There is no option to skip it.

## Exit codes
• {EXIT_OK} success
• {EXIT_ERROR} generic error
• {EXIT_USAGE} wrong usage or missing confirmation
• {EXIT_VERIFY_FAILED} verification failed or checksum mismatch
• {EXIT_EJECT_FAILED} written and verified, but the drive could not be ejected
• {EXIT_INTERRUPTED} interrupted (Ctrl-C)

Data goes to stdout; messages, progress and errors go to stderr. NO_COLOR is honored."""),

        ("Troubleshooting", """## No drive appears in the list
• Only USB drives are listed (SD cards, internal disks and the system disk never are). Check the connection and click "Refresh USB drives list".

## The drive does not show in Finder after a Linux ISO (macOS)
• Expected. See "Quick start: Linux and other ISOs". Click Ignore, never Initialize.

## "Verification FAILED"
• The drive does not match the ISO. It was not ejected and must not be used. Write it again; try another port or drive if it repeats.

## "Aborted for safety: /dev/... is no longer listed as an external drive"
• The drive changed between choosing it and writing. Refresh the list and select it again.

## "Could not find sources/install.wim or sources/install.esd on the ISO"
• The ISO is not a Windows installation image. Download the official multi-edition ISO from Microsoft, or use the Linux mode for a Linux ISO.

## "This ISO is not a bootable hybrid image"
• Linux mode needs a hybrid image. Current Ubuntu, Debian, Fedora, Mint and Arch ISOs are. A Windows ISO needs the Windows mode.

## "This is the ZIP archive, not the disk image inside it"
• You selected latest.bin.zip in a place that expects the .bin. With the "Google Chrome" card (or "Select existing ISO file...") choose the ZIP and the program extracts the .bin for you.

## "This file is not a bootable disk image"
• ChromeOS Flex mode needs the .bin from Google's official latest.bin.zip. Download it again with the "Google Chrome" card.

## "The image is larger than the drive"
• Choose a bigger USB drive. Nothing was changed. For ChromeOS Flex Google asks for 16 GB or larger.

## The ChromeOS Flex download fails or is very slow
• Cancel and start it again: the partial file is kept and the download resumes. Google's server is the only source this program accepts for it.

## "wimlib-imagex not found"
• Install wimlib (macOS: brew install wimlib) or use "Install missing dependencies".

## "Neither 'sudo' nor 'pkexec' was found"
• Install sudo, or run the program as root.

## "Tkinter is not available for this Python installation"
• Install Tk for your Python (macOS: brew install python-tk@<version matching your Python>, for example python-tk@3.15; Debian/Ubuntu: sudo apt install python3-tk).

## The computer does not boot from the drive
• Windows drives are UEFI + GPT only: choose the UEFI entry in the boot menu and make sure Legacy/CSM is off.

## A cancel or crash during writing
• The drive is unusable until it is written again. Nothing else is affected."""),

        ("Files, logs and settings", f"""## Audit log
• Every destructive operation is recorded with its start, result and the SHA-256 of the ISO, together with security events such as hidden disks and rejected identifiers. Passwords are never logged.
• Location: {audit_path}
• It rotates at {audit_mb} MB ({AUDIT_LOG_BACKUPS} older files are kept) and is readable only by you. "Help > Open the audit log folder" opens it.

## Environment variables (all optional)
• {ENV_AUDIT_LOG} — another path for the audit log.
• {ENV_DISABLE_AUDIT_LOG} — set to 1 to turn the audit log off.
• {ENV_TRUSTED_HOSTS} — comma-separated list of trusted download hosts (replaces the Microsoft list).
• {ENV_ALLOW_ANY_HOST} — set to 1 to silence the unrecognised-server warning. This lowers security.
• {ENV_EXPECTED_SHA256} — pre-fills the expected checksum field of the Windows 11 card.
• {ENV_LANG} — set to pt for a Brazilian Portuguese window. The default is US English whatever the system language.

## Privacy
• No telemetry, no accounts, no data leaves your computer. The only network traffic is the ISO or ChromeOS Flex download you ask for."""),

        ("About", f"""EPMA USB CREATOR {__version__}
{APP_TAGLINE}, on macOS and Linux.

Platform: {platform_display_name()}
License: GNU General Public License v3 or later
Copyright (C) 2026 EPMA
Project: {PROJECT_URL}

The program has no third-party dependencies: it uses only the Python standard library."""),
    ]


_CanvasBase = tk.Canvas if tk else object  # the module must stay importable without Tkinter


_LabelBase = ttk.Label if ttk else object


class _LazyLabel(_LabelBase):
    """A label that occupies no space while its text is empty (it is packed when it gets text).

    `before=` / `after=` (a widget, or a function returning one) say where in the parent the label
    goes when it is packed. Without them a label that appears later would land at the END of the page,
    below everything else. A target that is not packed at that moment is ignored.
    """

    def __init__(self, parent, **pack_options):
        super().__init__(parent, text="", justify="left", wraplength=680)
        self._pack_options = pack_options

    def _pack_now(self):
        options = dict(self._pack_options)
        targets = {}
        for key in ("before", "after"):
            target = options.pop(key, None)
            if callable(target):
                target = target()
            if target is not None and str(target.winfo_manager()) == "pack":
                targets[key] = target
        if "before" in targets:  # Tk takes one anchor: "just above X" wins over "just below Y"
            options["before"] = targets["before"]
        elif "after" in targets:
            options["after"] = targets["after"]
        self.pack(**options)

    def config(self, cnf=None, **kw):
        result = super().config(cnf, **kw)
        if "text" in kw:
            if kw["text"]:
                if not self.winfo_manager():
                    self._pack_now()
            else:
                self.pack_forget()
        return result

    configure = config


class OptionCard(_CanvasBase):
    """A square, clickable choice: one of the four image types at the top of the window.

    Drawn on a canvas so it looks the same on macOS and Linux and follows the light/dark
    theme. It works from the keyboard too (Tab to focus, Space/Return to choose). The symbols
    are plain shapes on purpose: no brand logos.
    """

    WIDTH, HEIGHT = 156, 124   # WIDTH is the width asked for; the grid cell it sits in decides the real one
    ACCENT = "#0a84ff"

    def __init__(self, parent, key, title, subtitle, command):
        style = ttk.Style(parent)
        self._bg = style.lookup("TFrame", "background") or style.lookup("TLabel", "background") or "#ececec"
        self._fg = style.lookup("TLabel", "foreground") or "#000000"
        super().__init__(parent, width=self.WIDTH, height=self.HEIGHT, bg=self._bg, highlightthickness=0,
                         takefocus=True, cursor="hand2")
        self.key, self._title, self._subtitle, self._command = key, title, subtitle, command
        self._selected = False
        self._hover = False
        self._enabled = True
        self._cw = self.WIDTH  # the width actually allocated (the card is redrawn when it changes)
        base = tkfont.nametofont("TkDefaultFont")
        self._title_font = (base.actual("family"), base.actual("size") + 2, "bold")
        self._sub_font = (base.actual("family"), max(base.actual("size") - 2, 8))
        self.bind("<Button-1>", lambda _e: self._choose())
        self.bind("<Return>", lambda _e: self._choose())
        self.bind("<space>", lambda _e: self._choose())
        self.bind("<Enter>", lambda _e: self._set_hover(True))
        self.bind("<Leave>", lambda _e: self._set_hover(False))
        self.bind("<FocusIn>", lambda _e: self._draw())
        self.bind("<FocusOut>", lambda _e: self._draw())
        self.bind("<Configure>", self._on_resize)
        self._draw()

    def _on_resize(self, event):
        if event.width > 1 and event.width != self._cw:
            self._cw = event.width
            self._draw()

    def _choose(self):
        if not self._enabled:
            return
        self.focus_set()
        self._command(self.key)

    def _set_hover(self, value):
        self._hover = value and self._enabled
        self._draw()

    def set_enabled(self, enabled):
        """A disabled card ignores clicks and the keyboard (the window locks them during a write)."""
        self._enabled = bool(enabled)
        self._hover = self._hover and self._enabled
        self.configure(cursor="hand2" if self._enabled else "arrow", takefocus=self._enabled)
        self._draw()

    def _has_focus(self):
        """True when this card has the keyboard focus. Never raises.

        Tk's `focus_get` can raise KeyError ('!combobox', 'popdown') while the focus sits in the
        pop-down list of a ttk Combobox, because Python cannot map that internal window to a widget.
        """
        try:
            return self.focus_get() is self
        except (KeyError, tk.TclError):
            try:
                return str(self.tk.call("focus")) == str(self)
            except tk.TclError:
                return False

    def set_selected(self, selected):
        self._selected = bool(selected)
        self._draw()

    def _rounded(self, x1, y1, x2, y2, r, **kw):
        points = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
                  x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
        return self.create_polygon(points, smooth=True, **kw)

    def _draw(self):
        focused = self._has_focus()  # before anything is erased: a failure here must not leave a blank card
        self.delete("all")
        color = self.ACCENT if self._selected else ("#a0a0a8" if (self._hover or focused) else "#6e6e73")
        width = 3 if self._selected else (2 if focused else 1)
        text_color = self._fg
        if not self._enabled:  # locked while a write runs: the chosen card stays visible, the rest greys out
            text_color = "#8e8e93"
            if not self._selected:
                color = "#8e8e93"
        self._rounded(3, 3, self._cw - 3, self.HEIGHT - 3, 14, outline=color, fill="", width=width)
        cx, cy = self._cw / 2, 40
        glyph = self.ACCENT if self._selected else text_color
        if self.key == CARD_WINDOWS:            # four tiles
            for ox, oy in ((-17, -17), (2, -17), (-17, 2), (2, 2)):
                self.create_rectangle(cx + ox, cy + oy, cx + ox + 15, cy + oy + 15, fill=glyph, outline=glyph)
        elif self.key == CARD_CHROME:           # a ring with a dot
            self.create_oval(cx - 20, cy - 20, cx + 20, cy + 20, outline=glyph, width=3)
            self.create_oval(cx - 8, cy - 8, cx + 8, cy + 8, fill=glyph, outline=glyph)
        elif self.key == CARD_LINUX:            # a terminal prompt
            self.create_text(cx, cy, text=">_", fill=glyph, font=("Menlo", 26, "bold"))
        else:                                   # a disc
            self.create_oval(cx - 20, cy - 20, cx + 20, cy + 20, outline=glyph, width=3)
            self.create_oval(cx - 6, cy - 6, cx + 6, cy + 6, outline=glyph, width=3)
        self.create_text(cx, 82, text=self._title, fill=text_color, font=self._title_font)
        self.create_text(cx, 103, text=self._subtitle, fill="#8e8e93", font=self._sub_font)


class AccentButton(_CanvasBase):
    """The one primary action of the window ("Create Bootable USB Drive"): a filled, rounded button in the
    accent colour. Native macOS buttons cannot be coloured, so it is drawn on a canvas (like OptionCard).

    It answers `config(state=...)`, `config(text=...)`, `cget("state")` and `invoke()` like a button, and
    works from the keyboard (Tab to focus, Space/Return to press).
    """

    HEIGHT = 46
    ACCENT, ACCENT_HOVER = "#0a84ff", "#409cff"
    _rounded = OptionCard._rounded

    def __init__(self, parent, text, command, state="normal"):
        style = ttk.Style(parent)
        bg = style.lookup("TFrame", "background") or style.lookup("TLabel", "background") or "#ececec"
        base = tkfont.nametofont("TkDefaultFont")
        font = tkfont.Font(family=base.actual("family"), size=base.actual("size") + 3, weight="bold")
        super().__init__(parent, width=max(260, font.measure(text) + 64), height=self.HEIGHT, bg=bg,
                         highlightthickness=0, takefocus=True)
        self._font, self._text, self._command = font, text, command
        self._state = "disabled" if state == "disabled" else "normal"
        self._hover = False
        r, g, b = self.winfo_rgb(bg)
        self._dark = (r + g + b) / 3 < 32768  # follows the light/dark theme through the window background
        self.bind("<Button-1>", lambda _e: self.invoke())
        self.bind("<Return>", lambda _e: self.invoke())
        self.bind("<space>", lambda _e: self.invoke())
        self.bind("<Enter>", lambda _e: self._set_hover(True))
        self.bind("<Leave>", lambda _e: self._set_hover(False))
        self.bind("<FocusIn>", lambda _e: self._draw())
        self.bind("<FocusOut>", lambda _e: self._draw())
        self._apply_state()

    def _apply_state(self):
        super().configure(cursor="hand2" if self._state == "normal" else "arrow", takefocus=self._state == "normal")
        self._draw()

    def _set_hover(self, value):
        self._hover = value and self._state == "normal"
        self._draw()

    def invoke(self):
        """Press the button (does nothing while it is disabled)."""
        if self._state != "normal":
            return None
        self.focus_set()
        return self._command()

    def cget(self, key):
        if key == "state":
            return self._state
        if key == "text":
            return self._text
        return super().cget(key)

    def configure(self, cnf=None, **kw):
        if "state" in kw:
            self._state = "disabled" if kw.pop("state") == "disabled" else "normal"
            self._hover = self._hover and self._state == "normal"
        if "text" in kw:
            self._text = kw.pop("text")
        result = super().configure(cnf, **kw) if (cnf or kw) else None
        self._apply_state()
        return result

    config = configure

    def _draw(self):
        self.delete("all")
        w, h = int(self.cget("width")), self.HEIGHT
        enabled = self._state == "normal"
        if enabled:
            fill, text = (self.ACCENT_HOVER if self._hover else self.ACCENT), "#ffffff"
        else:
            fill, text = ("#3a3a3c" if self._dark else "#d8d8dc"), "#8e8e93"
        self._rounded(2, 2, w - 2, h - 2, 10, fill=fill, outline=fill)
        try:
            focused = enabled and self.focus_get() is self
        except (KeyError, tk.TclError):
            focused = False
        if focused:  # keyboard focus ring
            self._rounded(2, 2, w - 2, h - 2, 10, fill="", outline="#ffffff" if self._dark else "#003d99", width=2)
        self.create_text(w / 2, h / 2, text=self._text, fill=text, font=self._font)


class _Disclosure(_LabelBase):
    """A link-like row that opens and closes a section: "▸ Show details" / "▾ Hide details".

    `on_toggle(is_open)` runs when the state changes. Works from the keyboard (Tab, Space/Return).
    """

    def __init__(self, parent, closed_text, open_text, on_toggle):
        super().__init__(parent, text="", foreground="#4da3ff", cursor="hand2", takefocus=True)
        self._texts = (closed_text, open_text)
        self._on_toggle = on_toggle
        self.is_open = False
        self._show()
        self.bind("<Button-1>", lambda _e: self.toggle())
        self.bind("<Return>", lambda _e: self.toggle())
        self.bind("<space>", lambda _e: self.toggle())

    def _show(self):
        self.config(text=("▾ " if self.is_open else "▸ ") + self._texts[1 if self.is_open else 0])

    def set_open(self, value):
        value = bool(value)
        if value != self.is_open:
            self.is_open = value
            self._show()
            self._on_toggle(value)

    def toggle(self):
        self.set_open(not self.is_open)


def drive_row_texts(disk):
    """The three texts of one row of the drive list: (name, size, detail).

    The name is the model (or the device path when the model is unknown), the size is human readable
    and the detail is the device path plus a summary of the volumes on the drive. A record without
    "model", "size" or "volumes" (an older one) still gives sensible text.
    """
    dev = "/dev/" + str(disk.get("id", ""))
    model = str(disk.get("model") or "").strip()
    size = human_size(disk["size"]) if isinstance(disk.get("size"), (int, float)) else ""
    volumes = disk.get("volumes")
    if "volumes" not in disk:
        summary = ""
    elif volumes is None:
        summary = _("contents unknown")
    elif not volumes:
        summary = _("no volumes")
    else:
        names = [str(v.get("name") or v.get("filesystem") or _("(unnamed)")) for v in volumes[:3]]
        if len(volumes) > 3:
            names.append("…")
        template = _("1 volume ({names})") if len(volumes) == 1 else _("{count} volumes ({names})")
        summary = template.format(count=len(volumes), names=", ".join(names))
    detail = " · ".join(part for part in ((dev if model else ""), summary) if part)
    return (model or dev), size, detail


class _DriveRow(_CanvasBase):
    """One row of the drive list: a radio-like marker, the name, a `USB` badge, the size and the volumes.
    With `item=None` it is a grey placeholder ("skeleton") shown while the drives are being listed.
    Drawn on a canvas (like OptionCard) so it follows the light/dark theme."""

    HEIGHT = 58
    _rounded = OptionCard._rounded

    def __init__(self, parent, owner):
        super().__init__(parent, width=200, height=self.HEIGHT, bg=owner.bg, highlightthickness=0, takefocus=False)
        self.owner, self.item = owner, None
        self.selected = False
        self._hover = False
        self.bind("<Button-1>", lambda _e: self.owner._row_pressed(self))
        self.bind("<Return>", lambda _e: self.owner._row_pressed(self))
        self.bind("<space>", lambda _e: self.owner._row_pressed(self))
        self.bind("<Up>", lambda _e: self.owner._row_arrow(self, -1))
        self.bind("<Down>", lambda _e: self.owner._row_arrow(self, 1))
        self.bind("<Enter>", lambda _e: self._set_hover(True))
        self.bind("<Leave>", lambda _e: self._set_hover(False))
        self.bind("<FocusIn>", lambda _e: self.draw())
        self.bind("<FocusOut>", lambda _e: self.draw())
        self.bind("<Configure>", lambda _e: self.draw())
        self.refresh()

    def refresh(self):
        """Apply what the owner says about the state (enabled or not) and redraw."""
        usable = self.item is not None and self.owner._enabled
        self.configure(cursor="hand2" if usable else "arrow", takefocus=usable and self.selected)
        self.draw()

    def _set_hover(self, value):
        self._hover = value and self.item is not None and self.owner._enabled
        self.draw()

    def _focused(self):
        try:
            return self.focus_get() is self
        except (KeyError, tk.TclError):
            return False

    @staticmethod
    def _fit(text, font, room):
        """`text` cut with an ellipsis so it is at most `room` pixels wide."""
        if font.measure(text) <= room:
            return text
        while text and font.measure(text + "…") > room:
            text = text[:-1]
        return text.rstrip() + "…"

    def draw(self):
        owner = self.owner
        focused = self._focused()  # before anything is erased
        self.delete("all")
        w = max(self.winfo_width(), 240) if self.winfo_width() > 1 else 560
        h = self.HEIGHT
        cy = h / 2
        if self.item is None:  # skeleton: no text, no animation
            base = "#2c2c2e" if owner.dark else "#e9e9ee"
            bar = "#3a3a3c" if owner.dark else "#d1d1d6"
            self._rounded(3, 3, w - 3, h - 3, 10, fill=base, outline=base)
            self.create_oval(16, cy - 8, 32, cy + 8, fill=bar, outline=bar)
            self.create_rectangle(44, cy - 14, 44 + w * 0.34, cy - 4, fill=bar, outline=bar)
            self.create_rectangle(44, cy + 5, 44 + w * 0.2, cy + 13, fill=bar, outline=bar)
            return
        enabled = owner._enabled
        muted = "#8e8e93"
        text_color = owner.fg if enabled else muted
        color = "#6e6e73" if enabled else muted
        width = 1
        fill = ""
        if self.selected:
            color, width = owner.ACCENT, 2
            fill = "#10263d" if owner.dark else "#e6f1ff"
        elif enabled and (self._hover or focused):
            color, width = "#a0a0a8", 2
        self._rounded(3, 3, w - 3, h - 3, 10, outline=color, fill=fill, width=width)
        if focused and enabled:  # keyboard focus ring, also on the selected row
            self._rounded(1, 1, w - 1, h - 1, 12, outline="#ffffff" if owner.dark else "#003d99", fill="", width=1)
        marker = owner.ACCENT if self.selected else muted
        self.create_oval(16, cy - 8, 32, cy + 8, outline=marker, width=2)
        if self.selected:
            self.create_oval(20, cy - 4, 28, cy + 4, fill=marker, outline=marker)
        name, size, detail = drive_row_texts(self.item)
        right = w - 16
        if size:
            self.create_text(right, 21, text=size, anchor="e", fill=text_color, font=owner.name_font)
            right -= owner.name_font.measure(size) + 12
        accented = self.selected and enabled
        badge = _("USB")
        badge_w = owner.badge_font.measure(badge) + 14
        badge_fill = owner.ACCENT if accented else ("#3a3a3c" if owner.dark else "#e5e5ea")
        self._rounded(right - badge_w, 12, right, 30, 8, fill=badge_fill, outline=badge_fill)
        self.create_text(right - badge_w / 2, 21, text=badge, fill="#ffffff" if accented else text_color,
                         font=owner.badge_font)
        self.create_text(44, 21, text=self._fit(name, owner.name_font, right - badge_w - 54), anchor="w",
                         fill=text_color, font=owner.name_font)
        if detail:
            self.create_text(44, 41, text=self._fit(detail, owner.detail_font, w - 44 - 16), anchor="w",
                             fill=muted, font=owner.detail_font)


_FrameBase = ttk.Frame if ttk else object


class DriveList(_FrameBase):
    """The list of USB drives: one selectable row per drive, a placeholder while the drives are being
    listed and a short message when there are none. Replaces a drop-down so the drives are visible at once.

    Model API: `set_items(items)` (drive records with an "id"; the selection stays on the drive with the
    same id, otherwise it moves to the first one), `selected_index()` (-1 for none), `selected_item()`,
    `select(index)`, `set_enabled(flag)` (a disabled list greys out and ignores the mouse and the keyboard)
    and `set_loading(flag)` (two grey placeholder rows while no drive is shown). `view_state()` says what
    is on screen: "items", "loading" or "empty". `on_select()` runs when the USER (or `select`) changes the
    selection, never for `set_items`.
    Keyboard: Tab reaches the selected row; Up/Down move the selection; Space/Return choose the focused row.
    """

    ACCENT = "#0a84ff"
    SKELETON_ROWS = 2

    def __init__(self, parent, on_select=None):
        super().__init__(parent)
        style = ttk.Style(parent)
        self.bg = style.lookup("TFrame", "background") or style.lookup("TLabel", "background") or "#ececec"
        self.fg = style.lookup("TLabel", "foreground") or "#000000"
        r, g, b = self.winfo_rgb(self.bg)
        self.dark = (r + g + b) / 3 < 32768  # follows the light/dark theme through the window background
        base = tkfont.nametofont("TkDefaultFont")
        family, size = base.actual("family"), base.actual("size")
        self.name_font = tkfont.Font(family=family, size=size, weight="bold")
        self.detail_font = tkfont.Font(family=family, size=max(size - 1, 8))
        self.badge_font = tkfont.Font(family=family, size=max(size - 3, 7), weight="bold")
        self._on_select = on_select
        self._items = []
        self._selected = -1
        self._enabled = True
        self._loading = False
        self._loaded = False
        self.rows = []       # one _DriveRow per item
        self.skeleton = [_DriveRow(self, self) for _i in range(self.SKELETON_ROWS)]
        self.empty = ttk.Frame(self)
        ttk.Label(self.empty, text=_("No USB drive found"), font=self.name_font).pack(pady=(8, 0))
        ttk.Label(self.empty, text=_("Plug in a USB drive (8 GB or more) and it will appear here."),
                  foreground="#8e8e93").pack(pady=(2, 8))
        self._show()

    # ----- model -----
    def set_items(self, items):
        previous = self.selected_item()
        self._items = list(items)
        self._loaded = True
        if self._items:
            keep = next((i for i, d in enumerate(self._items)
                         if previous is not None and d.get("id") == previous.get("id")), 0)
        else:
            keep = -1
        self._selected = keep
        while len(self.rows) > len(self._items):
            self.rows.pop().destroy()
        while len(self.rows) < len(self._items):
            self.rows.append(_DriveRow(self, self))
        for i, (row, item) in enumerate(zip(self.rows, self._items, strict=True)):
            row.item, row.selected = item, i == self._selected
            row.refresh()
        self._show()

    def items(self):
        return list(self._items)

    def selected_index(self):
        return self._selected

    def selected_item(self):
        return self._items[self._selected] if 0 <= self._selected < len(self._items) else None

    def select(self, index):
        """Select row `index` (-1 clears the selection); calls `on_select` when the selection changed."""
        index = index if 0 <= index < len(self._items) else -1
        if index == self._selected:
            return
        self._selected = index
        for i, row in enumerate(self.rows):
            row.selected = i == index
            row.refresh()
        if self._on_select:
            self._on_select()

    def set_enabled(self, enabled):
        self._enabled = bool(enabled)
        for row in self.rows + self.skeleton:
            row._hover = row._hover and self._enabled
            row.refresh()

    def is_enabled(self):
        return self._enabled

    def set_loading(self, loading):
        loading = bool(loading)
        if loading != self._loading:
            self._loading = loading
            self._show()

    def is_loading(self):
        return self._loading

    def view_state(self):
        """What the list shows: "items", "loading" (placeholder rows) or "empty" (the no-drive message)."""
        if self._items:
            return "items"
        return "loading" if (self._loading or not self._loaded) else "empty"

    # ----- layout -----
    def _show(self):
        state = self.view_state()
        wanted = self.rows if state == "items" else (self.skeleton if state == "loading" else [self.empty])
        for widget in self.rows + self.skeleton + [self.empty]:
            if widget not in wanted and widget.winfo_manager():
                widget.pack_forget()
        for widget in wanted:
            if not widget.winfo_manager():
                widget.pack(fill="x", pady=2)

    # ----- input from the rows -----
    def _row_pressed(self, row):
        if not self._enabled or row.item is None:
            return
        row.focus_set()
        self.select(self.rows.index(row))

    def _row_arrow(self, row, step):
        if not self._enabled or row.item is None:
            return None
        target = self.rows.index(row) + step
        if 0 <= target < len(self.rows):
            self.select(target)
            self.rows[target].focus_set()
        return "break"


def _shorten_middle(text, limit):
    """`text` cut to at most `limit` characters by replacing the middle with an ellipsis (the start and the
    end of a path or file name are the parts that identify it)."""
    if limit < 5 or len(text) <= limit:
        return text
    keep = limit - 1
    head = keep // 2 + keep % 2
    return text[:head] + "…" + text[len(text) - (keep - head):]


class _StepHeading(ttk.Frame if ttk else object):
    """A small section heading: a numbered pill and a bold title ("1  Image type"). Follows the light/dark
    theme through the window background and the label colours."""

    MUTED = "#8e8e93"

    def __init__(self, parent, number, title):
        super().__init__(parent)
        style = ttk.Style(parent)
        bg = style.lookup("TFrame", "background") or style.lookup("TLabel", "background") or "#ececec"
        fg = style.lookup("TLabel", "foreground") or "#000000"
        base = tkfont.nametofont("TkDefaultFont")
        size = max(base.actual("size") - 1, 8)
        self.number, self.title = number, title
        pill = tk.Canvas(self, width=20, height=20, bg=bg, highlightthickness=0)
        pill.create_oval(1, 1, 19, 19, outline=self.MUTED, width=1)
        pill.create_text(10, 10, text=str(number), fill=self.MUTED, font=(base.actual("family"), size, "bold"))
        pill.pack(side="left", padx=(0, 8))
        self.label = ttk.Label(self, text=title, font=(base.actual("family"), base.actual("size") + 1, "bold"),
                               foreground=fg)
        self.label.pack(side="left")


class _FileCard(tk.Frame if tk else object):
    """The chosen image, as a compact card: the file name (bold), its folder (muted, shortened in the
    middle), its size and a badge with the kind that was detected. Until a file is chosen it shows only
    `empty_text`. `label` is the name label (it holds `empty_text` in the empty state)."""

    KIND_BADGES = {"windows": "#0a84ff", "linux": "#bf5af2", "chromeos": "#30a46c", "unknown": "#8e8e93"}

    def __init__(self, parent, empty_text, kind_names):
        style = ttk.Style(parent)
        bg = style.lookup("TFrame", "background") or style.lookup("TLabel", "background") or "#ececec"
        fg = style.lookup("TLabel", "foreground") or "#000000"
        super().__init__(parent, bg=bg, highlightthickness=0)
        self._empty_text, self._kind_names = empty_text, kind_names
        base = tkfont.nametofont("TkDefaultFont")
        small = (base.actual("family"), max(base.actual("size") - 1, 8))
        self.columnconfigure(0, weight=1)
        self.label = ttk.Label(self, text=empty_text, foreground="#8e8e93")
        self.label.grid(row=0, column=0, sticky="w")
        self._bold = (base.actual("family"), base.actual("size"), "bold")
        self._fg = fg
        self.folder_label = ttk.Label(self, text="", foreground="#8e8e93", font=small)
        self.size_label = ttk.Label(self, text="", foreground="#8e8e93", font=small)
        self.badge = tk.Label(self, text="", fg="#ffffff", font=(base.actual("family"), small[1], "bold"),
                              padx=7, pady=1, bd=0)
        self.has_file = False

    def clear(self):
        self.has_file = False
        self.label.configure(text=self._empty_text, foreground="#8e8e93", font=tkfont.nametofont("TkDefaultFont"))
        for widget in (self.folder_label, self.size_label, self.badge):
            widget.grid_remove()

    def show(self, path, kind, size=None):
        """Show `path`; `kind` is an ISO_KIND_* value; `size` is in bytes (None when it cannot be read)."""
        self.has_file = True
        folder = os.path.dirname(path)
        home = os.path.expanduser("~")
        if home and home != os.sep and (folder == home or folder.startswith(home + os.sep)):
            folder = "~" + folder[len(home):]
        self.label.configure(text=_shorten_middle(os.path.basename(path) or path, 56),
                             foreground=self._fg, font=self._bold)
        self.folder_label.configure(text=_shorten_middle(folder, 64))
        self.folder_label.grid(row=1, column=0, sticky="w")
        self.size_label.configure(text=human_size(size) if size is not None else "")
        self.size_label.grid(row=1, column=1, sticky="e", padx=(12, 0))
        name = self._kind_names.get(kind) or self._kind_names["unknown"]
        self.badge.configure(text=name, bg=self.KIND_BADGES.get(kind, self.KIND_BADGES["unknown"]))
        self.badge.grid(row=0, column=1, sticky="e", padx=(12, 0))


def _pack_bar(bar, *followers, pady=(8, 2)):
    """Show a progress bar that was hidden with pack_forget(), just above the first of `followers`
    that is on screen (so it keeps its place in the page)."""
    if str(bar.winfo_manager()) == "pack":
        return
    options = {"fill": "x", "pady": pady}
    for follower in followers:
        if follower is not None and str(follower.winfo_manager()) == "pack":
            options["before"] = follower
            break
    bar.pack(**options)


class _LinkLabel(_LabelBase):
    """A link-like label that runs `command` when clicked (or on Space/Return after Tab)."""

    def __init__(self, parent, text, command):
        super().__init__(parent, text=text, foreground="#4da3ff", cursor="hand2", takefocus=True)
        self._command = command
        self.bind("<Button-1>", lambda _e: self._command())
        self.bind("<Return>", lambda _e: self._command())
        self.bind("<space>", lambda _e: self._command())


_FrameBase = tk.Frame if tk else object


class _Banner(_FrameBase):
    """An inline message box with a soft coloured border: a failure ("error"), a finished write
    ("success") or something that needs attention ("warning"). It holds a title, the message and links
    (e.g. "Try again", "Make another", and "Dismiss"), and takes no space until `show()` packs it.

    `before=` / `after=` (a widget, or a function returning one) say where it goes when shown, as for
    `_LazyLabel`; without them it would land at the end of the page.
    """

    COLORS = {"error": "#e5534b", "success": "#2ea043", "warning": "#ff9f0a"}
    _pack_now = _LazyLabel._pack_now

    def __init__(self, parent, kind, **pack_options):
        style = ttk.Style(parent)
        bg = style.lookup("TFrame", "background") or style.lookup("TLabel", "background") or "#ececec"
        super().__init__(parent, bg=bg, highlightthickness=1, highlightbackground=self.COLORS[kind],
                         highlightcolor=self.COLORS[kind], bd=0)
        self.kind = kind
        self._pack_options = {"fill": "x", "pady": (8, 0), **pack_options}
        base = tkfont.nametofont("TkDefaultFont")
        bold = tkfont.Font(family=base.actual("family"), size=base.actual("size"), weight="bold")
        head = ttk.Frame(self)
        head.pack(fill="x", padx=10, pady=(6, 0))
        self._title = ttk.Label(head, font=bold)
        self._title.pack(side="left")
        self._links = ttk.Frame(head)
        self._links.pack(side="right")
        self._message = ttk.Label(self, justify="left", wraplength=PANEL_WRAP - 60)
        self._message.pack(anchor="w", padx=10, pady=(2, 8))
        self.title_text = self.message_text = ""

    @property
    def shown(self):
        return str(self.winfo_manager()) == "pack"

    def show(self, title, message, actions=(), dismiss=True, kind=None):
        """Show the box. `actions` are (text, command) links; each one closes the box first.
        `dismiss` adds the "Dismiss" link. `kind` changes the colour (default: the one it was made with)."""
        self.kind = kind or self.kind
        color = self.COLORS[self.kind]
        self.config(highlightbackground=color, highlightcolor=color)
        self._title.config(text=title, foreground=color)
        self._message.config(text=message)
        self.title_text, self.message_text = title, message
        for child in self._links.winfo_children():
            child.destroy()
        links = list(actions)
        if dismiss:
            links.append((_("Dismiss"), None))
        for text, command in links:
            _LinkLabel(self._links, text, lambda c=command: self._run(c)).pack(side="left", padx=(12, 0))
        if not self.shown:
            self._pack_now()

    def _run(self, command):
        self.clear()
        if command is not None:
            command()

    def clear(self):
        self.pack_forget()
        self.title_text = self.message_text = ""


class _DownloadWidgets:
    """The three widgets of a download card (download button, progress bar and its label) and the
    state changes the Windows ISO card and the ChromeOS Flex card share. The window keeps one per card and
    still exposes the widgets under their own names (download_btn, progress, flex_progress_label, ...).
    Cancel is the window's single Cancel button. The bar is on screen only while it has something to show."""

    def __init__(self, btn, bar, label):
        self.btn, self.bar, self.label = btn, bar, label

    def sync(self, running, creating):
        """Download off while a write (`creating`) or this card's own operation (`running`) is going."""
        self.btn.config(state="disabled" if (creating or running) else "normal")

    def hide_bar(self):
        self.bar.pack_forget()

    def start(self, text=None):
        """A new operation: an empty determinate bar (and `text` in the label, if given)."""
        _pack_bar(self.bar, self.label)
        self.bar.config(mode="determinate", value=0)
        if text is not None:
            self.label.config(text=text)

    def show(self, pct, text):
        """Progress: `pct` percent on the bar, or None when the length is unknown (a moving bar)."""
        _pack_bar(self.bar, self.label)
        if pct is None:
            self.bar.config(mode="indeterminate")
        else:
            self.bar.config(mode="determinate", value=pct)
        self.label.config(text=text)

    def finish(self, text, bar_value=None):
        """The operation ended (done or failed): the final `text`, and the bar set to `bar_value` if given
        (a bar left empty is hidden)."""
        if bar_value is not None:
            self.bar.config(mode="determinate", value=bar_value)
            if bar_value:
                _pack_bar(self.bar, self.label)
            else:
                self.hide_bar()
        self.label.config(text=text)


class App(_TkBase):
    def __init__(self):
        if tk is None:
            raise RuntimeError(TK_MISSING_MESSAGE)
        set_macos_app_name(APP_NAME)  # must run before the first window exists
        super().__init__(className=APP_NAME)
        self.title("EPMA USB CREATOR")
        self._window_size = (780, 700)  # grows when content needs more room (see _fit_window)
        self.geometry("{}x{}".format(*self._window_size))
        self.iso_path = tk.StringVar(value="")
        self.cancel_event = threading.Event()
        self.create_cancel_event = threading.Event()  # cancels the USB creation (not the download)
        self.disks = []
        self.priv = PrivilegeHelper(self)
        self._log_lock = threading.Lock()
        self._log_pending = []
        self._sha_job = 0  # identifies the running SHA-256 calculation, so stale results are ignored
        self._help_win = None
        self._creating = False          # True from the click on "Create" until the write has ended
        self._create_thread = None      # the worker that writes the drive (None before it starts / after it ends)
        self._closing = False           # the window is being closed: no more dialogs, no more listings
        self._download_running = False  # a Windows ISO download is running
        self._flex_busy = False         # a ChromeOS Flex download or extraction is running
        self._flex_extracting = False   # ... and it is in the extraction step
        self._installing = False        # "Install missing dependencies" is running
        self._last_disk_refresh = 0.0
        self._disk_job = 0              # identifies the drive listing whose result may still be applied
        self._disk_listing = False      # a listing worker is running (listings never overlap)
        self._disk_pending = None       # a refresh asked for while one was running: the `quiet` of the request
        self.flex_cancel_event = threading.Event()
        self._build_menu()
        self._build_ui()
        self._fit_window()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        if IS_MAC:
            self.createcommand("tk::mac::Quit", self._on_close)  # Cmd-Q goes through the same checks
        self.bind("<FocusIn>", self._auto_refresh_disks)
        self.after(300, self._auto_refresh_disks)
        self.after(LOG_FLUSH_MS, self._log_tick)

    # ---------- UI ----------
    # ---------- the window: one page ----------
    # 1 Image type (cards) -> 2 Image (where it comes from, the file) -> 3 USB drive -> create.
    def _build_ui(self):
        page = ttk.Frame(self)
        page.pack(fill="both", expand=True, padx=14, pady=(12, 8))
        self._build_header(page)
        self.step_headings = {}
        self._add_step(page, 1, _("Image type"), pady=(0, 6))
        self._build_cards(page)
        self._add_step(page, 2, _("Image"), pady=(0, 6))
        self._build_sources(page)
        self._build_image(page)
        before = len(page.pack_slaves())
        self._build_drive(page)
        # The heading of step 3 goes above the first widget of the drive section (after its separator, if any).
        section = page.pack_slaves()[before:]
        first = next((w for w in section if not isinstance(w, ttk.Separator)), None)
        self._add_step(page, 3, _("USB drive"), pady=(0, 6), before=first)
        self._build_create(page)
        self.select_card(CARD_WINDOWS)

    def _build_header(self, page):
        """The slim top row: name and version, the dependency chip (with the install button) and Help."""
        row = ttk.Frame(page)
        row.pack(fill="x", pady=(0, 10))
        base = tkfont.nametofont("TkDefaultFont")
        bold = tkfont.Font(family=base.actual("family"), size=base.actual("size") + 1, weight="bold")
        ttk.Label(row, text="EPMA USB CREATOR", font=bold).pack(side="left")
        ttk.Label(row, text=f"v{__version__}", foreground="#8e8e93").pack(side="left", padx=(6, 0))
        self.help_link = _LinkLabel(row, _("Help"), lambda: self.show_help())  # the same window as F1
        self.help_link.pack(side="right")
        # The chip: "● Ready" (green) or "● Missing tools" (amber). The install button sits to its left
        # and is shown only while something is missing (see check_dependencies).
        self.dep_label = ttk.Label(row, text="")
        self.dep_label.pack(side="right", padx=(0, 14))
        self.install_deps_btn = ttk.Button(row, text=_("Install missing dependencies"),
                                           command=self.install_dependencies)

    def _add_step(self, page, number, title, pady, **pack_options):
        heading = _StepHeading(page, number, title)
        heading.pack(anchor="w", pady=pady, **{k: v for k, v in pack_options.items() if v is not None})
        self.step_headings[number] = heading
        return heading

    def _build_cards(self, page):
        row = ttk.Frame(page)
        row.pack(fill="x", pady=(0, 10))
        self.cards_row = row
        for column in range(4):  # four equal columns sharing the window width
            row.columnconfigure(column, weight=1, uniform="cards")
        self.card_var = tk.StringVar(value=CARD_WINDOWS)
        self.mode_var = tk.StringVar(value=MODE_WINDOWS)
        self.cards = {}
        self.card_titles = {}
        for column, (key, title, subtitle) in enumerate((
            (CARD_CHROME, _("Google Chrome"), _("ChromeOS Flex")),
            (CARD_WINDOWS, _("Windows 11"), _("Copies the files")),
            (CARD_LINUX, _("Linux"), _("Ubuntu, Fedora...")),
            (CARD_OTHER, _("Other ISO"), _("Any bootable image")),
        )):
            card = OptionCard(row, key, title, subtitle, self.select_card)
            card.grid(row=0, column=column, sticky="ew", padx=((0, 9), (3, 6), (6, 3), (9, 0))[column])  # 9 px of gap in every cell
            self.cards[key] = card
            self.card_titles[key] = title

    def _build_sources(self, page):
        """One panel per card, stacked in the same cell; only the chosen one is shown (the others are
        grid_remove()d), so the holder is exactly as tall as the panel on screen: no blank area under a short
        panel. A download bar counts only while it is packed (see _pack_bar)."""
        holder = ttk.Frame(page)
        holder.pack(fill="x")
        holder.columnconfigure(0, weight=1)
        self._panel_holder = holder
        self.panels = {}
        for key in CARD_ORDER:
            panel = ttk.Frame(holder)
            panel.grid(row=0, column=0, sticky="nsew")
            self.panels[key] = panel

        # --- Google Chrome (ChromeOS Flex) ---
        f = self.panels[CARD_CHROME]
        ttk.Label(
            f, justify="left", wraplength=PANEL_WRAP,
            text=_("ChromeOS Flex is Google's free version of ChromeOS for PCs and Macs. Google does not publish "
                   "regular ChromeOS for ordinary computers. It needs a USB drive of 16 GB or larger; the "
                   "computer you install it on needs an Intel or AMD 64-bit processor, 4 GB of RAM and 16 GB "
                   "of storage, and Google only guarantees certified models.")).pack(anchor="w", pady=(0, 6))
        row = ttk.Frame(f)
        row.pack(fill="x")
        self.flex_download_btn = ttk.Button(row, text=_("Download ChromeOS Flex from Google"),
                                            command=self.start_flex_download)
        self.flex_download_btn.pack(side="left")
        links = ttk.Frame(f)
        links.pack(fill="x", pady=(6, 0))
        ttk.Button(links, text=_("Google's installation guide"),
                   command=lambda: webbrowser.open(CHROMEOS_FLEX_GUIDE_URL)).pack(side="left")
        ttk.Button(links, text=_("Google's requirements page"),
                   command=lambda: webbrowser.open(CHROMEOS_FLEX_REQUIREMENTS_URL)).pack(side="left", padx=5)
        self.flex_progress = ttk.Progressbar(f, orient="horizontal", mode="determinate")
        self.flex_progress.pack(fill="x", pady=(8, 2))
        self.flex_progress_label = _LazyLabel(f, anchor="w")  # takes no room while it has no text
        self.flex_dl = _DownloadWidgets(self.flex_download_btn, self.flex_progress, self.flex_progress_label)

        # --- Windows 11 ---
        f = self.panels[CARD_WINDOWS]
        ttk.Label(
            f, justify="left", wraplength=PANEL_WRAP,
            text=_("Microsoft only gives out the direct ISO link after you choose the edition and language: "
                   "open the official page, pick 'Windows 11 (multi-edition ISO)', right-click the blue 64-bit "
                   "button, choose 'Copy Link Address' (do NOT click it) and paste the link here.")
        ).pack(anchor="w", pady=(0, 6))
        grid = ttk.Frame(f)
        grid.pack(fill="x")
        grid.columnconfigure(1, weight=1)
        ttk.Label(grid, text=_("Direct ISO link (HTTPS only):")).grid(row=0, column=0, sticky="w", padx=(0, 8))
        self.url_entry = ttk.Entry(grid)
        self.url_entry.grid(row=0, column=1, sticky="ew", pady=2)
        ttk.Label(grid, text=_("Expected SHA-256 (optional):")).grid(row=1, column=0, sticky="w", padx=(0, 8))
        self.sha_entry = ttk.Entry(grid)
        self.sha_entry.grid(row=1, column=1, sticky="ew", pady=2)
        self.sha_entry.insert(0, os.environ.get(ENV_EXPECTED_SHA256, ""))
        btns = ttk.Frame(f)
        btns.pack(fill="x", pady=(6, 0))
        ttk.Button(btns, text=_("Open Microsoft's official page"), command=self.open_ms_page).pack(
            side="left", padx=(0, 12))
        self.download_btn = ttk.Button(btns, text=_("Download ISO"), command=self.start_download)
        self.download_btn.pack(side="left")
        self.progress = ttk.Progressbar(f, orient="horizontal", mode="determinate")
        self.progress.pack(fill="x", pady=(8, 2))
        self.progress_label = _LazyLabel(f, anchor="w")  # takes no room while it has no text
        self.windows_dl = _DownloadWidgets(self.download_btn, self.progress, self.progress_label)

        # --- Linux and Other ISO: nothing to download here ---
        ttk.Label(
            self.panels[CARD_LINUX], justify="left", wraplength=PANEL_WRAP,
            text=_("Download the ISO from your distribution's website (Ubuntu, Debian, Fedora, Mint, Arch...), "
                   "then choose the file below. It is written to the drive as it is, so it must be a hybrid "
                   "image; all current Linux ISOs are. Check its SHA-256 below if the site publishes one.")
        ).pack(anchor="nw")
        ttk.Label(
            self.panels[CARD_OTHER], justify="left", wraplength=PANEL_WRAP,
            text=_("Any bootable hybrid ISO or disk image is written to the drive exactly as it is. Choose the "
                   "file below. Images that cannot boot from a USB drive are refused before anything is erased.")
        ).pack(anchor="nw")

        for panel in self.panels.values():
            panel.grid_remove()
        # The progress bars appear only when a download runs.
        self.windows_dl.hide_bar()
        self.flex_dl.hide_bar()

    def _build_drive(self, page):
        ttk.Separator(page).pack(fill="x", pady=(10, 8))
        row = ttk.Frame(page)
        row.pack(fill="x")
        self.refresh_btn = ttk.Button(row, text="⟳ " + _("Refresh USB drives list"), command=self.refresh_disks)
        self.refresh_btn.pack(side="right")
        self.disk_list = DriveList(page, on_select=self.update_create_button_state)
        self.disk_list.pack(fill="x", pady=(4, 0))

    def _build_image(self, page):
        row = ttk.Frame(page)
        row.pack(fill="x", pady=(10, 0))
        ttk.Label(row, text=_("Already downloaded the image (ISO, or ChromeOS Flex .zip/.bin)?")).pack(side="left")
        self.pick_btn = ttk.Button(row, text=_("Select existing ISO file..."), command=self.pick_existing_iso)
        self.pick_btn.pack(side="left", padx=(8, 0))
        # The chosen image as a compact card (name, folder, size, detected kind); `iso_label` is its name label.
        self.iso_card = _FileCard(page, _("No ISO selected yet."), {
            ISO_KIND_WINDOWS: _("Windows 11"), ISO_KIND_LINUX: _("Linux"),
            ISO_KIND_CHROMEOS: _("ChromeOS Flex"), ISO_KIND_UNKNOWN: _("Unknown")})
        self.iso_card.pack(fill="x", pady=(6, 4))
        self.iso_label = self.iso_card.label

        # Integrity check of the selected image: a link that appears once an image is selected (see
        # set_iso) and opens this panel (progressive disclosure: most people skip the check).
        self.sha_toggle = _Disclosure(page, _("Verify the selected ISO (SHA-256)"),
                                      _("Verify the selected ISO (SHA-256)"), self._on_sha_toggled)
        self.iso_check_frame = ttk.LabelFrame(
            page, text=_("Paste the published hash or SHA256SUMS line, then calculate"))
        sha_row = ttk.Frame(self.iso_check_frame)
        sha_row.pack(fill="x", padx=8, pady=(4, 2))
        self.iso_sha_entry = ttk.Entry(sha_row)
        self.iso_sha_entry.pack(side="left", fill="x", expand=True)
        self.iso_sha_btn = ttk.Button(sha_row, text=_("Calculate SHA-256"), command=self.calculate_iso_sha256)
        self.iso_sha_btn.pack(side="left", padx=(8, 0))
        self.iso_sha_progress = ttk.Progressbar(self.iso_check_frame, orient="horizontal", mode="determinate")
        # The bar is packed only while a calculation has run (see _show_sha_bar).
        # Each label is placed relative to the other, whichever gets its text first: the progress text
        # always sits above the verdict.
        self.iso_sha_label = _LazyLabel(self.iso_check_frame, anchor="w", padx=8,
                                        after=self.iso_sha_progress, before=lambda: self.iso_sha_result)
        self.iso_sha_result = _LazyLabel(self.iso_check_frame, anchor="w", padx=8, pady=(0, 4),
                                         after=lambda: self.iso_sha_label)

    def _build_create(self, page):
        ttk.Separator(page).pack(fill="x", pady=(8, 8))
        self.check_dependencies()

        # One short warning right above the button that does the damage, in the warning colour.
        ttk.Label(page, text=_("WARNING: ALL DATA on the selected drive will be PERMANENTLY erased."),
                  foreground="#ff9f0a", justify="left", wraplength=PANEL_WRAP).pack(anchor="w", pady=(0, 6))
        create_row = ttk.Frame(page)
        create_row.pack(fill="x")
        self.create_btn = AccentButton(create_row, _("Create Bootable USB Drive"), self.start_create_usb,
                                       state="disabled")
        self.create_btn.pack(side="left")
        # The window's single Cancel: it stops whatever is running (a download, an extraction or the write).
        self.cancel_create_btn = ttk.Button(create_row, text=_("Cancel"), command=self.cancel_current,
                                            state="disabled")
        self.cancel_create_btn.pack(side="left", padx=(10, 0))
        # The bar is on screen only while an operation has run (see _reset_create_progress).
        self.create_progress = ttk.Progressbar(page, orient="horizontal", mode="determinate")
        self.create_progress_label = ttk.Label(page, text="")
        self.create_progress_label.pack(anchor="w")
        # The hint is packed only when it has text; `before=` keeps it right under the Create row
        # (above the bar when that is on screen) instead of at the very end of the page.
        self.create_hint = _LazyLabel(
            page, anchor="w", pady=(6, 0),
            before=lambda: self.create_progress if str(self.create_progress.winfo_manager()) == "pack"
            else self.create_progress_label)
        self.create_hint.config(foreground="#8e8e93")
        # Inline results under the Create row: a failure (soft red) and a finished write (green). Each is
        # packed only when shown, above the hint and the bar, so nothing else moves while they are hidden.
        self.error_banner = _Banner(page, "error", before=lambda: self._first_on_screen(
            self.success_panel, self.create_hint, self.create_progress, self.create_progress_label))
        self.success_panel = _Banner(page, "success", before=lambda: self._first_on_screen(
            self.create_hint, self.create_progress, self.create_progress_label))
        self._create_started = None
        self._create_last_ui = 0.0
        self._create_stage = None
        self._create_stage_base = 0

        # The log is behind a link: it is for problems, not for everyone.
        self.details_toggle = _Disclosure(page, _("Show details"), _("Hide details"), self._on_details_toggled)
        self.details_toggle.pack(anchor="w", pady=(6, 0))
        self.log_text = tk.Text(page, height=6, state="disabled", bg="black", fg="lightgreen")

    @staticmethod
    def _first_on_screen(*widgets):
        """The first of `widgets` that is packed (the anchor for `before=`), or None."""
        return next((w for w in widgets if str(w.winfo_manager()) == "pack"), None)

    # ---------- inline messages ----------
    def show_error(self, title, message, retry=None):
        """Show the red banner under the Create row. `retry` (optional) adds a "Try again" link."""
        self.error_banner.show(title, message, actions=[(_("Try again"), retry)] if retry else ())
        self.after_idle(self._fit_window)

    def clear_error(self):
        self.error_banner.clear()

    def show_success(self, title, message, verified_and_ejected=True):
        """Show the finished-write panel (green; amber when the drive still has to be ejected by hand)."""
        self.success_panel.show(title, message, actions=[(_("Make another"), self.make_another)], dismiss=False,
                                kind="success" if verified_and_ejected else "warning")
        self.after_idle(self._fit_window)

    def clear_success(self):
        self.success_panel.clear()

    def make_another(self):
        """Back to the start of the flow after a finished write: the panel and the old result go away."""
        self.clear_success()
        self.create_progress.pack_forget()
        self.create_progress_label.config(text="")
        self.refresh_disks(quiet=True)  # the drive that was ejected is no longer there
        self.update_create_button_state()

    def _on_details_toggled(self, is_open):
        if is_open:
            self.log_text.pack(fill="both", expand=True, pady=(6, 0), after=self.details_toggle)
            self.log_text.see("end")
        else:
            self.log_text.pack_forget()
        self.after_idle(self._fit_window)

    def _on_sha_toggled(self, is_open):
        if is_open:
            if str(self.sha_toggle.winfo_manager()) == "pack":  # the link shows once an image is chosen
                self.iso_check_frame.pack(fill="x", pady=(0, 6), after=self.sha_toggle)
        else:
            self.iso_check_frame.pack_forget()
        self.after_idle(self._fit_window)

    def _show_sha_bar(self):
        _pack_bar(self.iso_sha_progress, self.iso_sha_label, self.iso_sha_result, pady=(0, 2))

    def select_card(self, key):
        """Choose the image type: shows its source panel and sets how the image will be written."""
        if key not in CARD_MODE:
            return
        self.card_var.set(key)
        self.mode_var.set(CARD_MODE[key])
        for k, card in self.cards.items():
            card.set_selected(k == key)
        for k, panel in self.panels.items():
            if k == key:
                panel.grid()
            else:
                panel.grid_remove()
        self.on_mode_change()

    # ---------- dependencies ----------
    def on_mode_change(self):
        self.check_dependencies()
        self.update_create_button_state()

    def check_dependencies(self):
        missing = get_missing_dependencies(self.mode_var.get())
        if not missing:
            self.dep_label.config(text=_("● Ready"), foreground="#2ea043")
            self.install_deps_btn.pack_forget()
        else:
            self.dep_label.config(text=_("● Missing tools"), foreground="#ff9f0a")
            self.install_deps_btn.pack(side="right", padx=(0, 10))

    def install_dependencies(self):
        if self._creating or self._installing:
            return  # installing clears the cached administrator password the running write may be using
        self._installing = True
        self.clear_error()
        self._sync_controls()
        self.update_create_button_state()

        def worker():
            try:
                if IS_MAC:
                    if not shutil.which("brew"):
                        raise RuntimeError("Homebrew not found. Install it from https://brew.sh")
                    run_cmd(["brew", "install", "wimlib"], self.log_threadsafe)
                else:
                    missing = get_missing_dependencies(MODE_WINDOWS)
                    mgr = linux_detect_pkg_manager()
                    if not mgr:
                        raise RuntimeError(
                            "No supported package manager found (apt/dnf/yum/pacman/zypper/apk). "
                            "Please install manually: " + ", ".join(missing)
                        )
                    install_command = linux_build_install_command(mgr, missing)
                    # Show exactly what will run as root before it runs.
                    self.log_threadsafe(f"About to run as administrator: {install_command}")
                    audit(f"Installing dependencies via {mgr}: {', '.join(missing)}")
                    # A fixed prefix (so a failing step stops the script) in front of a command that
                    # linux_build_install_command() builds only from the fixed package allow-list.
                    script = "set -eu\n" + install_command
                    self.priv.run_script(script, self.log_threadsafe)
            except (ValueError, RuntimeError) as e:  # shown as a banner (not a dialog), with "Try again"
                self.after(0, self._report_error, "Error", str(e), None, False, self.install_dependencies)
            except Exception as e:
                self.after(0, self._report_error, "Unexpected error", None, e, False, self.install_dependencies)
            finally:
                self.priv.clear_cached_password()
                self.after(0, self._installation_ended)

        threading.Thread(target=worker, daemon=True).start()

    def _installation_ended(self):
        self._installing = False
        self.check_dependencies()
        self._sync_controls()
        self.update_create_button_state()  # the Create button depends on the tools being there

    # ---------- download ----------
    def open_ms_page(self):
        webbrowser.open(MS_DOWNLOAD_PAGE)

    def pick_existing_iso(self):
        if self._creating or self._flex_busy:
            return  # the button is disabled meanwhile; this is the safety net for other callers
        path = filedialog.askopenfilename(
            title=_("Select an ISO or disk image"),
            filetypes=[(_("ISO and disk images"), "*.iso *.bin *.img *.zip"), (_("All files"), "*")])
        if not path:
            return
        if self._creating or self._flex_busy:
            return  # something started while the file dialog was open
        if path.lower().endswith(".zip"):
            # Google distributes ChromeOS Flex as latest.bin.zip: extract the .bin next to it.
            self.select_card(CARD_CHROME)  # the extraction progress is shown in that card
            self.flex_cancel_event.clear()  # a new operation: only here, so a running one never loses its cancel
            self._extract_flex_image(path, delete_zip=False)
        else:
            self.set_iso(path)

    def _launch_download(self, url, dest, cancel_event, on_progress, on_done, on_error, **thread_options):
        """Start a DownloadThread whose three callbacks run on the Tk thread (the worker only posts them).

        on_progress(done, total, speed), on_done(path, sha256, verified), on_error(message).
        """
        DownloadThread(
            url, dest,
            progress_cb=lambda d, t, sp: self.after(0, on_progress, d, t, sp),
            done_cb=lambda p, h, v: self.after(0, on_done, p, h, v),
            error_cb=lambda e: self.after(0, on_error, e),
            cancel_event=cancel_event, **thread_options,
        ).start()

    # ---------- ChromeOS Flex (download from Google, extract, then the normal write flow) ----------
    def start_flex_download(self):
        if self._creating or self._flex_busy:
            return
        if not messagebox.askyesno(
            _("Download ChromeOS Flex"),
            _("ChromeOS Flex is provided by Google and is subject to Google's own terms.\n\n"
              "This program only downloads Google's official image from its servers "
              "(dl.google.com) over HTTPS and prepares it for your USB drive. Google's installation "
              "guide: {url}\n\nDownload it now?").format(url=CHROMEOS_FLEX_GUIDE_URL),
        ):
            return
        dest = filedialog.asksaveasfilename(
            title=_("Save ChromeOS Flex as"), defaultextension=".zip", initialfile="chromeos_flex_latest.bin.zip",
            filetypes=[(_("ZIP archive"), "*.zip")])
        if not dest:
            return
        try:
            free = shutil.disk_usage(os.path.dirname(os.path.abspath(dest))).free
        except OSError:
            free = None
        if free is not None and free < CHROMEOS_FLEX_FREE_BYTES and not messagebox.askyesno(
                _("Not much free space"),
                _("The download (about 1.4 GB) and the extracted image (about 9.5 GB) need roughly "
                  "{need} free in this folder, and only {free} is available. It may fail part-way.\n\n"
                  "Continue anyway?").format(need=human_size(CHROMEOS_FLEX_FREE_BYTES), free=human_size(free)),
                icon="warning"):
            return
        if self._creating or self._flex_busy:
            return  # something started while the dialogs were open
        audit("ChromeOS Flex download started (dl.google.com)")
        self.flex_cancel_event.clear()
        self._flex_busy = True
        self.clear_error()
        self._sync_controls()
        self.flex_dl.start()
        self._launch_download(
            CHROMEOS_FLEX_URL, dest, self.flex_cancel_event,
            on_progress=lambda d, t, sp: self._on_flex_progress(d, t, sp, _("Downloading...")),
            on_done=lambda p, h, _verified: self._on_flex_downloaded(p, h),
            on_error=self._on_flex_error,
            allowed_hosts=CHROMEOS_FLEX_HOSTS)

    def cancel_flex(self):
        self.flex_cancel_event.set()

    def _on_flex_progress(self, done, total, speed, stage):
        if total:
            pct = done / total * 100
            self.flex_dl.show(
                pct, f"{stage}  {pct:.1f}% — {human_size(done)} / {human_size(total)}{_rate_tail(done, total, speed)}")
        else:
            self.flex_dl.show(None, f"{stage}  {human_size(done)}")

    def _on_flex_downloaded(self, path, sha256):
        self.log(_("SHA-256 of the downloaded file: {sha256}").format(sha256=sha256))
        if self.flex_cancel_event.is_set():  # canceled just as the download ended: keep the cancel
            self._on_flex_error(_("Canceled."))
            return
        self._extract_flex_image(path, delete_zip=True)

    def _extract_flex_image(self, zip_path, delete_zip):
        """Extract the .bin from `zip_path` in a worker thread, then select it for writing.

        The caller starts the operation (see `start_flex_download` / `pick_existing_iso`); this never
        clears `flex_cancel_event`, so a cancel that is already pending is honoured. A second
        extraction cannot start while one is running.
        """
        if self._flex_extracting:
            return
        self._flex_extracting = True
        self._flex_busy = True
        self.clear_error()
        self._sync_controls()
        self.flex_dl.start(_("Extracting..."))
        folder = os.path.dirname(os.path.abspath(zip_path))

        def worker():
            try:
                image = extract_disk_image(
                    zip_path, folder,
                    progress=lambda d, t: self.after(0, self._on_flex_progress, d, t, 0, _("Extracting...")),
                    cancel_event=self.flex_cancel_event)
            except OperationCanceled:
                self.after(0, self._on_flex_error, _("Canceled."))
            except (ValueError, OSError, RuntimeError) as e:
                self.after(0, self._on_flex_error, str(e))
            except Exception as e:  # noqa: BLE001 - shown in a dialog, never lost
                self.after(0, self._on_flex_error, f"{type(e).__name__}: {e}")
            else:
                self.after(0, self._on_flex_extracted, image, zip_path, delete_zip)

        threading.Thread(target=worker, daemon=True).start()

    def _on_flex_extracted(self, image, zip_path, delete_zip):
        self._flex_busy = self._flex_extracting = False
        self._sync_controls()
        if self._closing:
            return
        self.flex_dl.finish(_("Ready."), bar_value=100)
        if delete_zip:
            _silent_remove(zip_path)  # only the archive this program downloaded itself
        self.set_iso(image)
        self.refresh_disks()  # so a drive that is already plugged in shows up right away
        messagebox.showinfo(
            _("ChromeOS Flex is ready"),
            _("The disk image is ready:\n{path}\n\nNext: plug in a USB drive of 16 GB or larger, click "
              "\"Refresh USB drives list\", select the drive and click "
              "\"Create Bootable USB Drive\".").format(path=image))

    def _on_flex_error(self, msg):
        was_extracting = self._flex_extracting
        self._flex_busy = self._flex_extracting = False
        self._sync_controls()
        if self._closing:
            return
        self.flex_dl.finish(_("Failed."), bar_value=0)
        # "Try again" repeats the download; a failed extraction of a file the user chose has nothing to repeat.
        self._report_error("ChromeOS Flex", msg, modal=False,
                           retry=None if was_extracting else self.start_flex_download)

    # ---------- Help menu and built-in documentation ----------
    def _build_menu(self):
        menubar = tk.Menu(self)
        # name="help" lets macOS treat it as the system Help menu.
        help_menu = tk.Menu(menubar, name="help", tearoff=False)
        help_menu.add_command(label=_("EPMA USB CREATOR Help"), accelerator="F1", command=self.show_help)
        help_menu.add_separator()
        help_menu.add_command(label=_("Open the audit log folder"), command=self.open_audit_log_folder)
        help_menu.add_command(label=_("Project page (GitHub)"), command=self.open_project_page)
        if not IS_MAC:  # on macOS "About" lives in the application menu (see createcommand below)
            help_menu.add_separator()
            help_menu.add_command(label=_("About EPMA USB CREATOR"), command=self.show_about)
        menubar.add_cascade(label=_("Help"), menu=help_menu)
        self.config(menu=menubar)
        self.bind_all("<F1>", lambda _event: self.show_help())
        if IS_MAC:
            self.createcommand("tk::mac::ShowHelp", self.show_help)
            self.createcommand("tkAboutDialog", self.show_about)

    def show_help(self, section=0):
        """Open the documentation window (or bring it to the front) on the given section."""
        sections = help_sections()
        win = self._help_win
        if win is not None and win.winfo_exists():
            win.deiconify()
            win.lift()
            win.focus_force()
            win._select(section)
            return
        win = tk.Toplevel(self)
        win.title(_("EPMA USB CREATOR Help"))
        win.geometry("880x640")
        win.minsize(640, 420)
        style = ttk.Style(win)
        bg = style.lookup("TLabel", "background") or "#ececec"
        fg = style.lookup("TLabel", "foreground") or "#000000"

        body = ttk.Frame(win)
        body.pack(fill="both", expand=True, padx=8, pady=8)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        nav = tk.Listbox(body, width=28, exportselection=False, activestyle="none", bg=bg, fg=fg,
                         highlightthickness=0, borderwidth=0)
        nav.grid(row=0, column=0, sticky="ns", padx=(0, 8))
        for title, _body in sections:
            nav.insert("end", title)

        text = tk.Text(body, wrap="word", bg=bg, fg=fg, insertbackground=fg, borderwidth=0,
                       highlightthickness=0, padx=14, pady=10, spacing1=2, spacing3=2, cursor="arrow")
        scroll = ttk.Scrollbar(body, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.grid(row=0, column=1, sticky="nsew")
        scroll.grid(row=0, column=2, sticky="ns")
        base = tkfont.nametofont("TkDefaultFont")
        text.tag_configure("h2", font=(base.actual("family"), base.actual("size") + 1, "bold"),
                           spacing1=10, spacing3=3)
        text.tag_configure("bullet", lmargin1=12, lmargin2=28)
        text.tag_configure("title", font=(base.actual("family"), base.actual("size") + 5, "bold"), spacing3=8)

        def select(index):
            index = max(0, min(int(index), len(sections) - 1))
            nav.selection_clear(0, "end")
            nav.selection_set(index)
            nav.see(index)
            self._render_help(text, *sections[index])

        win._select = select
        nav.bind("<<ListboxSelect>>", lambda _e: select(nav.curselection()[0]) if nav.curselection() else None)
        ttk.Button(win, text=_("Close"), command=win.destroy).pack(anchor="e", padx=10, pady=(0, 10))
        win.bind("<Escape>", lambda _e: win.destroy())
        self._help_win = win
        select(section)
        win.lift()
        win.focus_force()

    @staticmethod
    def _render_help(text, title, body):
        """Show one documentation section in the (read-only) Text widget."""
        text.configure(state="normal")
        text.delete("1.0", "end")
        text.insert("end", title + "\n", "title")
        for line in body.split("\n"):
            if line.startswith("## "):
                text.insert("end", line[3:] + "\n", "h2")
            elif line.startswith("• "):
                text.insert("end", line + "\n", "bullet")
            else:
                text.insert("end", line + "\n")
        text.configure(state="disabled")
        text.yview_moveto(0)

    def show_about(self):
        about = dict(help_sections())["About"]
        messagebox.showinfo(_("About EPMA USB CREATOR"), about)

    def open_audit_log_folder(self):
        folder = os.path.dirname(audit_log_path())
        try:
            os.makedirs(folder, mode=0o700, exist_ok=True)
            webbrowser.open(pathlib.Path(folder).as_uri())
        except OSError as e:
            messagebox.showerror(_("Audit log"), _("Could not open the folder: {reason}").format(reason=e))

    def open_project_page(self):
        webbrowser.open(PROJECT_URL)

    def _image_matches_choice(self, mode):
        """Stop (or ask) when the selected file is clearly not what the chosen card writes.

        A Linux image under "Windows 11" would otherwise be discovered only after the drive
        was erased ("could not find install.wim"); a non-ChromeOS file under "Google Chrome"
        is refused outright.
        """
        image = self.iso_path.get()
        kind = detect_iso_kind(image)
        if mode == MODE_CHROMEOS and kind != ISO_KIND_CHROMEOS:
            messagebox.showerror(
                _("ChromeOS Flex"),
                _("The selected image is not a ChromeOS Flex disk image:\n{path}\n\n"
                  "Download it with the button above, or select the .bin file from Google's "
                  "latest.bin.zip.").format(path=image))
            return False
        if mode == MODE_WINDOWS and kind in (ISO_KIND_LINUX, ISO_KIND_CHROMEOS):
            name = _("a Linux image") if kind == ISO_KIND_LINUX else _("a ChromeOS image")
            return messagebox.askyesno(
                _("This does not look like Windows"),
                _("The selected file looks like {name}, but \"Windows 11\" is chosen. Windows mode would "
                  "erase the drive and then fail to find the Windows installer.\n\n"
                  "Choose the matching card instead, or continue only if you are sure.\n\n"
                  "Continue anyway?").format(name=name),
                icon="warning")
        if mode == MODE_WINDOWS and kind == ISO_KIND_UNKNOWN:
            # Nothing says this is a Windows installer, and Windows mode erases the drive BEFORE it
            # looks for install.wim. The file name is no evidence, so ask.
            return messagebox.askyesno(
                _("Image type not recognised"),
                _("The program could not identify the selected file, but \"Windows 11\" is chosen. Windows mode "
                  "would erase the drive and then fail if this is not a Windows installer.\n\n"
                  "Continue only if you are sure this is a Windows 11 ISO.\n\n"
                  "Continue anyway?"),
                icon="warning")
        return True

    MIN_WINDOW_HEIGHT = 700  # the height the window starts with and settles back to

    def _fit_window(self):
        """Make the window tall enough for its content, and let it settle back when the content shrinks.

        It grows when something appears (the checksum panel, the log, a result) and returns toward
        MIN_WINDOW_HEIGHT when that goes away again, but only while the user has not resized the window
        by hand. Capped to the screen. The width is kept as it is.
        """
        self.update_idletasks()
        last = self._window_size[1]
        shown = self.winfo_height()
        if shown <= 1:  # not on screen yet (or withdrawn): the size that was asked for is all there is
            shown = last
        width = self.winfo_width() if self.winfo_width() > 1 else self._window_size[0]
        needed = min(max(self.MIN_WINDOW_HEIGHT, self.winfo_reqheight()),
                     max(self.winfo_screenheight() - 120, self.MIN_WINDOW_HEIGHT))
        if needed > shown:
            height = needed
        elif abs(shown - last) <= 2 and needed < last:  # still the size we set: settle back
            height = needed
        else:
            return  # the user made it taller than needed: leave it alone
        if height != last:
            self._window_size = (width, height)
            self.geometry("{}x{}".format(*self._window_size))

    def set_iso(self, path):
        self.iso_path.set(path)
        # Only a default: the user can still switch the image type by hand. The CONTENT of the ISO
        # decides. When it cannot be identified the card is left as it is: guessing from the file name
        # could pick the card that erases the drive first ("darwin-linux.img" contains "win").
        kind = detect_iso_kind(path)
        try:
            size = os.path.getsize(path)
        except OSError:
            size = None
        self.iso_card.show(path, kind, size)
        if kind == ISO_KIND_UNKNOWN:
            card = self.card_var.get()
            self.log(_("The content of this image could not be identified, so the image type was not changed. "
                       "Check that the selected card ({card}) is the right one.").format(
                           card=self.card_titles.get(card, card)))
        else:
            card = KIND_CARD[kind]
            if kind == ISO_KIND_LINUX and self.card_var.get() == CARD_OTHER:
                card = CARD_OTHER  # a hybrid image keeps "Other ISO" if that is what was chosen, otherwise "Linux"
            image = _image_label(KIND_MODE[kind], _("Linux / other hybrid ISO"))
            self.log(_("Image type preselected {how}: {image}.").format(
                how=_("from the content of the ISO"), image=image))
        self.select_card(card)
        self._reset_iso_sha()
        self.sha_toggle.pack(anchor="w", pady=(0, 6), after=self.iso_card)
        if self.sha_toggle.is_open:
            self.iso_check_frame.pack(fill="x", pady=(0, 6), after=self.sha_toggle)
        self.after_idle(self._fit_window)

    def start_download(self):
        if self._creating or self._download_running:
            return
        try:
            url, host, untrusted_host = validate_download_url(self.url_entry.get())
        except ValueError as e:
            messagebox.showerror(_("Invalid link"), str(e))
            return

        expected_sha = self.sha_entry.get().strip().lower()
        if expected_sha and not is_sha256_hex(expected_sha):
            messagebox.showerror(
                _("Invalid checksum"),
                _("A SHA-256 checksum must be exactly 64 characters using only 0-9 and a-f.\n\n"
                  "Leave the field empty if you do not have one."),
            )
            return

        if untrusted_host and not messagebox.askyesno(
            _("Unrecognised download server"),
            _("This link points to '{host}', which is not a known Microsoft download server.\n\n"
              "Downloading a Windows image from an unofficial source is a real risk: a tampered "
              "image would install a compromised Windows on the target computer, and you would "
              "have no way of noticing.\n\n"
              "Continue anyway?").format(host=host),
            icon="warning",
        ):
            audit(f"User declined download from untrusted host: {host}")
            return

        dest = filedialog.asksaveasfilename(
            title=_("Save ISO as"), defaultextension=".iso", initialfile="Win11.iso",
            filetypes=[(_("ISO image"), "*.iso")]
        )
        if not dest:
            return
        audit(f"Download started from host={host} trusted={not untrusted_host} "
              f"checksum_supplied={bool(expected_sha)}")
        if self._creating or self._download_running:
            return  # something started while the dialogs were open
        self.cancel_event.clear()
        self._download_running = True
        self.clear_error()
        self._sync_controls()
        self.windows_dl.start()
        self._launch_download(url, dest, self.cancel_event, self._on_progress, self._on_download_done,
                              self._on_download_error, expected_sha256=expected_sha)

    def cancel_download(self):
        self.cancel_event.set()

    def _on_progress(self, downloaded, total, speed):
        if total:
            pct = downloaded / total * 100
            eta = _eta_remaining(downloaded, total, speed)
            self.windows_dl.show(pct, _("{done} / {total} ({pct:.1f}%) — {speed}/s — {eta}").format(
                done=human_size(downloaded), total=human_size(total), pct=pct,
                speed=human_size(speed), eta=eta or _("calculating...")))
        else:
            self.windows_dl.show(None, _("{done} downloaded — {speed}/s").format(
                done=human_size(downloaded), speed=human_size(speed)))

    def _on_download_done(self, path, sha256, verified):
        self._download_running = False
        self._sync_controls()
        if self._closing:
            return
        self.windows_dl.finish(_("Download complete."))
        self.set_iso(path)
        self.log(_("SHA-256 of the downloaded file: {sha256}").format(sha256=sha256))
        if verified:
            detail = "\n\n" + _("The SHA-256 checksum matches the value you supplied — the file is intact.")
        else:
            detail = "\n\n" + _(
                "SHA-256 of this file:\n{sha256}\n\n"
                "No checksum was supplied, so authenticity was NOT verified. If Microsoft "
                "publishes a checksum for this image, compare it with the value above before "
                "writing the USB drive."
            ).format(sha256=sha256)
        messagebox.showinfo(_("Done"), _("ISO downloaded to:\n{path}").format(path=path) + detail)

    def _on_download_error(self, msg):
        self._download_running = False
        self._sync_controls()
        if self._closing:
            return
        self.windows_dl.finish(_("Download failed."), bar_value=0)
        self._report_error("Download error", msg, modal=False, retry=self.start_download)

    # ---------- USB drive ----------
    def refresh_disks(self, quiet=False, sync=False):
        """Read the list of USB drives. `quiet` (automatic refreshes) logs a failure instead of
        opening a dialog. The drive that was selected stays selected if it is still there.

        The listing runs diskutil/lsblk, which can take a long time (or hang) with a faulty drive, so
        it runs in a worker thread and the window stays alive; the result is applied on the Tk thread.
        Two listings never overlap: a request made while one runs is remembered and served right after.
        `sync=True` lists on the calling thread (tests and the smoke test).
        """
        if self._closing:
            return
        if not quiet:
            self.clear_error()  # an explicit refresh starts over; automatic ones never hide a message
        if sync:
            self._disk_job += 1
            job = self._disk_job
            try:
                disks = get_external_disks()
            except Exception as e:  # noqa: BLE001 - shown (or logged), never lost
                self._on_disks_error(job, e, quiet)
            else:
                self._on_disks(job, disks)
            return
        if self._disk_listing:
            # Keep the strongest request: an explicit click (not quiet) must still report a failure.
            self._disk_pending = quiet if self._disk_pending is None else (self._disk_pending and quiet)
            return
        self._disk_listing = True
        self.disk_list.set_loading(True)
        self._disk_job += 1
        job = self._disk_job

        def worker():
            try:
                disks = get_external_disks()
            except Exception as e:  # noqa: BLE001 - delivered to the Tk thread below
                self._post(self._listing_finished, job, None, e, quiet)
            else:
                self._post(self._listing_finished, job, disks, None, quiet)

        threading.Thread(target=worker, daemon=True).start()

    def _post(self, func, *args):
        """Run `func(*args)` on the Tk thread from a worker; silently drop it once the window is gone."""
        try:
            self.after(0, func, *args)
        except (RuntimeError, tk.TclError):
            pass

    def _listing_finished(self, job, disks, error, quiet):
        """The listing worker delivered its result on the Tk thread; then serve the request made meanwhile."""
        self._disk_listing = False
        self.disk_list.set_loading(False)
        try:
            if error is not None:
                self._on_disks_error(job, error, quiet)
            else:
                self._on_disks(job, disks)
        finally:
            pending, self._disk_pending = self._disk_pending, None
            if pending is not None and not self._closing:
                self.refresh_disks(quiet=pending)

    def _on_disks_error(self, job, error, quiet):
        if job != self._disk_job or self._closing:
            return  # an older listing, or the window is closing
        if self.disk_list.view_state() == "loading":
            self.disk_list.set_items(self.disks)  # the listing failed: stop showing the placeholder rows
        if quiet:
            self.log(_("Could not list disks: {error}").format(error=error))
        else:
            self._report_error("Error", _("Could not list disks: {error}").format(error=error), modal=False,
                               retry=self.refresh_disks)

    def _on_disks(self, job, disks):
        if job != self._disk_job or self._closing or self._creating:
            return  # an older listing, or the write is running: _creation_ended lists again
        self.disks = disks
        self._last_disk_refresh = time.monotonic()
        self.disk_list.set_items(self.disks)  # keeps the selection on the same drive (by id), else the first
        self.update_create_button_state()
        self.after_idle(self._fit_window)  # the list is taller or shorter with more or fewer drives

    def _auto_refresh_disks(self, _event=None):
        """Look for newly plugged drives when the program starts and whenever its window gets
        focus again, so the user does not have to remember to click "Refresh"."""
        if _event is not None and _event.widget is not self:
            return  # focus moved between widgets inside the window
        if self._creating or time.monotonic() - self._last_disk_refresh < AUTO_REFRESH_MIN_SECONDS:
            return
        self.refresh_disks(quiet=True)

    def selected_disk(self):
        idx = self.disk_list.selected_index()
        if idx < 0 or idx >= len(self.disks):
            return None
        return self.disks[idx]

    def _sync_controls(self):
        """Enable or disable the controls that must not be used while something is running.

        While a write runs nothing that changes the image type, the drive or the image may be touched
        (a second click on Create, a different card or a refreshed list would act on the same drive).
        A download or an extraction only locks its own button and the image picker.
        """
        creating = self._creating
        busy = "disabled"
        for card in self.cards.values():
            card.set_enabled(not creating)
        self.disk_list.set_enabled(not creating)
        self.refresh_btn.config(state=busy if creating else "normal")
        self.windows_dl.sync(self._download_running, creating)
        self.flex_dl.sync(self._flex_busy, creating)
        if not creating:  # during a write the Cancel button follows the write itself (see start_create_usb)
            self.cancel_create_btn.config(state="normal" if (self._download_running or self._flex_busy)
                                          else "disabled")
        self.pick_btn.config(state=busy if (creating or self._flex_busy) else "normal")
        self.install_deps_btn.config(state=busy if (creating or self._installing) else "normal")

    def update_create_button_state(self):
        disk = self.selected_disk()
        has_image = bool(self.iso_path.get())
        # The tools the chosen mode needs: without them the drive would be erased and the copy would then fail.
        missing = [] if self._creating else get_missing_dependencies(self.mode_var.get())
        ok = (has_image and disk is not None and not missing and not self._creating and not self._installing
              and not self._closing)
        self.create_btn.config(state="normal" if ok else "disabled")
        if self._creating:
            hint = ""
        elif not has_image:
            hint = _("Choose the image file first (\"Select existing ISO file...\" or the download above).")
        elif disk is None and not self.disks:
            hint = _("No USB drive found. Plug it in and click \"Refresh USB drives list\".")
        elif disk is None:
            hint = _("Select a USB drive in the list.")
        elif missing:
            hint = _("Missing tools: {tools}. Click \"Install missing dependencies\" first.").format(
                tools=", ".join(missing))
        elif self._installing:
            hint = _("Installing the missing tools...")
        else:
            hint = ""
        self.create_hint.config(text=hint)

    # ---------- log box ----------
    # Workers can emit thousands of lines (rsync -v); inserting each one through after(0)
    # floods the Tk event loop. They append to a queue instead, drained in one insert every
    # LOG_FLUSH_MS. log() (main thread) appends and drains at once, so order is preserved.
    def log_threadsafe(self, msg):
        """Queue a log line from ANY thread; it appears within LOG_FLUSH_MS."""
        with self._log_lock:
            self._log_pending.append(str(msg))
            if len(self._log_pending) > 4 * LOG_MAX_LINES:  # nobody can read more than the box keeps
                del self._log_pending[:2 * LOG_MAX_LINES]

    def log(self, msg):
        """Write a log line. Main thread only; use log_threadsafe() from workers."""
        self.log_threadsafe(msg)
        self._flush_log()

    def _flush_log(self):
        with self._log_lock:
            lines, self._log_pending = self._log_pending, []
        if not lines:
            return
        lines = lines[-LOG_MAX_LINES:]
        self.log_text.config(state="normal")
        self.log_text.insert("end", "\n".join(lines) + "\n")
        total = int(self.log_text.index("end-1c").split(".")[0])
        if total > LOG_MAX_LINES:
            self.log_text.delete("1.0", f"{total - LOG_MAX_LINES + 1}.0")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def _log_tick(self):
        try:
            self._flush_log()
        except tk.TclError:
            return  # the window is gone
        self.after(LOG_FLUSH_MS, self._log_tick)

    # ---------- SHA-256 of the selected ISO ----------
    def _reset_iso_sha(self):
        self._sha_job += 1  # invalidates any calculation still running for the previous file
        self.iso_sha_btn.config(state="normal")
        self.iso_sha_progress.config(value=0)
        self.iso_sha_progress.pack_forget()
        self.iso_sha_label.config(text="")
        self.iso_sha_result.config(text="", foreground="")

    def calculate_iso_sha256(self):
        path = self.iso_path.get()
        if not path or not os.path.isfile(path):
            self.iso_sha_result.config(text=_("Select an ISO file first."), foreground="#c62828")
            return
        try:
            expected = parse_expected_sha256(self.iso_sha_entry.get(), os.path.basename(path))
        except ValueError as e:
            self.iso_sha_result.config(text=str(e), foreground="#c62828")
            return
        self._sha_job += 1
        job = self._sha_job
        self.iso_sha_btn.config(state="disabled")
        self.iso_sha_progress.config(value=0)
        self.iso_sha_result.config(text="", foreground="")
        self.iso_sha_label.config(text=_("Calculating..."))
        self._show_sha_bar()
        self.log(_("Calculating SHA-256 of {name}...").format(name=os.path.basename(path)))
        last = [0.0]

        def progress(done, total):
            now = time.time()
            if done < total and now - last[0] < SHA_UI_INTERVAL:
                return  # ~10 UI updates per second is plenty
            last[0] = now
            self.after(0, self._on_iso_sha_progress, job, done, total)

        def worker():
            try:
                digest = sha256_file(path, progress=progress)
                self.after(0, self._on_iso_sha_done, job, path, digest, expected)
            except Exception as e:  # noqa: BLE001 - reported in the UI, never lost in the thread
                self.after(0, self._on_iso_sha_error, job, e)

        threading.Thread(target=worker, daemon=True).start()

    def _on_iso_sha_progress(self, job, done, total):
        if job != self._sha_job:
            return
        pct = done / total * 100 if total else 0
        self.iso_sha_progress.config(value=pct)
        self.iso_sha_label.config(text=_("Calculating... {pct:.0f}% ({done} / {total})").format(
            pct=pct, done=human_size(done), total=human_size(total)))

    def _on_iso_sha_done(self, job, path, digest, expected):
        if job != self._sha_job:
            return
        self.iso_sha_btn.config(state="normal")
        self.iso_sha_progress.config(value=100)
        self.iso_sha_label.config(text=_("SHA-256: {digest}").format(digest=digest))
        if expected is None:
            outcome, text, color = "unverified", _("No expected checksum given: compare the value above yourself."), ""
            outcome_label = _("UNVERIFIED")
        elif digest == expected:
            outcome, color = "match", "#1a7f37"
            text = _("MATCH — the file is intact and identical to the published one.")
            outcome_label = _("MATCH")
        else:
            outcome, color = "mismatch", "#c62828"
            text = _("MISMATCH — this is NOT the published file. Do not use it.")
            outcome_label = _("MISMATCH")
            self.log(_("Expected SHA-256: {expected}").format(expected=expected))
        self.iso_sha_result.config(text=text, foreground=color)
        self.after_idle(self._fit_window)  # the result lines can add height
        self.log(_("SHA-256 of {name}: {digest}").format(name=os.path.basename(path), digest=digest))
        self.log(_("Checksum comparison: {outcome}").format(outcome=outcome_label))
        audit(f"ISO SHA-256 check result={outcome}", logging.WARNING if outcome == "mismatch" else logging.INFO)

    def _on_iso_sha_error(self, job, exc):
        if job != self._sha_job:
            return
        self.iso_sha_btn.config(state="normal")
        self.iso_sha_label.config(text="")
        self.iso_sha_result.config(
            text=_("Could not read the file ({reason}).").format(reason=type(exc).__name__), foreground="#c62828")

    def confirm_erase(self, disk, what):
        """Final confirmation: always shows model, size and contents; high-risk drives also need
        their identifier typed. Returns True to go ahead."""
        level, reasons = assess_disk_risk(disk, translate=True)  # the level never depends on the language
        text = (_("This will PERMANENTLY ERASE all data on /dev/{id} and write {what} to it.").format(
                    id=disk["id"], what=what)
                + "\n\n" + describe_disk_for_confirmation(disk, translate=True))
        audit(f"Erase confirmation shown for /dev/{disk['id']} risk={level}")
        if level == "high":
            ok = ask_typed_confirmation(self, _("Confirm erasing this drive"), text, disk["id"], reasons)
        else:
            ok = messagebox.askyesno(_("Final confirmation"), text + "\n\n" + _("Continue?"))
        if not ok:
            audit(f"Erase of /dev/{disk['id']} declined by the user")
        return ok

    def start_create_usb(self):
        if self._creating:
            return  # a write (or its confirmation) is already in progress: never start a second one
        self._creating = True
        self._sync_controls()
        started = False
        try:
            started = bool(self._start_create_usb())
        finally:
            if not started:  # canceled or refused before the worker began
                self._creating = False
                self._sync_controls()
                self.update_create_button_state()

    def _start_create_usb(self):
        disk = self.selected_disk()
        if not disk:
            return
        mode = self.mode_var.get()
        missing = get_missing_dependencies(mode)
        if missing:  # the Create button is disabled in this case; this covers a stale button
            messagebox.showerror(
                _("Missing tools"),
                _("These tools are missing: {tools}. Click \"Install missing dependencies\" first. "
                  "Nothing was changed.").format(tools=", ".join(missing)))
            return
        disk_size = disk.get("size") or 0
        if disk_size <= 0:
            # An empty card reader reports 0 bytes. Never skip the size checks for it: refuse.
            messagebox.showerror(
                _("Unknown drive size"),
                _("The size of this drive could not be read (it reports 0 bytes). It may be an empty card "
                  "reader or a drive that is not ready. Nothing was changed."))
            return
        if not self._image_matches_choice(mode):
            return
        what = _image_label(mode, _("the selected Linux image"))
        if mode in RAW_MODES:
            try:
                image_size = os.path.getsize(self.iso_path.get())
            except OSError:
                image_size = 0
            if image_exceeds_drive(image_size, disk_size):
                messagebox.showerror(
                    _("Drive too small"),
                    _("The image ({image}) is larger than this drive ({drive}). Choose a bigger drive. "
                      "Nothing was changed.").format(image=human_size(image_size), drive=human_size(disk_size)))
                return
        if chromeos_drive_too_small(mode, disk_size) and not messagebox.askyesno(
                _("Small USB drive"),
                _("Google asks for a USB drive of 16 GB or larger for ChromeOS Flex, and this one is {size}. "
                  "It may not work as an installer.\n\nContinue anyway?").format(size=human_size(disk_size)),
                icon="warning"):
            return
        if not self.confirm_erase(disk, what):
            return
        # Bind the safety re-check (right before erasing) to exactly the drive that was confirmed.
        pin_target_identity(disk["id"], disk.get("identity"))
        # Writing the drive needs administrator rights (always on Linux; on macOS only for
        # the direct-write mode). Collect and verify the password now, before touching
        # the drive.
        if needs_admin(mode) and not self.priv.authenticate(
                _("Administrator access is required to write /dev/{id}.").format(id=disk["id"])):
            self.priv.clear_cached_password()
            self.log(_("Canceled: administrator password was not provided. The drive was not modified."))
            return
        self.create_cancel_event.clear()
        self.update_create_button_state()
        self.cancel_create_btn.config(state="normal")
        self.clear_error()
        self.clear_success()
        self._reset_create_progress()
        iso = self.iso_path.get()
        dev = disk["id"]
        expected_size = disk_size

        def worker():
            try:
                ejected = build_usb(iso, dev, self.log_threadsafe, self.priv,
                                    expected_size=expected_size, mode=mode,
                                    progress=lambda d, t, s: self._post(self._on_create_progress, d, t, s),
                                    cancel_event=self.create_cancel_event)
                self._post(self._finish_create_progress, True)
                self._post(self._show_create_success, ejected)
            except OperationCanceled as e:
                # Not an error: the user asked for it. Say clearly what state the drive is in.
                log_text, title, body = self._canceled_texts(getattr(e, "drive_touched", True), getattr(e, "written", False))
                self._post(self._finish_create_progress, False, True)
                self._post(self.log, log_text)
                self._post(self._notify, "info", title, body)
                if getattr(e, "drive_touched", True):  # the warning that the drive is not usable stays on screen
                    self._post(self.show_error, title, body)
            except (ValueError, RuntimeError) as e:
                # Expected, actionable failures: the message is written for the user.
                self._post(self._finish_create_progress, False)
                self._post(self._report_error, "Error", str(e))
            except Exception as e:
                # Unexpected failure: show a short message, keep the detail in the log
                # so internal paths and command lines are not surfaced in a dialog.
                self._post(self._finish_create_progress, False)
                self._post(self._report_error, "Unexpected error", None, e)
            finally:
                # The administrator password is no longer needed once the operation ends.
                self.priv.clear_cached_password()
                self._post(self._creation_ended)

        self._create_thread = threading.Thread(target=worker, daemon=True)
        self._create_thread.start()
        return True

    @staticmethod
    def _canceled_texts(drive_touched, written=False):
        """(log line, dialog title, dialog text) after a cancel. The engine says whether it had already
        started to change the drive (when it did not, the drive must not be called unusable) and
        whether the whole image had been written (canceled during the final check)."""
        if drive_touched and written:
            return (_("Canceled during verification. The image was written but NOT verified; do not rely "
                      "on this drive."),
                    _("Canceled"),
                    _("The operation was canceled during verification.\n\nThe image was written to the "
                      "drive but NOT verified, so do not rely on it. Create it again to verify it."))
        if drive_touched:
            return (_("Canceled. The drive was left unusable; create it again before use."),
                    _("Canceled"),
                    _("The operation was canceled.\n\nThe USB drive was left incomplete and "
                      "unusable. Create it again before using it."))
        return (_("Canceled. The drive was not modified."),
                _("Canceled"),
                _("The operation was canceled.\n\nThe USB drive was NOT modified."))

    def _show_create_success(self, ejected):
        """The write was verified: the inline panel replaces the old "Done" dialog. Without the eject the
        panel is amber and says the drive must be ejected by hand before it is unplugged."""
        if self._closing:
            return
        note = (_("It was verified against the ISO and ejected — you can unplug it now.") if ejected else
                _("It was verified against the ISO, but could not be ejected automatically. "
                  "Eject it from the file manager before unplugging."))
        self.show_success(_("Bootable USB drive created successfully!"), note, verified_and_ejected=bool(ejected))

    def _notify(self, kind, title, message):
        """An information dialog from a worker's result; skipped while the window is closing."""
        if self._closing:
            return
        (messagebox.showinfo if kind == "info" else messagebox.showerror)(title, message)

    def _creation_ended(self):
        """The write finished (or failed or was canceled): unlock the window and look at the drives
        again, because a drive that was ejected is no longer there."""
        self._creating = False
        self._create_thread = None
        self.cancel_create_btn.config(state="disabled")
        self._sync_controls()
        self.update_create_button_state()
        self.refresh_disks(quiet=True)

    def cancel_current(self):
        """The single Cancel button: stop whatever is running (the write, else a download or extraction)."""
        if self._creating:
            self.cancel_create_usb()
        elif self._download_running:
            self.cancel_download()
        elif self._flex_busy:
            self.cancel_flex()

    def cancel_create_usb(self):
        """Ask the running USB creation to stop (after a warning). Safe to call at any time."""
        if self.create_cancel_event.is_set() or str(self.cancel_create_btn.cget("state")) == "disabled":
            return
        if not messagebox.askyesno(
            _("Cancel the operation?"),
            _("Canceling now will leave the USB drive incomplete and UNUSABLE until it is created "
              "again.\n\nDo you really want to cancel?"),
            icon="warning",
        ):
            return
        self.create_cancel_event.set()
        self.cancel_create_btn.config(state="disabled")
        self.log(_("Cancel requested: stopping safely..."))
        audit("User requested cancel of the USB creation")

    # ---------- USB creation progress ----------
    def _reset_create_progress(self):
        self._create_started = None
        self._create_last_ui = 0.0
        self._create_stage = None
        self._create_stage_base = 0
        _pack_bar(self.create_progress, self.create_progress_label, pady=(10, 2))
        self.create_progress.config(mode="indeterminate", value=0)
        self.create_progress.start(12)
        self.create_progress_label.config(text=_("Preparing the drive..."))

    def _on_create_progress(self, done, total, text):
        text = _(text)  # the stage names come from the engine in English; same input, same output
        now = time.time()
        if not total:
            # Length unknown (e.g. comparing files): show a busy bar with what is going on.
            if str(self.create_progress.cget("mode")) != "indeterminate":
                self.create_progress.config(mode="indeterminate", value=0)
                self.create_progress.start(12)
            self.create_progress_label.config(text=_("{stage} (this can take a few minutes)").format(stage=text))
            self._create_stage = None
            return
        finished = done >= total
        # Updates can arrive thousands of times (one per copied file); redraw ~5x/s.
        if not finished and now - self._create_last_ui < PROGRESS_UI_INTERVAL:
            return
        self._create_last_ui = now
        if str(self.create_progress.cget("mode")) != "determinate":
            self.create_progress.stop()
            self.create_progress.config(mode="determinate")
        if text != self._create_stage:
            # New stage: measure speed and time left from where this stage began.
            self._create_stage = text
            self._create_started = now
            self._create_stage_base = done
        pct = done / total * 100
        self.create_progress.config(value=pct)
        if finished:
            self.create_progress_label.config(text=f"{text}  100%")
            return
        elapsed = max(now - self._create_started, 0.001)
        speed = (done - self._create_stage_base) / elapsed
        tail = _rate_tail(done, total, speed) or _(" — calculating...")
        self.create_progress_label.config(
            text=f"{text}  {pct:.1f}% — {human_size(done)} / {human_size(total)}{tail}")

    def _finish_create_progress(self, ok, canceled=False):
        self._flush_log()  # show the worker's last lines before the result dialog appears
        self.create_progress.stop()
        self.create_progress.config(mode="determinate", value=100 if ok else 0)
        if not ok:
            self.create_progress.pack_forget()  # an empty bar says nothing; the label below says what happened
            if not canceled:
                self.details_toggle.set_open(True)  # a failure: the log is what the user will want to read
        self.create_progress_label.config(
            text=_("Done — 100%") if ok else (_("Canceled.") if canceled else _("Failed.")))

    # ---------- closing the window ----------
    CLOSE_WAIT_SECONDS = 20  # how long a close waits for a canceled write to stop

    def _write_running(self):
        thread = self._create_thread
        return thread is not None and thread.is_alive()

    def _on_close(self):
        """The window's close button and Cmd-Q. A running write is never abandoned silently: closing
        asks first, then cancels it and waits (bounded, UI alive) for the worker to stop."""
        if self._closing:
            return
        if self._creating and self._create_thread is None:
            return  # a confirmation or password dialog is waiting for an answer: finish that first
        if self._write_running():
            if not messagebox.askyesno(
                _("Quit while writing?"),
                _("A USB drive is being written right now. Quitting cancels the operation and leaves "
                  "the drive incomplete and UNUSABLE until it is created again.\n\n"
                  "Cancel the operation and quit?"),
                icon="warning",
            ):
                return
            if self._write_running():  # it may have finished while the question was open
                self.create_cancel_event.set()
                self.cancel_create_btn.config(state="disabled")
                self.log(_("Cancel requested: stopping safely..."))
                audit("User closed the window during the USB creation: canceling it")
                if not self._wait_for_write(self.CLOSE_WAIT_SECONDS) and not messagebox.askyesno(
                    _("Still stopping"),
                    _("The operation is taking a while to stop. Quit anyway? The drive stays unusable "
                      "until it is created again."),
                    icon="warning",
                ):
                    return
        self._closing = True
        self.cancel_event.set()        # a Windows ISO download
        self.flex_cancel_event.set()   # a ChromeOS Flex download or extraction
        self.destroy()

    def _wait_for_write(self, seconds):
        """Keep the window responsive until the write worker ends or `seconds` pass. True if it ended.

        Dialogs from the worker are suppressed meanwhile (`_closing`), so nothing can block the wait."""
        self._closing = True
        try:
            deadline = time.monotonic() + seconds
            while self._write_running() and time.monotonic() < deadline:
                try:
                    self.update()
                except tk.TclError:
                    break
                time.sleep(0.05)
        finally:
            self._closing = False
        return not self._write_running()

    def report_callback_exception(self, exc, val, tb):
        """Tk swallows exceptions raised in button handlers (they only reach stderr).
        Show them, so a broken button never looks like "nothing happened"."""
        self._report_error("Unexpected error", None, val)

    def _report_error(self, title, message, exc=None, modal=True, retry=None):
        """Show a user-facing error without leaking internals into the dialog.

        `title` is the English text (it also goes to the audit log); the dialog shows it translated.
        A `message` given by the caller (an engine error) is shown as it is.

        The red banner under the Create row always shows it (with "Try again" when `retry` is given).
        The modal dialog is also shown unless `modal=False`: a failed write or verification keeps it (the
        drive's state matters); downloads, extractions, drive listings and tool installs use the banner only.
        """
        if self._closing:  # no dialog while the window is going away; the log and the audit trail keep it
            self.log(f"ERROR: {message}" if exc is None else f"ERROR [{type(exc).__name__}]: {exc}")
            return
        if exc is not None:
            self.log(f"ERROR [{type(exc).__name__}]: {exc}")
            audit(f"{title}: {type(exc).__name__}", logging.ERROR)
            message = _(
                "The operation could not be completed.\n\n"
                "Reason: {reason}\n\n"
                "The full technical detail was written to the log box below and to the "
                "audit log at:\n{path}"
            ).format(reason=type(exc).__name__, path=audit_log_path())
        else:
            self.log(f"ERROR: {message}")
        self.show_error(_(title), message, retry=retry)
        if modal:
            messagebox.showerror(_(title), message)


# ============================================================
# ===== Command line interface =====
#
#   epma-usb-creator                 open the GUI (same as `epma-usb-creator gui`)
#   epma-usb-creator list            list the USB drives that can be written
#   epma-usb-creator detect ISO      windows / linux / unknown
#   epma-usb-creator sha256 ISO      checksum, optionally compared with --expected
#   epma-usb-creator write ...       create the bootable drive
#
# Data goes to stdout; messages, errors and progress go to stderr. Verification
# of the written drive is part of `write` and cannot be switched off.
# ============================================================
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_VERIFY_FAILED = 3     # the drive does not match the ISO, or the checksum differs
EXIT_EJECT_FAILED = 4      # written and verified, but the drive could not be ejected
EXIT_INTERRUPTED = 130     # Ctrl-C

CLI_PROG = APP_NAME
# Engine log lines worth showing without --verbose (everything else is command output).
CLI_MILESTONE_RE = re.compile(
    r"warning|error|fail|verif|eject|done!|safety re-check|erasing|writing the iso|copying|"
    r"splitting|mounting|syncing|note:|could not|aborted", re.IGNORECASE)


class CliError(Exception):
    """A failure the command line reports as a plain message with an exit code."""

    def __init__(self, message, code=EXIT_ERROR):
        super().__init__(message)
        self.message = message
        self.code = code


def _emit(stream, text, end="\n"):
    try:
        stream.write(text + end)
    except UnicodeEncodeError:  # e.g. LANG=C: the "—" in disk labels cannot be encoded
        enc = getattr(stream, "encoding", None) or "ascii"
        stream.write((text + end).encode(enc, "replace").decode(enc, "replace"))
    with contextlib.suppress(OSError, ValueError):
        stream.flush()


def _out(text=""):
    _emit(sys.stdout, text)


def _err(text=""):
    _emit(sys.stderr, text)


def _use_color(stream):
    if os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False
    isatty = getattr(stream, "isatty", None)
    return bool(isatty and isatty())


def _style(stream, text, code):
    return f"\033[{code}m{text}\033[0m" if _use_color(stream) else text


def _error(message):
    _err(f"{_style(sys.stderr, 'error:', '1;31')} {message}")


def _warn(message):
    _err(f"{_style(sys.stderr, 'warning:', '33')} {message}")


class CliProgress:
    """Progress sink for the engine: one updating line on a terminal, periodic lines otherwise."""

    def __init__(self, stream=None, clock=time.monotonic):
        self.stream = stream if stream is not None else sys.stderr
        isatty = getattr(self.stream, "isatty", None)
        self.tty = bool(isatty and isatty())
        self.interval = 0.25 if self.tty else 10.0
        self.clock = clock
        self._text = None
        self._base = 0
        self._stage_start = 0.0
        self._last = None
        self._width = 0
        self._open = False

    def _format(self, done, total, text, now):
        if not total:
            return text
        pct = min(done / total * 100, 100.0)
        line = f"{text}  {pct:5.1f}%  {human_size(done)} / {human_size(total)}"
        elapsed = now - self._stage_start
        if elapsed >= 1.0 and done > self._base:
            speed = (done - self._base) / elapsed
            line += f"  {human_size(speed)}/s  {_eta_remaining(done, total, speed, translate=False)}"
        return line

    def __call__(self, done, total, text):
        now = self.clock()
        changed = text != self._text
        if changed:
            self._text, self._base, self._stage_start = text, done, now
        final = bool(total) and done >= total
        if not (changed or final) and self._last is not None and now - self._last < self.interval:
            return
        self._last = now
        line = self._format(done, total, text, now)
        if self.tty:
            self._width = max(self._width, len(line))
            _emit(self.stream, "\r" + line.ljust(self._width), end="")
            self._open = True
        else:
            _emit(self.stream, line)

    def clear(self):
        """Wipe the progress line so a log message can be printed in its place."""
        if self._open:
            _emit(self.stream, "\r" + " " * self._width + "\r", end="")
            self._open = False

    def finish(self):
        if self._open:
            _emit(self.stream, "")
            self._open = False


class CliLogger:
    """Log sink for the engine: milestones always, everything with --verbose."""

    def __init__(self, progress, verbose=False):
        self.progress = progress
        self.verbose = verbose
        self.recent = collections.deque(maxlen=20)

    def __call__(self, line):
        line = str(line).rstrip()
        if not line:
            return
        self.recent.append(line)
        if self.verbose or (CLI_MILESTONE_RE.search(line) and not line.startswith("$ ")):
            self.progress.clear()
            _err(line)

    def dump_recent(self):
        if self.verbose or not self.recent:
            return
        _err("Last log lines:")
        for line in self.recent:
            _err("  " + line)


class CliPrivilege:
    """Privilege helper for the command line, duck-typed to what the engine uses.

    Unlike the GUI's PrivilegeHelper it never handles the administrator credential
    itself: sudo asks on the controlling terminal. Scripts are run once and never
    retried; a failure is reported as it is.
    """

    def __init__(self):
        self.cached_password = None  # always None: sudo owns the credential
        self._stop = threading.Event()
        self._thread = None

    @staticmethod
    def is_root():
        return os.geteuid() == 0

    def authenticate(self):
        """Ask sudo for credentials up front, before anything touches the drive."""
        if self.is_root():
            return
        if not shutil.which("sudo"):
            raise RuntimeError("Administrator privileges are required but 'sudo' was not found. "
                               "Run this command as root or install sudo.")
        # stdin/stdout/stderr are inherited, so sudo prompts on the terminal.
        if subprocess.call(["sudo", "-v"]) != 0:
            raise RuntimeError("Could not obtain administrator privileges (sudo refused). "
                               "Nothing was changed.")
        self._start_keepalive()

    def _start_keepalive(self):
        # Writing and verifying a large image can outlast sudo's credential cache.
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=_sudo_refresh_loop, args=(self._stop,), daemon=True)
        self._thread.start()

    def clear_cached_password(self):
        self.cached_password = None
        self._stop.set()

    def run_script(self, script, log, args=None, **_kw):
        """Run `script` as root once. Values arrive only as "$1".. arguments."""
        args = [str(a) for a in (args or [])]
        argv = ["bash", "-c", script, "win11_usb_creator"] + args
        if not self.is_root():
            argv = ["sudo"] + argv
        log(("$ sudo " if not self.is_root() else "$ ") + "bash -c '<privileged script>' "
            + " ".join(repr(a) for a in args))
        with subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, errors="replace", bufsize=1) as proc:
            try:
                for line in proc.stdout:
                    log(line.rstrip())
            except BaseException:
                with contextlib.suppress(OSError):
                    proc.terminate()
                raise
        if proc.returncode != 0:
            audit(f"Privileged script failed (exit {proc.returncode})", logging.ERROR)
            raise RuntimeError(f"Privileged command failed (exit code {proc.returncode}). "
                               "Check the messages above.")


def cli_sha256_file(path, progress=None, chunk=SHA256_CHUNK):
    """sha256_file() reporting (done, total, text) to `progress`, the shape CliProgress takes."""
    return sha256_file(path, chunk=chunk,
                       progress=(lambda done, total: progress(done, total, "Computing SHA-256...")) if progress
                       else None)


def cli_detect_kind(iso_path):
    """Return (kind, method): kind is one of the ISO_KIND_* values (windows, linux, chromeos or unknown).

    Uses detect_iso_kind() (reads the ISO), then the hybrid-image boot signature. The FILE NAME is never
    used: a guess from the name could select the destructive Windows mode for an unrelated image
    ("darwin-linux.img" contains "win"), so content that cannot be recognised stays "unknown" and the
    user must pass --mode.
    """
    kind = detect_iso_kind(iso_path)  # never raises
    if kind in KIND_MODE:
        return kind, "content"
    try:
        validate_hybrid_iso(iso_path)
        return ISO_KIND_LINUX, "boot-signature"
    except (ValueError, OSError):
        return KIND_UNKNOWN, "none"


def _is_interactive():
    return bool(sys.stdin and sys.stdin.isatty() and sys.stderr.isatty())


def _is_verification_failure(exc):
    """True for the engine's "Verification FAILED" / "could not complete the verification" errors."""
    text = str(exc).lower()
    return "verification failed" in text or "could not complete the verification" in text


def _disk_summary(disk):
    info = {k: v for k, v in disk.items() if v is None or isinstance(v, (str, int, float, bool))}
    info["size_human"] = human_size(disk.get("size") or 0)
    return info


def _write_steps(mode, disk_id, eject):
    steps = [f"Re-check that /dev/{disk_id} is still the listed USB drive"]
    if mode in RAW_MODES:
        steps += [f"Unmount /dev/{disk_id} and write the image to it byte for byte",
                  "Read the drive back and compare it with the image"]
    else:
        steps += [f"Erase /dev/{disk_id} and format it as GPT + FAT32 ('{VOL_NAME}')",
                  "Copy the ISO contents (install.wim is split when it exceeds 4 GB)",
                  "Verify the copied files against the ISO"]
    steps.append("Eject the drive" if eject else "Leave the drive connected (--no-eject)")
    return steps


def _print_plan(plan, to_stdout):
    disk = plan["disk"]
    emit = _out if to_stdout else _err
    emit("Plan")
    emit(f"  Disk : /dev/{disk['id']}  {disk.get('size_human', '')}  {disk.get('label', '')}".rstrip())
    if disk.get("model"):
        emit(f"  Model: {disk['model']}")
    emit(f"  ISO  : {plan['iso']} ({human_size(plan['iso_size'])})")
    emit(f"  Mode : {plan['mode']}")
    emit("  Steps:")
    for i, step in enumerate(plan["steps"], 1):
        emit(f"    {i}. {step}")


def _list_disks():
    """get_external_disks() with a failure turned into the command line's CliError."""
    try:
        return get_external_disks()
    except Exception as e:
        raise CliError(f"Could not list the drives: {e}") from None


# ---------- commands ----------
def cmd_list(args):
    disks = _list_disks()
    if args.json:
        _out(json.dumps({"disks": [_disk_summary(d) for d in disks]}, indent=2, default=str))
        return EXIT_OK
    if not disks:
        _err("No USB drives found. Plug one in and try again.")
        return EXIT_OK
    has_model = any(d.get("model") for d in disks)
    header = ["ID", "SIZE"] + (["MODEL"] if has_model else []) + ["LABEL"]
    rows = [[d["id"], human_size(d.get("size") or 0)] + ([str(d.get("model") or "")] if has_model else [])
            + [str(d.get("label", ""))] for d in disks]
    widths = [max(len(r[i]) for r in [header] + rows) for i in range(len(header))]
    for row in [header] + rows:
        _out("  ".join(c.ljust(widths[i]) for i, c in enumerate(row)).rstrip())
    return EXIT_OK


def cmd_detect(args):
    iso = resolve_path(args.iso)
    if not os.path.isfile(iso):
        raise CliError(f"Not a file: {iso}")
    kind, method = cli_detect_kind(iso)
    if args.json:
        _out(json.dumps({"iso": iso, "kind": kind, "method": method}, indent=2))
    else:
        _out(kind)
    return EXIT_OK


def cmd_sha256(args):
    expected = None
    if args.expected:
        expected = args.expected.strip().lower()
        if expected.startswith("sha256:"):
            expected = expected[len("sha256:"):]
        if not is_sha256_hex(expected):
            raise CliError("--expected must be a 64-character hexadecimal SHA-256 value.", EXIT_USAGE)
    iso = resolve_path(args.iso)
    if not os.path.isfile(iso):
        raise CliError(f"Not a file: {iso}")
    progress = CliProgress()
    try:
        digest = cli_sha256_file(iso, progress)
    except OSError as e:
        progress.finish()
        raise CliError(f"Could not read {iso}: {e.strerror or e}") from None
    progress.finish()
    match = None if expected is None else (digest == expected)
    if args.json:
        _out(json.dumps({"file": iso, "sha256": digest, "expected": expected, "match": match}, indent=2))
    else:
        _out(f"{digest}  {iso}")
    if match is False:
        _error(f"The checksum does not match.\n  expected: {expected}\n  actual:   {digest}")
        return EXIT_VERIFY_FAILED
    if match:
        _err("Checksum matches.")
    return EXIT_OK


def download_file_blocking(url, dest, progress=None, cancel_event=None):
    """Run DownloadThread to completion in the calling thread; return the SHA-256 of the file.

    Raises RuntimeError with the user-facing reason when the download fails.
    """
    result = {}

    def on_done(_path, sha256, _verified):
        result["sha256"] = sha256

    def on_error(message):
        result["error"] = message

    worker = DownloadThread(url, dest, progress_cb=(lambda d, t, _s: progress(d, t, "Downloading")) if progress
                            else (lambda *_a: None),
                            done_cb=on_done, error_cb=on_error,
                            cancel_event=cancel_event or threading.Event(),
                            allowed_hosts=CHROMEOS_FLEX_HOSTS if url == CHROMEOS_FLEX_URL else None)
    worker.start()
    worker.join()
    if "error" in result:
        raise RuntimeError(result["error"])
    return result["sha256"]


def cmd_fetch_chromeos(args):
    """Download ChromeOS Flex from Google and extract the disk image (nothing is written to a drive)."""
    dest_dir = resolve_path(args.dest or ".")
    if not os.path.isdir(dest_dir):
        raise CliError(f"Not a folder: {dest_dir}")
    zip_path = os.path.join(dest_dir, "chromeos_flex_latest.bin.zip")
    # A complete ZIP from an earlier run (the download finished, the extraction did not) is
    # extracted again instead of being downloaded again; an unfinished ".part" is resumed.
    reuse_zip = os.path.exists(zip_path) and not os.path.exists(zip_path + ".part")
    _err("ChromeOS Flex is provided by Google under Google's own terms: "
         f"{CHROMEOS_FLEX_GUIDE_URL}")
    free = shutil.disk_usage(dest_dir).free
    if free < CHROMEOS_FLEX_FREE_BYTES:
        _warn(f"Downloading and extracting needs roughly {human_size(CHROMEOS_FLEX_FREE_BYTES)} free; "
              f"{human_size(free)} is available in {dest_dir}.")
    progress = CliProgress()
    try:
        if reuse_zip:
            _err(f"{zip_path} is already there: extracting it again instead of downloading it. "
                 "(Remove that file to download a fresh copy.)")
            sha256 = cli_sha256_file(zip_path, progress)
        else:
            sha256 = download_file_blocking(CHROMEOS_FLEX_URL, zip_path, progress)
        image = extract_disk_image(zip_path, dest_dir, progress=lambda d, t: progress(d, t, "Extracting"))
    except (RuntimeError, ValueError, OSError) as e:
        progress.finish()
        message = str(e)
        if os.path.exists(zip_path) and not os.path.exists(zip_path + ".part"):
            message += (f"\n\nThe downloaded file was kept: {zip_path}\nFix the problem (for example free up "
                        f"space) and run '{CLI_PROG} fetch-chromeos' again to extract it, or remove the file "
                        "to download it afresh.")
        raise CliError(message) from None
    progress.finish()
    # A ZIP that was already there is the user's to keep; only one downloaded now is removed.
    keep_zip = bool(args.keep_zip) or reuse_zip
    if not keep_zip:
        _silent_remove(zip_path)
    if args.json:
        _out(json.dumps({"image": image, "zip_sha256": sha256, "kept_zip": keep_zip}, indent=2))
    else:
        _out(image)
    _err(f"Done. Write it with: {CLI_PROG} write --iso {image} --disk <DISKID> --mode chromeos")
    return EXIT_OK


def _prepare_write(args):
    """Validate everything and build the plan. Raises CliError; touches nothing."""
    try:
        iso = validate_iso_path(args.iso)
        disk_id = validate_device_name(normalize_typed_identifier(args.disk))
    except ValueError as e:
        raise CliError(str(e)) from None
    disks = _list_disks()
    disk = next((d for d in disks if d.get("id") == disk_id), None)
    if disk is None:
        raise CliError(f"/dev/{disk_id} is not an eligible USB drive. "
                       f"Run '{CLI_PROG} list' to see the drives that can be written.")
    mode = args.mode
    detected, _method = cli_detect_kind(iso)
    detected_mode = KIND_MODE.get(detected)
    if mode == MODE_AUTO:
        if detected_mode is None:
            raise CliError("Could not tell what kind of image this is. "
                           "Pass --mode windows, --mode linux or --mode chromeos.", EXIT_USAGE)
        mode = detected_mode
    elif detected_mode is not None and detected_mode != mode:
        _warn(f"This ISO looks like a {detected} image but --mode {mode} was requested.")
    iso_size = os.path.getsize(iso)
    size = disk.get("size") or 0
    if mode in RAW_MODES:
        try:
            (validate_disk_image if mode == MODE_CHROMEOS else validate_hybrid_iso)(iso)
        except ValueError as e:
            raise CliError(str(e)) from None
        if chromeos_drive_too_small(mode, size):
            _warn(f"Google asks for a USB drive of 16 GB or larger for ChromeOS Flex; this one is "
                  f"{human_size(size)}.")
    if image_exceeds_drive(iso_size, size):
        # A raw write needs the whole image; the copy of a Windows ISO holds at least its contents.
        raise CliError(f"The ISO ({human_size(iso_size)}) is larger than the drive ({human_size(size)}).")
    missing = get_missing_dependencies(mode)
    if missing:
        raise CliError("Missing required tools: " + ", ".join(missing) + ". " + missing_dependencies_hint(missing))
    eject = not args.no_eject
    # The identity (serial, WWN, ...) is a tuple of pairs, so _disk_summary leaves it out; keep it here
    # so the safety re-check can compare the drive that is erased with the one that was listed.
    return {"iso": iso, "iso_size": iso_size, "mode": mode, "disk": _disk_summary(disk),
            "identity": tuple(disk.get("identity") or ()),
            "steps": _write_steps(mode, disk_id, eject), "eject": eject, "dry_run": bool(args.dry_run)}


def _confirm_write(args, plan):
    """Return normally only when the user has agreed to erase the drive."""
    if args.yes:
        return
    disk_id = plan["disk"]["id"]
    if not _is_interactive():
        raise CliError("Refusing to erase a drive without confirmation: this is not an interactive "
                       "terminal. Review the plan with --dry-run, then pass --yes.", EXIT_USAGE)
    _err(f"\nThis will PERMANENTLY ERASE all data on /dev/{disk_id}.")
    _emit(sys.stderr, f"Type the disk id ({disk_id}) to confirm: ", end="")
    answer = sys.stdin.readline().strip()
    if answer != disk_id:
        raise CliError("The confirmation did not match. Nothing was changed.", EXIT_USAGE)


def _run_write(args, plan, result):
    needs_priv = needs_admin(plan["mode"])
    priv = CliPrivilege()
    progress = CliProgress()
    log = CliLogger(progress, verbose=args.verbose)
    cancel = threading.Event()
    state = {"interrupted": False}

    def on_sigint(_signum, _frame):
        if state["interrupted"]:
            raise KeyboardInterrupt
        state["interrupted"] = True
        cancel.set()
        _err("\nInterrupted: finishing safely (unmounting) - press Ctrl-C again to force quit.")

    try:
        previous = signal.signal(signal.SIGINT, on_sigint)
    except ValueError:  # not the main thread
        previous = None
    started = time.time()
    audit(f"CLI write requested: /dev/{plan['disk']['id']} mode={plan['mode']}")
    ejected, failure = None, None
    try:
        if needs_priv:
            priv.authenticate()
        # Bind the safety re-check (right before erasing) to exactly the drive that was planned.
        pin_target_identity(plan["disk"]["id"], plan.get("identity"))
        ejected = build_usb(plan["iso"], plan["disk"]["id"], log, priv,
                            expected_size=plan["disk"].get("size"), mode=plan["mode"],
                            progress=progress, eject=plan["eject"], cancel_event=cancel)
    except KeyboardInterrupt as e:
        state["interrupted"] = True
        failure = e
    except Exception as e:
        failure = e
        if args.debug:
            progress.clear()
            traceback.print_exc()
    finally:
        progress.finish()
        priv.clear_cached_password()
        pin_target_identity(plan["disk"]["id"], None)  # never leave a pin behind (build_usb normally consumes it)
        if previous is not None:
            signal.signal(signal.SIGINT, previous)
    result["elapsed_seconds"] = round(time.time() - started, 1)

    if failure is None:
        result.update(ok=True, verified=True, ejected=bool(ejected))
        if not plan["eject"]:
            _err("Done. The drive was written and verified; it was left connected (--no-eject).")
            return EXIT_OK
        if ejected:
            _err("Done. The drive was written, verified and ejected - you can unplug it now.")
            return EXIT_OK
        _error("The drive was written and verified, but it could not be ejected. "
               "Eject it from the file manager before unplugging.")
        result["error"] = "eject failed"
        return EXIT_EJECT_FAILED

    if state["interrupted"]:
        result["error"] = "interrupted"
        _error("Interrupted. The drive may be partially written and must not be used.")
        return EXIT_INTERRUPTED
    result["error"] = str(failure)
    if _is_verification_failure(failure):
        _error(str(failure))
        return EXIT_VERIFY_FAILED
    if isinstance(failure, (ValueError, RuntimeError)):
        _error(str(failure))
    else:
        _error(f"Unexpected failure ({type(failure).__name__}): {failure}")
    log.dump_recent()
    return EXIT_ERROR


def cmd_write(args):
    result = {"ok": False, "mode": None, "iso": None, "disk": None, "verified": False,
              "ejected": False, "error": None, "exit_code": EXIT_ERROR}
    try:
        plan = _prepare_write(args)
        result.update(mode=plan["mode"], iso=plan["iso"], disk=plan["disk"]["id"])
        if args.dry_run:
            if args.json:
                # The identity is a tuple of (key, value) pairs: show it as an object.
                _out(json.dumps({**plan, "identity": dict(plan["identity"])}, indent=2, default=str))
            else:
                _print_plan(plan, to_stdout=True)
                _err("Dry run: nothing was changed.")
            return EXIT_OK
        _print_plan(plan, to_stdout=False)
        _confirm_write(args, plan)
        code = _run_write(args, plan, result)
    except CliError as e:
        result.update(error=e.message, exit_code=e.code)
        if args.json:
            _out(json.dumps(result, indent=2))
        raise
    result["exit_code"] = code
    if args.json:
        _out(json.dumps(result, indent=2))
    return code


COMMANDS = {"list": cmd_list, "detect": cmd_detect, "sha256": cmd_sha256, "write": cmd_write,
            "fetch-chromeos": cmd_fetch_chromeos}


# What `--help` says about exit codes and environment variables. Both lists are written out here,
# next to the constants, and tests/test_docs_consistency.py fails when an EXIT_* or ENV_*
# constant is missing from them, so --help cannot fall behind the code.
CLI_EXIT_CODE_HELP = (
    (EXIT_OK, "success"),
    (EXIT_ERROR, "error"),
    (EXIT_USAGE, "usage error (also: confirmation missing, ISO kind unknown)"),
    (EXIT_VERIFY_FAILED, "verification failed / checksum mismatch"),
    (EXIT_EJECT_FAILED, "written and verified, but the drive could not be ejected"),
    (EXIT_INTERRUPTED, "interrupted (Ctrl-C)"),
)
CLI_ENV_HELP = (
    (ENV_AUDIT_LOG, "path of the audit log"),
    (ENV_DISABLE_AUDIT_LOG, "1 = do not write the audit log"),
    (ENV_TRUSTED_HOSTS, "comma-separated trusted download hosts (replaces the Microsoft list)"),
    (ENV_ALLOW_ANY_HOST, "1 = no warning for unrecognised download servers (lowers security)"),
    (ENV_EXPECTED_SHA256, "expected SHA-256 pre-filled in the window (window only)"),
    (ENV_LANG, "pt = Portuguese window (the command line is always English)"),
    ("NO_COLOR", "disable colored messages"),
)


def cli_epilog():
    """The text under `--help`: exit codes and environment variables, built from the constants."""
    codes = "\n".join(f"  {code:<4} {meaning}" for code, meaning in CLI_EXIT_CODE_HELP)
    env = "\n".join(f"  {name:<34} {meaning}" for name, meaning in CLI_ENV_HELP)
    return (f"exit codes:\n{codes}\n\n"
            f"environment (all optional):\n{env}\n\n"
            "Data is written to stdout; messages, errors and progress to stderr.\n"
            "The written drive is always read back and compared with the ISO.")


def build_cli_parser():
    common = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    common.add_argument("--debug", action="store_true", default=argparse.SUPPRESS,
                        help="show Python tracebacks for unexpected errors")
    parser = argparse.ArgumentParser(
        prog=CLI_PROG, allow_abbrev=False,
        description=f"{APP_TAGLINE}.\nRun without arguments to open the graphical interface.",
        epilog=cli_epilog(),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=f"{CLI_PROG} {__version__}")
    parser.add_argument("--debug", action="store_true", help="show Python tracebacks for unexpected errors")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    def add(name, help_text, **kw):
        return sub.add_parser(name, help=help_text, description=help_text, parents=[common],
                              allow_abbrev=False, **kw)

    add("gui", "open the graphical interface (the default with no arguments)")
    p = add("list", "list the USB drives that can be written")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p = add("detect", "tell whether an image is windows, linux or chromeos (or unknown)")
    p.add_argument("iso", metavar="ISO")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p = add("sha256", "compute the SHA-256 of a file, optionally comparing it with a known value")
    p.add_argument("iso", metavar="ISO")
    p.add_argument("--expected", metavar="HASH", help="expected SHA-256; exit code 3 if it differs")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p = add("fetch-chromeos", "download ChromeOS Flex from Google and extract the disk image (does not write a drive)")
    p.add_argument("--dest", metavar="DIR", help="folder for the image (default: the current folder)")
    p.add_argument("--keep-zip", action="store_true", help="keep latest.bin.zip after extracting it")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p = add("write", "write an ISO or disk image to a USB drive, verify it and eject",
            epilog="The drive is ERASED. Use --dry-run first to see the plan without changing anything.")
    p.add_argument("--iso", required=True, metavar="ISO",
                   help="path of the ISO or disk image (.bin for ChromeOS Flex; use fetch-chromeos to get it)")
    p.add_argument("--disk", required=True, metavar="DISKID",
                   help="drive id as shown by 'list' (disk4 on macOS, sdb on Linux)")
    p.add_argument("--mode", choices=[MODE_AUTO, *ALL_MODES], default=MODE_AUTO,
                   help="windows: GPT+FAT32 file copy; linux: raw write of a hybrid ISO; "
                        "chromeos: raw write of a ChromeOS Flex disk image; auto: detect (default)")
    p.add_argument("--yes", action="store_true",
                   help="do not ask for confirmation (required when not in an interactive terminal)")
    p.add_argument("--dry-run", action="store_true", help="print the plan and exit without touching anything")
    p.add_argument("--no-eject", action="store_true", help="leave the drive connected when done")
    p.add_argument("--json", action="store_true", help="machine-readable result on stdout")
    p.add_argument("-v", "--verbose", action="store_true", help="show every engine log line")
    return parser


def _run_gui():
    if tk is None:
        _err(TK_MISSING_MESSAGE)
        return EXIT_ERROR
    App().mainloop()
    return EXIT_OK


def main(argv=None):
    """Entry point. Returns the process exit code (see the exit codes in --help)."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        command, args = "gui", None
    else:
        try:
            args = build_cli_parser().parse_args(argv)
        except SystemExit as e:  # --help / --version (0) or a usage error (2)
            return e.code if isinstance(e.code, int) else (EXIT_OK if e.code is None else EXIT_USAGE)
        command = args.command or "gui"
    if command in ("gui", "list", "write") and not (IS_MAC or IS_LINUX):
        _err("This script supports macOS and Linux only.")
        return EXIT_ERROR
    debug = bool(getattr(args, "debug", False))
    try:
        if command == "gui":
            return _run_gui()
        return COMMANDS[command](args)
    except CliError as e:
        _error(e.message)
        return e.code
    except KeyboardInterrupt:
        _err("Interrupted.")
        return EXIT_INTERRUPTED
    except BrokenPipeError:
        with contextlib.suppress(Exception):
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return EXIT_OK
    except Exception as e:
        if debug:
            traceback.print_exc()
        _error(str(e) if isinstance(e, (ValueError, RuntimeError, OSError))
               else f"Unexpected failure ({type(e).__name__}): {e}")
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
