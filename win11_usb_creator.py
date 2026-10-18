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
SEED_WINDOWS = "windows"  # Windows 11: a seed drive with harden.cmd / harden.ps1 (and, optionally, an answer file)
SEED_TARGETS = (SEED_UBUNTU, SEED_FEDORA, SEED_DEBIAN, SEED_WINDOWS)

# What detect_iso_kind() finds in an image. The strings are what `detect` prints; KIND_MODE says which
# mode writes each kind (the two sets of names are kept apart on purpose, whatever their spelling).
ISO_KIND_WINDOWS = "windows"
ISO_KIND_LINUX = "linux"
ISO_KIND_CHROMEOS = "chromeos"
ISO_KIND_UNKNOWN = "unknown"
KIND_UNKNOWN = ISO_KIND_UNKNOWN
KIND_MODE = {ISO_KIND_WINDOWS: MODE_WINDOWS, ISO_KIND_LINUX: MODE_LINUX, ISO_KIND_CHROMEOS: MODE_CHROMEOS}

# The choices at the top of the window ("cards"), and how each one writes the drive. Four of them are image
# types; the fifth, "Hardening seed", needs no image: it makes a second, small drive with auto-install files.
CARD_CHROME, CARD_WINDOWS, CARD_LINUX, CARD_OTHER = "chrome", "windows", "linux", "other"
CARD_SEED = "seed"
CARD_ORDER = (CARD_CHROME, CARD_WINDOWS, CARD_LINUX, CARD_OTHER, CARD_SEED)
CARD_MODE = {CARD_CHROME: MODE_CHROMEOS, CARD_WINDOWS: MODE_WINDOWS, CARD_LINUX: MODE_LINUX, CARD_OTHER: MODE_LINUX,
             CARD_SEED: MODE_SEED}
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
    # ===== hardening: GUI =====
    "Hardening seed": "Kit de reforço",
    "Auto-install files": "Instalação automática",
    "Add hardening settings to the Windows installation (optional)": "Adicionar ajustes de segurança à instalação do Windows (opcional)",
    "Adds a few files to the same drive. A script applies the settings at the END of Windows setup and writes its log to {log}.": "Adiciona alguns arquivos ao mesmo pendrive. Um script aplica os ajustes no FINAL da instalação do Windows e grava o log em {log}.",
    "What does it change?": "O que isto altera?",
    "Hide the list": "Ocultar a lista",
    "The settings are applied at the end of Windows setup by a script, and every change is written to {log}. You choose the disk, the account and the edition during setup as usual.": "Os ajustes são aplicados no final da instalação do Windows por um script, e cada alteração é registrada em {log}. Você escolhe o disco, a conta e a edição durante a instalação, como de costume.",
    "Makes a SECOND, small USB drive (not the installer) that carries settings for a hardened Linux install or a hardened Windows 11. For Linux, write the installer to its own drive with the Linux card, then plug both drives into the computer you install on. The files never choose or erase a disk on that computer: you still pick the disk and create the account yourself. No image file is needed; writing this drive ERASES it. The Windows scripts were never run on a real Windows computer: try them on a test machine first.": "Cria um SEGUNDO pendrive, pequeno (não é o instalador), com ajustes para uma instalação reforçada do Linux ou do Windows 11. Para o Linux, grave o instalador no pendrive dele com o cartão Linux e depois conecte os dois pendrives ao computador onde vai instalar. Os arquivos nunca escolhem nem apagam um disco desse computador: você continua escolhendo o disco e criando a conta. Não é preciso nenhum arquivo de imagem; gravar este pendrive o APAGA. Os scripts do Windows nunca foram executados em um Windows real: teste-os primeiro em um computador de teste.",
    "Windows 11 (run after install)": "Windows 11 (executar depois de instalar)",
    "Windows 11 (during setup, experimental)": "Windows 11 (durante a instalação, experimental)",
    "Run harden.cmd as administrator on a Windows 11 that is already installed; audit.cmd shows a report first, undo.cmd goes back.": "Execute o harden.cmd como administrador em um Windows 11 já instalado; o audit.cmd mostra primeiro um relatório e o undo.cmd desfaz.",
    "EXPERIMENTAL, never tested on real Windows.": "EXPERIMENTAL, nunca testado em um Windows real.",
    "the hardening seed files (experimental: includes an answer file for Windows Setup)": "os arquivos do kit de reforço (experimental: inclui um arquivo de resposta para a Instalação do Windows)",
    "The files were checked on the drive and it was ejected — you can unplug it now.": "Os arquivos foram conferidos no pendrive e ele foi ejetado — você já pode removê-lo.",
    "The files were checked on the drive, but it could not be ejected automatically. Eject it from the file manager before unplugging.": "Os arquivos foram conferidos no pendrive, mas ele não pôde ser ejetado automaticamente. Ejete-o pelo gerenciador de arquivos antes de removê-lo.",
    "Windows 11 setup drive (experimental) created and verified": "Pendrive de instalação do Windows 11 (experimental) criado e verificado",
    "Windows 11 hardening drive created and verified": "Pendrive de reforço do Windows 11 criado e verificado",
    "EXPERIMENTAL: plug it in next to the Windows installer USB drive BEFORE Windows Setup starts; Setup then reads the answer file (autounattend.xml) on it. An invalid answer file can stop an installation, and the scripts were never run on real Windows: try it on a test machine first. harden.cmd, audit.cmd and undo.cmd are on the drive as well.": "EXPERIMENTAL: conecte-o junto com o pendrive instalador do Windows ANTES de a Instalação do Windows começar; a Instalação lê então o arquivo de resposta (autounattend.xml) que está nele. Um arquivo de resposta inválido pode interromper uma instalação, e os scripts nunca foram executados em um Windows real: teste primeiro em um computador de teste. O harden.cmd, o audit.cmd e o undo.cmd também estão no pendrive.",
    "On a Windows 11 that is already installed, open this drive and run audit.cmd (shows a report, changes nothing), harden.cmd (as administrator) or undo.cmd (goes back). The scripts were never run on real Windows: try them on a test machine first.": "Em um Windows 11 já instalado, abra este pendrive e execute o audit.cmd (mostra um relatório, não altera nada), o harden.cmd (como administrador) ou o undo.cmd (desfaz). Os scripts nunca foram executados em um Windows real: teste primeiro em um computador de teste.",
    "Install target:": "Sistema de destino:",
    "Ubuntu (autoinstall)": "Ubuntu (autoinstall)",
    "Fedora / RHEL (kickstart)": "Fedora / RHEL (kickstart)",
    "Debian (script + preseed)": "Debian (script + preseed)",
    "Ubuntu's installer looks for settings on a drive labelled CIDATA. It still asks for the disk and your account.": "O instalador do Ubuntu procura os ajustes em um pendrive com o nome CIDATA. Ele continua perguntando o disco e a sua conta.",
    "The installer looks for a kickstart file on a drive labelled OEMDRV. It still asks for the disk and your account.": "O instalador procura um arquivo kickstart em um pendrive com o nome OEMDRV. Ele continua perguntando o disco e a sua conta.",
    "Debian does not look for the drive by itself: the README on it explains the boot parameter, and the script to run after the install is on it too.": "O Debian não procura o pendrive sozinho: o README nele explica o parâmetro de inicialização, e o script para rodar depois da instalação também está nele.",
    "Create Seed Drive": "Criar o pendrive do kit",
    "Image remembered: {name}. The Hardening seed card does not use it; choose the matching card to write it.": "Imagem guardada: {name}. O cartão Kit de reforço não a usa; escolha o cartão correspondente para gravá-la.",
    "Choose which system the seed drive is for. Nothing was changed.": "Escolha para qual sistema é o pendrive do kit. Nada foi alterado.",
    "the hardening seed files": "os arquivos do kit de reforço",
    "Windows 11 and add the hardening files": "o Windows 11 e adicionar os arquivos de reforço",
    "Canceled during verification. The seed files were written but NOT verified; do not rely on this drive.": "Cancelado durante a verificação. Os arquivos do kit foram gravados, mas NÃO verificados; não confie neste pendrive.",
    "The operation was canceled during verification.\n\nThe seed files were written to the drive but NOT verified, so do not rely on it. Create it again to verify it.": "A operação foi cancelada durante a verificação.\n\nOs arquivos do kit foram gravados no pendrive, mas NÃO verificados; portanto, não confie nele. Crie-o novamente para verificá-lo.",
    "The seed files were checked on the drive and it was ejected — you can unplug it now. Plug it in next to the installer USB drive before you start the installation.": "Os arquivos do kit foram conferidos no pendrive e ele foi ejetado — você já pode removê-lo. Conecte-o junto com o pendrive instalador antes de iniciar a instalação.",
    "The seed files were checked on the drive, but it could not be ejected automatically. Eject it from the file manager before unplugging, then plug it in next to the installer USB drive before you start the installation.": "Os arquivos do kit foram conferidos no pendrive, mas ele não pôde ser ejetado automaticamente. Ejete-o pelo gerenciador de arquivos antes de removê-lo e depois conecte-o junto com o pendrive instalador antes de iniciar a instalação.",
    "Seed drive created and verified": "Pendrive do kit criado e verificado",
    "Wait for the download to finish or cancel it first.": "Espere o download terminar ou cancele-o antes.",
    "Download in progress": "Download em andamento",
    "The hardening files were written to the drive and checked byte for byte. After Windows setup finishes, their log will be at {log}.": "Os arquivos de reforço foram gravados no pendrive e conferidos byte a byte. Depois que a instalação do Windows terminar, o log deles estará em {log}.",
    # ===== end hardening: GUI =====
    # ===== hardening: windows content =====
    # One entry per line of describe_hardening_windows() (the GUI shows them through _()); a test checks them all.
    "Turn off SMBv1 (obsolete file-sharing protocol) -- risk: Very old NAS boxes, scanners or Windows XP-era PCs that only speak SMBv1 can no longer connect.": "Desativar o SMBv1 (protocolo obsoleto de compartilhamento de arquivos) -- risco: NAS muito antigos, scanners ou PCs da época do Windows XP que só falam SMBv1 não conseguem mais se conectar.",
    "Turn off LLMNR name lookups -- risk: Single-word names that only resolve through LLMNR stop resolving on networks without proper DNS.": "Desativar a resolução de nomes LLMNR -- risco: Nomes de uma só palavra que só se resolvem pelo LLMNR deixam de funcionar em redes sem DNS adequado.",
    "Turn off AutoRun and AutoPlay on every drive type -- risk: Inserted USB sticks and discs no longer start installers or show the AutoPlay prompt, and phones and cameras no longer show the import-photos prompt; open them from File Explorer.": "Desativar a Execução Automática e o AutoPlay em todos os tipos de unidade -- risco: Pendrives e discos inseridos não iniciam mais instaladores nem mostram o aviso do AutoPlay, e celulares e câmeras não mostram mais o aviso de importar fotos; abra-os pelo Explorador de Arquivos.",
    "Windows Firewall on for all network profiles, inbound blocked unless a rule allows it -- risk: A program that must accept incoming connections (game server, file sharing, remote tools) needs an allow rule. The script runs once at the end of Setup and does not retry; the log says [WARN] if the firewall settings are not in effect.": "Firewall do Windows ativado em todos os perfis de rede, com entrada bloqueada a menos que uma regra permita -- risco: Um programa que precisa aceitar conexões de entrada (servidor de jogo, compartilhamento de arquivos, ferramentas remotas) precisa de uma regra de permissão. O script roda uma única vez no fim da instalação e não tenta de novo; o log mostra [WARN] se os ajustes do firewall não estiverem em vigor.",
    "Defender: block potentially unwanted apps and turn cloud protection on -- risk: Some bundled freeware may be flagged, and cloud protection sends file metadata to Microsoft. The script runs once at the end of Setup and does not retry; Tamper Protection, another antivirus or a Defender that is not ready yet can stop the change, and the log then says [WARN].": "Defender: bloquear aplicativos potencialmente indesejados e ativar a proteção na nuvem -- risco: Alguns programas gratuitos que vêm agrupados podem ser sinalizados, e a proteção na nuvem envia metadados dos arquivos à Microsoft. O script roda uma única vez no fim da instalação e não tenta de novo; a Proteção contra Adulteração, outro antivírus ou um Defender que ainda não está pronto podem impedir a alteração, e o log então mostra [WARN].",
    "Defender attack surface rule in Block mode: no credential stealing from LSASS -- risk: Rarely, security or backup tools that read LSASS memory are blocked and Defender shows a notification. The script runs once at the end of Setup and does not retry; the log says [WARN] if the rule is not in effect.": "Regra de redução da superfície de ataque do Defender em modo Bloquear: sem roubo de credenciais do LSASS -- risco: Raramente, ferramentas de segurança ou de backup que leem a memória do LSASS são bloqueadas e o Defender mostra uma notificação. O script roda uma única vez no fim da instalação e não tenta de novo; o log mostra [WARN] se a regra não estiver em vigor.",
    "Defender attack surface rules in Audit mode (log only): email executable content, Office child processes, obfuscated scripts, script-launched downloads -- risk: Audit mode only writes events and blocks nothing. Review the Defender event log before switching any rule to Block. The script runs once at the end of Setup and does not retry; the log says [WARN] for a rule that is not in effect.": "Regras de redução da superfície de ataque do Defender em modo Auditoria (somente registro): conteúdo executável de e-mail, processos filhos do Office, scripts ofuscados, downloads iniciados por scripts -- risco: O modo Auditoria só grava eventos e não bloqueia nada. Revise o log de eventos do Defender antes de mudar qualquer regra para Bloquear. O script roda uma única vez no fim da instalação e não tenta de novo; o log mostra [WARN] para uma regra que não esteja em vigor.",
    "Do not keep plain-text WDigest credentials in memory -- risk: Only legacy digest authentication against very old web servers is affected.": "Não manter credenciais WDigest em texto simples na memória -- risco: Só é afetada a autenticação digest antiga em servidores web muito antigos.",
    "PowerShell script block logging -- risk: Adds events to the PowerShell log; secrets typed inside a script would be logged as well.": "Registro de blocos de script do PowerShell -- risco: Adiciona eventos ao log do PowerShell; segredos digitados dentro de um script também seriam registrados.",
    "Disable the PowerShell 2.0 optional feature -- risk: Very old scripts or tools that insist on running with -Version 2 stop working.": "Desativar o recurso opcional PowerShell 2.0 -- risco: Scripts ou ferramentas muito antigos que insistem em rodar com -Version 2 deixam de funcionar.",
    "Turn off Remote Assistance invitations -- risk: Old-style Remote Assistance invitations stop working; Quick Assist and Remote Desktop are not changed.": "Desativar os convites de Assistência Remota -- risco: Os convites no estilo antigo da Assistência Remota deixam de funcionar; o Assistência Rápida e a Área de Trabalho Remota não são alterados.",
    "Advanced audit policy: sign-ins, account lockouts, account and group changes, audit-policy changes, process creation; Security log size raised to 128 MiB -- risk: The Security event log fills much faster (process creation and sign-ins are frequent events), so its maximum size is raised to 128 MiB (never lowered). Retention is still limited: on a busy PC the oldest events can be overwritten within days, so export the log if you need to keep it.": "Política de auditoria avançada: logons, bloqueios de conta, alterações de contas e grupos, alterações da política de auditoria, criação de processos; tamanho do log de Segurança aumentado para 128 MiB -- risco: O log de eventos de Segurança enche muito mais rápido (criação de processos e logons são eventos frequentes); por isso o tamanho máximo dele sobe para 128 MiB (nunca é reduzido). A retenção continua limitada: num PC muito usado, os eventos mais antigos podem ser sobrescritos em poucos dias; exporte o log se precisar guardá-lo.",
    "Keep User Account Control switched on -- risk: Only acts when UAC was switched off; takes effect after the next restart.": "Manter o Controle de Conta de Usuário ativado -- risco: Só age quando o UAC estava desativado; vale após a próxima reinicialização.",
    # ===== hardening2: windows script (new describe lines) =====
    "Defender attack surface rules in Audit mode (log only), more: abuse of exploited vulnerable signed drivers, process creation from PsExec and WMI commands, untrusted processes that run from USB drives -- risk: Audit mode only writes events and blocks nothing; running programs from a USB stick or with remote-management tools adds events. Review the Defender event log before switching any rule to Block. The script runs once at the end of Setup and does not retry; the log says [WARN] for a rule that is not in effect.": "Regras de redução da superfície de ataque do Defender em modo Auditoria (somente registro), mais: abuso de drivers assinados vulneráveis já explorados, criação de processos por comandos PsExec e WMI, processos não confiáveis executados de pendrives USB -- risco: O modo Auditoria só grava eventos e não bloqueia nada; executar programas de um pendrive ou com ferramentas de administração remota gera eventos. Revise o log de eventos do Defender antes de mudar qualquer regra para Bloquear. O script roda uma única vez no fim da instalação e não tenta de novo; o log mostra [WARN] para uma regra que não esteja em vigor.",
    "Opt-in (-DisableLegacyNetwork, never applied by default): turn off NetBIOS over TCP/IP on all network adapters -- risk: Looking up or browsing machines by their NetBIOS name stops working on the adapters that exist now (very old file shares, printers or NAS boxes reached by a short name). It takes effect when the adapter reconnects or after a restart; adapters added later keep their default.": "Opcional (-DisableLegacyNetwork, nunca aplicado por padrão): desativar o NetBIOS sobre TCP/IP em todos os adaptadores de rede -- risco: Localizar ou navegar por máquinas pelo nome NetBIOS deixa de funcionar nos adaptadores que existem agora (compartilhamentos, impressoras ou NAS muito antigos acessados por um nome curto). Vale quando o adaptador se reconecta ou após uma reinicialização; adaptadores adicionados depois mantêm o padrão deles.",
    "Opt-in (-DisableLegacyNetwork, never applied by default): turn off WPAD proxy auto-discovery for WinHTTP -- risk: A network that hands out its proxy only through WPAD (some offices and schools) no longer gives it to Windows services and apps that use WinHTTP, so they can lose internet access until a proxy is set by hand. The WinHTTP auto-proxy service itself is left running.": "Opcional (-DisableLegacyNetwork, nunca aplicado por padrão): desativar a descoberta automática de proxy WPAD para o WinHTTP -- risco: Uma rede que só informa o proxy pelo WPAD (alguns escritórios e escolas) deixa de entregá-lo aos serviços e aplicativos do Windows que usam o WinHTTP, que podem ficar sem internet até que um proxy seja configurado manualmente. O próprio serviço de proxy automático do WinHTTP continua em execução.",
    # ===== end hardening2: windows script =====
    # ===== end hardening: windows content =====
    # ===== hardening2: windows xml =====
    # One entry per line of describe_windows_seed_during_setup().
    "EXPERIMENTAL: this mode has not been tested on a real Windows installation. If anything looks wrong, use the \"run after install\" mode instead.": "EXPERIMENTAL: este modo não foi testado em uma instalação real do Windows. Se algo parecer errado, use o modo \"executar após a instalação\".",
    "The seed drive carries an answer file (autounattend.xml). Windows Setup looks for that file on the root of removable drives, so plug the seed drive in next to the Windows installer drive before you start.": "O pendrive do kit leva um arquivo de resposta (autounattend.xml). A instalação do Windows procura esse arquivo na raiz das unidades removíveis; por isso, conecte o pendrive do kit ao lado do pendrive instalador do Windows antes de começar.",
    "The answer file adds one step, early on the first start of the new system: it looks for the file EPMA-SEED.txt on the drives D: to Z: and, where it finds it, runs harden.ps1 from that drive in Apply mode.": "O arquivo de resposta adiciona uma etapa, logo no primeiro início do sistema novo: procura o arquivo EPMA-SEED.txt nas unidades D: a Z: e, onde o encontrar, executa o harden.ps1 dessa unidade no modo Apply.",
    "Keep both drives plugged in until the first screens of the new Windows (region, keyboard, network) appear. If the seed drive is gone by then, nothing is hardened and the installation goes on normally.": "Mantenha os dois pendrives conectados até aparecerem as primeiras telas do novo Windows (região, teclado, rede). Se o pendrive do kit já tiver sido retirado, nada é reforçado e a instalação continua normalmente.",
    "It does not choose or erase a disk, set a product key, accept licence terms, create accounts, set the language or region, skip the hardware checks, download anything or restart the PC. Setup stays interactive.": "Ele não escolhe nem apaga um disco, não define chave de produto, não aceita termos de licença, não cria contas, não define idioma nem região, não ignora as verificações de hardware, não baixa nada e não reinicia o PC. A instalação continua interativa.",
    "If no drive has the marker file, nothing happens and Setup continues as usual.": "Se nenhuma unidade tiver o arquivo marcador, nada acontece e a instalação continua como de costume.",
    "Only 64-bit Intel/AMD PCs (x64) are covered. On any other PC the answer file does nothing: use the \"run after install\" mode.": "Apenas PCs Intel/AMD de 64 bits (x64) são atendidos. Em qualquer outro PC o arquivo de resposta não faz nada: use o modo \"executar após a instalação\".",
    # ===== end hardening2: windows xml =====
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
    `extra_files` ({relative path: bytes}, the hardening files) are compared byte for byte too. They never
    replace a file of the ISO (an image that already holds one is refused before anything is copied), so
    the rsync comparison has no exemption: a hardening file that overwrote an ISO file shows up as a difference.
    """
    log("Verifying the copied files (reading them back from the drive)...")
    if progress:
        progress(0, 0, "Verifying the copied files...")
    bad = []

    def watch(line):
        log(line)
        if re.match(r"^(>f|cd|\*deleting)", line):
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
                         extra_files=None):
    """Copy the contents of a mounted Windows ISO to the drive, reporting progress.

    Everything except sources/install.wim|esd is copied with rsync; that file is
    copied directly, or split into <4 GB parts when it exceeds the FAT32 limit.
    Progress is counted in bytes over the whole payload. The "sources" folder and the
    install image are looked up ignoring case.
    `extra_files` ({relative path: bytes}, the hardening files) are written after the ISO's files with
    write_hardening_files (plain file I/O as the user: both mounts are user-owned) and read back with the rest.
    """
    if extra_files:
        check_image_for_hardening_clash(src_root, extra_files)  # before a single byte is copied
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
        # Hardening files go on after the ISO's own files and before the remount, so the read-back
        # below covers them too.
        report(total, "Adding hardening files...")
        log("Adding hardening files...")
        check_canceled(cancel_event)
        write_hardening_files(dst_root, extra_files, cancel_event)

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
            **({"extra_files": hardening_files} if hardening_files else {}))
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
    iso_mount = tempfile.mkdtemp(prefix="win11iso_")
    usb_mount = tempfile.mkdtemp(prefix="win11usb_")

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
            **({"extra_files": hardening_files} if hardening_files else {}))
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

    ejected = linux_eject(dev_name, log, priv) if eject else None
    log("Done! The USB drive is ready to install Windows 11.")
    report_eject(ejected, log, skipped=not eject)
    return ejected


# ===== hardening: engine-windows =====
# Extra files for a Windows drive (a SetupComplete script and its PowerShell script, see
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
    files = validate_seed_files(hardening_files_windows(hardening))
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


# --- the hardening files must never replace a file the image already ships -------------------------------
# An image of its own (an OEM or custom build) may already carry e.g. sources/$OEM$/$$/Setup/Scripts/
# SetupComplete.cmd. Writing ours over it would silently drop that content, so such an image is refused.
# The check looks at the ISO's tree (read-only) BEFORE the drive is touched (refuse_hardening_clash, called
# by build_usb); copy_windows_payload repeats it on the mounted tree as a last line of defence, and the
# post-copy verification has no exemption for these paths either.
def find_hardening_clashes(root, files):
    """The paths of `files` ({relative posix path: bytes}) that already exist below `root`, ignoring case.

    FAT32 (and a Windows setup) treat names case-insensitively, so "Sources/$OEM$/..." clashes with
    "sources/$oem$/...". Returns the paths as spelled in `files`, sorted.
    """
    clashes = []
    for rel in sorted(files):
        path = root
        for part in rel.split("/"):
            path = find_case_insensitive(path, part)
            if path is None:
                break
        if path is not None:
            clashes.append(rel)
    return clashes


def check_image_for_hardening_clash(root, files):
    """Raise ValueError (and audit the refusal) when the image tree at `root` already holds any of `files`."""
    clashes = find_hardening_clashes(root, files)
    if clashes:
        audit(f"HARDENING REFUSED: the image already contains {clashes}; nothing was changed", logging.WARNING)
        raise ValueError(f"This Windows image already contains {', '.join(clashes)}. Adding the hardening "
                         "files would replace them, so nothing was changed. Untick the hardening option "
                         "or use another image.")


# Root script that mounts the ISO read-only so the app (as the user) can list it BEFORE the drive is
# touched (the prep script of linux_build_usb mounts it only after wiping). Same mount calls as that script;
# "$1" the ISO, "$2" an empty folder, "$3" uid:gid. Nothing is written anywhere and no drive is involved.
LINUX_ISO_PEEK_SCRIPT = (
    'set -eu\n'
    "trap '' INT\n"
    'ISO="$1"; ISO_MNT="$2"; OWNER="$3"\n'
    'if ! mount -t udf,iso9660 -o loop,ro,uid="${OWNER%%:*}",gid="${OWNER##*:}" "$ISO" "$ISO_MNT"; then\n'
    'echo "Mounting the ISO as UDF/ISO 9660 failed; letting mount detect the type." >&2\n'
    'mount -o loop,ro,uid="${OWNER%%:*}",gid="${OWNER##*:}" "$ISO" "$ISO_MNT"\n'
    'fi\n'
)
LINUX_ISO_PEEK_CLEANUP_SCRIPT = (
    'set -eu\n'
    "trap '' INT\n"
    'umount "$1" || true\n'
)


def refuse_hardening_clash(iso_path, files, log, priv):
    """Before the drive is touched: mount the ISO read-only, and refuse (ValueError) if it already holds any
    of the hardening `files`. Does nothing when there are no files. The ISO is unmounted again either way."""
    if not files:
        return
    log("Checking that the image does not already contain the hardening files...")
    mount_dir = tempfile.mkdtemp(prefix="win11peek_")
    attempted = False
    try:
        if IS_MAC:
            attempted = True
            run_cmd(["hdiutil", "attach", iso_path, "-nobrowse", "-readonly", "-mountpoint", mount_dir], log,
                    timeout=300)
        else:
            attempted = True  # set first: an interrupt right after the mount must still reach the unmount
            priv.run_script(LINUX_ISO_PEEK_SCRIPT, log,
                            args=[iso_path, mount_dir, f"{os.getuid()}:{os.getgid()}"])
        check_image_for_hardening_clash(mount_dir, files)
    finally:
        if attempted:
            if IS_MAC:
                run_cmd(["hdiutil", "detach", mount_dir, "-force"], log, check=False, timeout=DISKUTIL_TIMEOUT)
            else:
                try:
                    priv.run_script(LINUX_ISO_PEEK_CLEANUP_SCRIPT, log, args=[mount_dir])
                except Exception as cleanup_err:
                    log(f"Warning: cleanup failed: {cleanup_err}")
        _silent_rmdir(mount_dir)

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
    refuse_hardening_clash(iso_path, hardening_files, log, priv)
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
              on the first boot of the installed system (up to 5 tries, then it gives up)
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
  STRICTER_KEYS=""
  PKG_REFRESHED=0
  ADMINS=""
  ADMIN_KEYS=0
  KEYS_CALLER=0
  EFFECTIVE_PW=""
  UNIT_NAME="epma-hardening-firstboot.service"
  FIRSTBOOT_MAX=5
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

# in_state created|modified PATH: is PATH listed (as a whole line) in that state file?
in_state() {
  local f="$STATE_DIR/$1.list"
  [ -f "$f" ] && grep -qxF -- "$2" "$f"
}

unrecord_created() {
  local f="$STATE_DIR/created.list"
  if [ -f "$f" ]; then
    grep -vxF -- "$1" "$f" >"$f.new" || true
    mv -f "$f.new" "$f"
  fi
}

# put_file DEST NEWFILE MODE: install NEWFILE as DEST when it differs. The original is copied to
# DEST.epma-bak once. Sets CHANGED_LAST=1 when DEST was (or would be) written. A file this script
# created itself (it is in created.list) never gets a backup of its own earlier version and is never
# recorded as modified: undo removes it, and must not put an old copy of it back afterwards.
put_file() {
  local dest="$1" new="$2" mode="$3" name own=0
  name="$(shown "$dest")"
  if in_state created "$dest"; then
    own=1
  fi
  if [ -e "$dest" ] && cmp -s "$new" "$dest"; then
    ok "$name is already as wanted"
    return 0
  fi
  CHANGED_LAST=1
  if [ "$DRY" = 1 ]; then
    if [ "$own" = 1 ] && [ -e "$dest" ]; then
      change "$name: would be updated (a file this script created)"
    elif [ -e "$dest" ]; then
      change "$name: would be updated (original kept as $name.epma-bak)"
    else
      change "$name: would be created"
    fi
    return 0
  fi
  mkdir -p "$(dirname "$dest")"
  if [ -e "$dest" ]; then
    mode="$(file_mode "$dest")"
    if [ "$own" = 1 ]; then
      cp "$new" "$dest.epma-new"
      chmod "$mode" "$dest.epma-new"
      mv -f "$dest.epma-new" "$dest"
      change "$name: updated (a file this script created)"
      return 0
    fi
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
    # No question may reach the (closed) standard input: keep the old version of a configuration file
    # a package would ask about, and wait up to 10 minutes for another apt or dpkg to finish.
    act "install package $1" apt-get install -y --no-install-recommends -o DPkg::Lock::Timeout=600 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$1" || return 1
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

# shellcheck disable=SC2317,SC2329  # called through "trap cleanup EXIT" in main
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

# sysctl_rank MODE VALUE: how strict a value is (a bigger number is stricter). MODE max: the bigger
# the value, the stricter it is. MODE rp (rp_filter): 1 (strict) is stricter than 2 (loose), and
# 0 is off. MODE set: the value is simply the wanted one (always the strictest possible).
sysctl_rank() {
  case "$1" in
    rp)
      case "$2" in
        1) echo 2 ;;
        2) echo 1 ;;
        *) echo 0 ;;
      esac
      ;;
    *) echo "$2" ;;
  esac
}

# sysctl_others KEY: the numeric values some OTHER source already asks for, one per line: the value
# in force now (not asked inside the installer, where it belongs to the installer's kernel) and the
# values in the sysctl configuration files other than ours.
sysctl_others() {
  local key="$1" path f
  if [ "$CHROOT" = 0 ]; then
    path="$R/proc/sys/$(printf '%s' "$key" | tr . /)"
    if [ -r "$path" ]; then
      head -n 1 "$path" 2>/dev/null | tr -d ' \t' || true
    fi
  fi
  for f in "$R"/etc/sysctl.conf "$R"/etc/sysctl.d/*.conf "$R"/run/sysctl.d/*.conf "$R"/usr/lib/sysctl.d/*.conf "$R"/lib/sysctl.d/*.conf; do
    if [ -f "$f" ] && [ "$f" != "$R/etc/sysctl.d/99-epma-hardening.conf" ]; then
      awk -v k="$key" '
        { sub(/^[ \t]+/, "") }
        /^[#;]/ { next }
        {
          line = $0
          sub(/^-/, "", line)
          n = index(line, "=")
          if (n == 0) next
          name = substr(line, 1, n - 1)
          gsub(/[ \t]/, "", name)
          val = substr(line, n + 1)
          gsub(/[ \t\r]/, "", val)
          if (name == k) print val
        }' "$f"
    fi
  done
}

# sysctl_stricter KEY WANTED MODE: succeeds when another source already asks for a stricter value
# than WANTED (the key is then left out, so this script never lowers a setting).
sysctl_stricter() {
  local v want_rank others
  if [ "$3" = set ]; then
    return 1
  fi
  want_rank="$(sysctl_rank "$3" "$2")"
  others="$(sysctl_others "$1")"
  for v in $others; do
    case "$v" in
      '' | *[!0-9]*) continue ;;
    esac
    if [ "$(sysctl_rank "$3" "$v")" -gt "$want_rank" ]; then
      return 0
    fi
  done
  return 1
}

build_sysctl() {
  local key val opt mode desc
  printf '%s\n' "# Managed by harden-linux.sh (EPMA USB CREATOR). Remove this file, or run the script with"
  printf '%s\n' "# --undo, to go back to the system defaults. Values are conservative on purpose, and a key is"
  printf '%s\n' "# left out when the system already has a stricter value (this file only ever raises a setting)."
  while IFS='|' read -r key val opt mode desc; do
    if [ -z "$key" ]; then
      continue
    fi
    if ! sysctl_key_ok "$key" "$opt"; then
      SKIPPED_KEYS="$SKIPPED_KEYS $key"
    elif sysctl_stricter "$key" "$val" "$mode"; then
      STRICTER_KEYS="$STRICTER_KEYS $key"
    else
      printf '\n# %s\n%s = %s\n' "$desc" "$key" "$val"
    fi
  done <<'EOF'
kernel.kptr_restrict|2|req|max|Hide kernel memory addresses from everybody (makes kernel exploits harder to write).
kernel.dmesg_restrict|1|req|max|Only root may read the kernel log, which can contain addresses and hardware details.
kernel.randomize_va_space|2|req|max|Full address space layout randomization (usually already on; makes sure nobody turned it down).
kernel.yama.ptrace_scope|1|opt|max|A process may only trace its own children, so one program cannot read another one's memory. Only where the kernel has the Yama module.
net.ipv4.conf.all.rp_filter|2|req|rp|Drop packets whose source address could not be reached through the interface they came in on. Loose mode (2) stays safe with VPNs and several network cards.
net.ipv4.conf.default.rp_filter|2|req|rp|Same, for interfaces created later.
net.ipv4.conf.all.accept_redirects|0|req|set|Ignore ICMP redirects (a way to silently reroute your traffic).
net.ipv4.conf.default.accept_redirects|0|req|set|Same, for interfaces created later.
net.ipv6.conf.all.accept_redirects|0|req|set|Ignore ICMPv6 redirects.
net.ipv6.conf.default.accept_redirects|0|req|set|Same, for interfaces created later.
net.ipv4.conf.all.send_redirects|0|req|set|This machine is not a router, so it never sends ICMP redirects.
net.ipv4.conf.default.send_redirects|0|req|set|Same, for interfaces created later.
net.ipv4.conf.all.accept_source_route|0|req|set|Ignore packets that choose their own route through the network (source routing).
net.ipv4.conf.default.accept_source_route|0|req|set|Same, for interfaces created later.
net.ipv6.conf.all.accept_source_route|0|req|set|Ignore IPv6 source routing.
net.ipv6.conf.default.accept_source_route|0|req|set|Same, for interfaces created later.
net.ipv4.tcp_syncookies|1|req|max|Keep the machine answering real clients during a SYN flood.
fs.protected_symlinks|1|req|max|Do not follow symlinks in sticky world-writable directories (like /tmp) unless the owner matches; blocks a class of temp-file attacks.
fs.protected_hardlinks|1|req|max|Only allow hard links to files you own or can write to.
fs.protected_fifos|1|opt|max|Restrict opening foreign FIFOs in sticky world-writable directories. Needs kernel 4.19 or newer.
fs.protected_regular|1|opt|max|Restrict opening foreign regular files in sticky world-writable directories. Needs kernel 4.19 or newer.
fs.suid_dumpable|0|req|set|Programs running with raised privileges never write core dumps (they may hold secrets).
EOF
}

do_sysctl() {
  local dest="$R/etc/sysctl.d/99-epma-hardening.conf"
  SKIPPED_KEYS=""
  STRICTER_KEYS=""
  build_sysctl >"$WORK/sysctl.new"
  CHANGED_LAST=0
  put_file "$dest" "$WORK/sysctl.new" 644
  if [ -n "$SKIPPED_KEYS" ]; then
    skip "sysctl: not available on this kernel, left out:$SKIPPED_KEYS"
  fi
  if [ -n "$STRICTER_KEYS" ]; then
    skip "sysctl: already set to something stricter, left alone:$STRICTER_KEYS"
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

# perms_recorded PATH FILE: does FILE already hold a "MODE PATH" line for exactly this PATH? (A whole
# path is compared, so /etc/shadow is not mistaken for /etc/shadow-.)
perms_recorded() {
  [ -f "$2" ] && awk -v p="$1" '{ sub(/^[^ ]+ /, ""); if ($0 == p) found = 1 } END { exit !found }' "$2"
}

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
    if ! perms_recorded "$f" "$pfile"; then
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

# admin_users: the people who can still administer this machine once root is refused over SSH. A
# normal login account (UID 1000-59999, not root, a real shell) that is a member of sudo, wheel or
# admin (as a listed member or through its primary group). One name per line. A service account such
# as a backup or deploy account does not count: it has no shell worth logging in to, or no administrator rights.
admin_users() {
  if [ ! -s "$R/etc/passwd" ] || [ ! -s "$R/etc/group" ]; then
    return 0
  fi
  awk -F: '
    FNR == NR {
      if ($1 == "sudo" || $1 == "wheel" || $1 == "admin") {
        gids[$3] = 1
        n = split($4, m, ",")
        for (i = 1; i <= n; i++) if (m[i] != "") members[m[i]] = 1
      }
      next
    }
    $3 >= 1000 && $3 < 60000 && $7 != "" && $7 !~ /(nologin|false|sync|halt|shutdown)$/ && (($1 in members) || ($4 in gids)) { print $1 }
  ' "$R/etc/group" "$R/etc/passwd"
}

is_admin() {
  case " $ADMINS " in
    *" $1 "*) return 0 ;;
  esac
  return 1
}

# scan_authorized_keys: sets ADMINS (the names from admin_users, separated by spaces), ADMIN_KEYS=1
# when at least one of them has an authorized_keys file holding a real key (comment-only and empty
# files do not count) and KEYS_CALLER=1 when the account running this script has one.
scan_authorized_keys() {
  local caller="${SUDO_USER:-root}" name home f
  ADMINS="$(admin_users | tr '\n' ' ')"
  ADMINS="${ADMINS% }"
  ADMIN_KEYS=0
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
      if is_admin "$name"; then
        ADMIN_KEYS=1
      fi
      if [ "$name" = "$caller" ]; then
        KEYS_CALLER=1
      fi
    fi
  done <"$R/etc/passwd"
}

build_sshd() {
  # $1 = PermitRootLogin value, $2 = 1 to turn password logins off
  printf '%s\n' "# Managed by harden-linux.sh (EPMA USB CREATOR). Remove this file, or run the script with --undo,"
  printf '%s\n' "# to go back. Note: sshd uses the FIRST value it reads for a keyword, so an earlier file in"
  printf '%s\n' "# this directory can win over this one (the script warns when that happens)."
  if [ "$1" = no ]; then
    printf '\n%s\n%s\n' "# Nobody logs in directly as root over the network (a user in sudo/wheel/admin exists)." "PermitRootLogin $1"
  else
    printf '\n%s\n%s\n' "# Root may log in over the network with a key only, never with a password (no user in sudo/wheel/admin exists yet)." "PermitRootLogin $1"
  fi
  printf '\n%s\n%s\n' "# No graphical-session forwarding (a rarely needed way to attack a client)." "X11Forwarding no"
  printf '\n%s\n%s\n' "# Drop connections that have not logged in after 30 seconds." "LoginGraceTime 30"
  printf '\n%s\n%s\n' "# Never accept an account with an empty password." "PermitEmptyPasswords no"
  printf '\n%s\n%s\n%s\n' "# Probe silent clients and drop the dead ones after about 10 minutes (live sessions stay open)." "ClientAliveInterval 300" "ClientAliveCountMax 2"
  if [ "$2" = 1 ]; then
    printf '\n%s\n%s\n%s\n' "# Written because a user in sudo/wheel/admin has a key in authorized_keys:" "# key logins keep working, password logins are refused." "PasswordAuthentication no"
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
  # ssh_effective_check ROOTLOGIN_WANTED: sshd -T prints the effective configuration; warn when a
  # value is not what this script asked for. Sets EFFECTIVE_PW to the effective PasswordAuthentication.
  local dump k want have
  EFFECTIVE_PW=""
  dump="$(sysrun sshd -T 2>/dev/null)" || return 0
  if [ -z "$dump" ]; then
    return 0
  fi
  EFFECTIVE_PW="$(printf '%s\n' "$dump" | awk '$1 == "passwordauthentication" { print $2; exit }')"
  for k in "permitrootlogin $1" "x11forwarding no" "logingracetime 30" "permitemptypasswords no"; do
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

# ssh_report_password DEST: what to tell the user about PasswordAuthentication no (only called when
# this run wants it off and the configuration was accepted).
ssh_report_password() {
  if [ "$CHROOT" = 1 ]; then
    if [ "$CHANGED_LAST" = 1 ]; then
      warn "SSH: PasswordAuthentication is set to no for the installed system, so password logins will be refused once its SSH server runs. A user in sudo/wheel/admin has an SSH key; make sure you can log in with it."
      notice "SSH password login will be OFF on the installed system. Test your key from a second terminal before you close the first session."
    else
      ok "SSH password login is set to off (a sudo/wheel/admin user has an authorized_keys key)"
    fi
    return 0
  fi
  case "$EFFECTIVE_PW" in
    no)
      if [ "$CHANGED_LAST" = 1 ]; then
        warn "SSH PASSWORD LOGIN IS NOW OFF: a user in sudo/wheel/admin has authorized_keys, so PasswordAuthentication is set to no. Make sure you can log in with your key BEFORE you close this session."
        notice "SSH password login is OFF. Test your key from a second terminal before closing this one."
      else
        ok "SSH password login is off (confirmed with sshd -T)"
      fi
      ;;
    '')
      warn "SSH: PasswordAuthentication no is written in $(shown "$1"), but sshd -T did not say whether it is in effect. Test your key from a second terminal before you close this session; password logins may still work."
      notice "Could not confirm with sshd -T that SSH password login is off; check it yourself."
      ;;
    *)
      warn "SSH: PasswordAuthentication is set to no in $(shown "$1"), but sshd -T reports '$EFFECTIVE_PW': the setting is NOT in effect and password logins still work. An earlier file wins (cloud images ship 50-cloud-init.conf with PasswordAuthentication yes, and sshd keeps the FIRST value it reads), or an Include line sits below the settings it should override. Edit that file or move the Include line to the top of sshd_config."
      notice "SSH password login is STILL ON: another configuration file overrides this script's PasswordAuthentication no (see the WARN line above)."
      ;;
  esac
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
  scan_authorized_keys
  # Two separate rules, so that nobody is left without a way in over SSH:
  #  1. root is refused (PermitRootLogin no) only when a non-root user with a real shell in
  #     sudo/wheel/admin exists; otherwise root keeps key-only login.
  #  2. passwords are refused only when THAT kind of user has a key in authorized_keys.
  if [ -z "$ADMINS" ]; then
    rootlogin=prohibit-password
    warn "SSH: no normal user with a login shell is in the sudo/wheel/admin group, so root is NOT refused over SSH (PermitRootLogin prohibit-password: key only) and password logins stay ON. Refusing root now could leave nobody able to log in over SSH."
    notice "Create a normal user in the sudo (Debian/Ubuntu) or wheel (Fedora/RHEL) group, add its SSH key, then run this script again to refuse root and password logins over SSH."
  elif [ "$ADMIN_KEYS" = 1 ]; then
    if [ -n "${SSH_CONNECTION:-}" ] && [ "$KEYS_CALLER" = 0 ]; then
      warn "SSH: you are connected over SSH but your own account has no authorized_keys; password login left as it is"
    else
      pwoff=1
    fi
  else
    warn "SSH: password login stays ON: no user in the sudo/wheel/admin group ($ADMINS) has a key in authorized_keys (a key for root or for a service account does not count). Add a key for your own user, then run this script again."
  fi
  build_sshd "$rootlogin" "$pwoff" >"$WORK/sshd.new"
  if [ -e "$dest" ]; then
    cp "$dest" "$WORK/sshd.prev"
    had_prev=1
  fi
  CHANGED_LAST=0
  put_file "$dest" "$WORK/sshd.new" 644
  if [ "$DRY" = 1 ]; then
    if [ "$CHANGED_LAST" = 1 ]; then
      if [ "$pwoff" = 1 ]; then
        warn "SSH: with this change password login would be turned OFF (a user in sudo/wheel/admin has an authorized_keys key)."
      fi
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
  if [ "$pwoff" = 1 ]; then
    ssh_report_password "$dest"
  fi
}

# ---------------------------------------------------------------------------------------------
# Firewall
# ---------------------------------------------------------------------------------------------

# firewall_listeners SSH_PORTS: warn about the services that listen on the network (not only on this
# machine) and are not SSH. A default "deny incoming" policy cuts them off from other computers.
firewall_listeners() {
  local out proto lcl addr port seen="" key
  if ! have_cmd ss; then
    skip "firewall: the 'ss' command is not available, so the listening network services were not checked"
    return 0
  fi
  out="$(sysrun ss -ltnu 2>/dev/null)" || out=""
  while read -r proto lcl; do
    if [ -z "$lcl" ]; then
      continue
    fi
    addr="${lcl%:*}"
    port="${lcl##*:}"
    case "$port" in
      '' | *[!0-9]*) continue ;;
    esac
    case "$addr" in
      127.* | '[::1]' | ::1 | '[::ffff:127.'*) continue ;;
    esac
    case " $1 " in
      *" $port "*) continue ;;
    esac
    case "$proto $port" in
      "udp 68" | "udp 546") continue ;;
    esac
    key="$port/$proto"
    case " $seen " in
      *" $key "*) continue ;;
    esac
    seen="$seen $key"
  done <<EOT
$(printf '%s\n' "$out" | awk 'NR > 1 { print $1, $5 }')
EOT
  if [ -n "$seen" ]; then
    warn "firewall: these services listen on the network and are not SSH:$seen. Incoming connections to them will be BLOCKED by the firewall unless you allow them (ufw allow PORT/tcp, or firewall-cmd --permanent --add-port=PORT/tcp)."
  else
    ok "firewall: no other service listens on the network"
  fi
}

# firewall_containers: print the names of container / virtual machine software that was found.
firewall_containers() {
  local u found=""
  for u in docker containerd libvirtd virtqemud lxd snap.lxd.daemon incus; do
    if service_active "$u" || service_enabled "$u"; then
      found="$found $u"
    fi
  done
  for u in docker virsh lxc incus; do
    if have_cmd "$u"; then
      found="$found $u"
    fi
  done
  printf '%s\n' "${found# }"
}

# firewall_precheck: look before the firewall is switched on. Returns 1 when it must stay off in
# this run: container or virtual machine software was found and --yes was not given.
firewall_precheck() {
  local ports found
  ports="$(ssh_ports)"
  firewall_listeners "$ports"
  found="$(firewall_containers)"
  if [ -z "$found" ]; then
    return 0
  fi
  warn "firewall: found $found. Docker, containerd, libvirt, LXD and Incus build their own network bridges, and a default 'deny incoming' policy can break them (containers or virtual machines may lose DHCP, DNS or published ports)."
  if [ "$YES" = 1 ]; then
    warn "firewall: --yes was given, so the firewall is switched on anyway; check those tools afterwards"
    return 0
  fi
  if [ "$DRY" = 1 ]; then
    warn "firewall: the firewall would NOT be switched on in a real run without --yes"
  else
    warn "firewall: the firewall was NOT switched on"
  fi
  notice "The firewall was NOT switched on because container or virtual machine software was found ($found). To switch it on anyway, run again with --yes: sudo bash $(script_ref) --yes"
  return 1
}

firewall_ufw() {
  local status="" ports p ufw_ok=1 have_it=0
  if service_active firewalld; then
    skip "firewall: firewalld is active, ufw is not added next to it"
    return 0
  fi
  if pkg_installed ufw; then
    have_it=1
    status="$(sysrun ufw status verbose 2>&1)" || status=""
  fi
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
  firewall_precheck || return 0
  pkg_install ufw || return 0
  if [ "$have_it" = 0 ] && [ "$DRY" = 1 ]; then
    change "(dry-run) ufw would be set to: deny incoming, allow outgoing, allow SSH when the SSH server is in use, then enabled"
    return 0
  fi
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
  local zone ports p have_it=0
  if pkg_installed firewalld; then
    have_it=1
    if service_enabled firewalld && service_active firewalld; then
      ok "firewall: firewalld is enabled and running; its zones are left as they are"
      return 0
    fi
  fi
  firewall_precheck || return 0
  pkg_install firewalld || return 0
  if [ "$have_it" = 0 ] && [ "$DRY" = 1 ]; then
    change "(dry-run) firewalld would be enabled and started, SSH kept reachable when the SSH server is in use (the default zone is not changed)"
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

# uu_origin_strings FILE...: the quoted entries of the active (not commented out) Allowed-Origins and
# Origins-Pattern lists of the apt configuration files given.
uu_origin_strings() {
  awk '
    { sub(/\/\/.*/, "") }
    /Unattended-Upgrade::(Allowed-Origins|Origins-Pattern)/ { inblk = 1 }
    inblk {
      line = $0
      while (match(line, /"[^"]*"/)) {
        print substr(line, RSTART + 1, RLENGTH - 2)
        line = substr(line, RSTART + RLENGTH)
      }
      if ($0 ~ /};/) inblk = 0
    }
  ' "$@"
}

# uu_restrict_origins: limit unattended-upgrades to the security archives. Only done on Debian and
# Ubuntu (ID=debian or ID=ubuntu) with the stock 50unattended-upgrades in place, and only when no
# other origin (a third-party repository the administrator added) is listed in the apt configuration:
# in every other case the list is left alone and a WARN says so. Automatic-Reboot is never touched.
uu_restrict_origins() {
  local id dir="$R/etc/apt/apt.conf.d" f o
  id="$(os_value ID)"
  case "$id" in
    debian | ubuntu) ;;
    *)
      warn "unattended-upgrades: this system is '${id:-unknown}', not Debian or Ubuntu, so its list of origins is left alone: it may install more than security updates. Check $(shown "$dir")/50unattended-upgrades by hand."
      return 0
      ;;
  esac
  if [ ! -f "$dir/50unattended-upgrades" ]; then
    if pkg_installed unattended-upgrades; then
      warn "unattended-upgrades: $(shown "$dir")/50unattended-upgrades does not exist, so its list of origins is left alone."
    else
      skip "unattended-upgrades: the stock 50unattended-upgrades does not exist yet (the package is installed later), so the list of origins is set on the first boot"
    fi
    return 0
  fi
  for f in "$dir"/*; do
    case "$f" in
      "$dir/52epma-hardening-unattended" | *.epma-bak | *.epma-new | *.dpkg-* | *.ucf-*) continue ;;
    esac
    if [ ! -f "$f" ]; then
      continue
    fi
    while IFS= read -r o; do
      case "$o" in
        "\${distro_id}:\${distro_codename}"* | "\${distro_id}ESM"* | 'origin=Debian,'* | 'origin=Ubuntu,'* | 'origin=UbuntuESM'* | 'o=Debian,'* | 'o=Ubuntu,'* | '') ;;
        *)
          warn "unattended-upgrades: $(shown "$f") lists the origin \"$o\", which is not a Debian or Ubuntu one. The list of origins is left alone (automatic installs from other repositories are your choice); only the daily run is switched on."
          return 0
          ;;
      esac
    done <<EOT
$(uu_origin_strings "$f")
EOT
  done
  cat >"$WORK/uu-origins.new" <<'EOF'
// Managed by harden-linux.sh (EPMA USB CREATOR): install SECURITY updates only (from the Debian or
// Ubuntu security archives), never other updates. This replaces the distribution's default list of
// origins; it changes nothing else (Automatic-Reboot stays as the administrator set it).
#clear Unattended-Upgrade::Allowed-Origins;
#clear Unattended-Upgrade::Origins-Pattern;
Unattended-Upgrade::Origins-Pattern {
        "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
        "origin=Debian,codename=${distro_codename},label=Debian-Security";
        "origin=Ubuntu,archive=${distro_codename}-security";
        "origin=UbuntuESMApps,codename=${distro_codename}-apps-security";
        "origin=UbuntuESM,codename=${distro_codename}-infra-security";
};
EOF
  put_file "$dir/52epma-hardening-unattended" "$WORK/uu-origins.new" 644
}

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
    pkg_install unattended-upgrades || true
    uu_restrict_origins
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
    if [ "$(os_value ID)" = centos ]; then
      warn "dnf-automatic: upgrade_type = security installs NOTHING on CentOS Stream, which publishes no security errata. Change upgrade_type in $(shown "$R/etc/dnf/automatic.conf") (the default installs every update) if you want automatic updates there."
    fi
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
    "/etc/sudoers sudoers" "/etc/sudoers.d/ sudoers" "/etc/ssh/sshd_config sshd" "/etc/ssh/sshd_config.d/ sshd"; do
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

self_is_file() {
  # Is this script running from a file of its own (and not through "bash -s")?
  [ -f "$0" ] && [ -r "$0" ] && [ "$(head -c 2 "$0")" = '#!' ] && grep -q '^emit_self()' "$0"
}

# script_ref: the path to show in "run it again" hints: the file this script runs from; inside the
# installer (--chroot) the place it will have on the installed system.
script_ref() {
  local me="$0"
  if [ "$CHROOT" = 1 ]; then
    if [ -e "$R/root/harden-linux.sh" ]; then
      printf '%s' "/root/harden-linux.sh"
    else
      printf '%s' "/usr/local/sbin/epma-harden-linux.sh"
    fi
  elif self_is_file; then
    case "$me" in
      /*) ;;
      *) me="$PWD/${me#./}" ;;
    esac
    printf '%q' "$me"
  elif [ -e "$R/usr/local/sbin/epma-harden-linux.sh" ]; then
    printf '%s' "/usr/local/sbin/epma-harden-linux.sh"
  else
    printf '%s' "harden-linux.sh"
  fi
}

self_copy() {
  # self_copy DEST: write a copy of this script to DEST.
  if self_is_file; then
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
# the next boot, up to 5 tries in all, and then gives up and switches itself off. After
# cloud-final.service so that cloud-init has created the user of an Ubuntu autoinstall before the
# SSH settings are decided.
[Unit]
Description=EPMA hardening (first boot)
Wants=network-online.target
After=network-online.target cloud-final.service
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
    printf '%s\n' "attempts=0" >"$marker"
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

# firstboot_gate: on the installed system, while the first-boot marker exists, every real run counts as
# one try (the number is kept in the marker). Returns 1 after FIRSTBOOT_MAX tries: the service is
# switched off for good, a message is left in the log and in firstboot-gave-up.txt, and the
# hardening itself is NOT run again.
firstboot_gate() {
  local marker="$STATE_DIR/firstboot.pending" wants="$R/etc/systemd/system/multi-user.target.wants/$UNIT_NAME"
  local n msg
  if [ ! -f "$marker" ] || [ "$DRY" = 1 ]; then
    return 0
  fi
  n="$(awk -F= '$1 == "attempts" && $2 ~ /^[0-9]+$/ { print $2; exit }' "$marker")"
  n="${n:-0}"
  if [ "$n" -ge "$FIRSTBOOT_MAX" ]; then
    msg="EPMA hardening gave up after $FIRSTBOOT_MAX tries on the first boot and has switched its service off. Read $(shown "$LOG_FILE") to see what failed, fix it (often: no network), then run it by hand: sudo bash $(script_ref)"
    warn "$msg"
    notice "$msg"
    printf '%s\n' "$msg" >"$STATE_DIR/firstboot-gave-up.txt"
    record_state created "$STATE_DIR/firstboot-gave-up.txt"
    act_soft "disable $UNIT_NAME" systemctl disable "$UNIT_NAME"
    rm -f -- "${marker:?}"
    if [ -L "$wants" ]; then
      rm -f -- "${wants:?}"
    fi
    N_ERR=$((N_ERR + 1))
    return 1
  fi
  n=$((n + 1))
  printf 'attempts=%s\n' "$n" >"$marker.new"
  mv -f "$marker.new" "$marker"
  say "first-boot service: try $n of $FIRSTBOOT_MAX"
  return 0
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
      if in_state created "$p"; then
        # A path this script created is gone (removed above): an old .epma-bak next to it is only
        # a copy of the script's own earlier version, so it is dropped, never put back.
        if [ -e "$bak" ] || [ -L "$bak" ]; then
          done_any=1
          if [ "$DRY" = 1 ]; then
            change "$(shown "$bak"): would be removed (a copy of a file this script created)"
          else
            rm -f -- "${bak:?}"
            change "$(shown "$bak"): removed (a copy of a file this script created)"
          fi
        fi
        continue
      fi
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
      say "To go back: sudo bash $(script_ref) --undo"
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
  elif [ "$CHROOT" = 0 ] && ! firstboot_gate; then
    :
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
    if mode == MODE_SEED:  # the seed drive needs no ISO tools: no rsync, no wimlib (see LINUX_SEED_TOOLS)
        return [] if IS_MAC else [t for t in LINUX_SEED_TOOLS if not shutil.which(t)]
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
WINDOWS_HARDENING_SCRIPTS_DIR = "sources/$OEM$/$$/Setup/Scripts"  # `$$` is copied to %windir% by Windows Setup
WINDOWS_HARDENING_CMD = WINDOWS_HARDENING_SCRIPTS_DIR + "/SetupComplete.cmd"
WINDOWS_HARDENING_PS1 = WINDOWS_HARDENING_SCRIPTS_DIR + "/harden.ps1"
# hardening2 (WIN-SCRIPT): harden.ps1 has three modes and keeps the first-seen value of every setting it changes in a
# state file, so that -Mode Undo can put it back. The folder is created on the first change and limited to
# Administrators and SYSTEM by the script itself (Get-Acl / Set-Acl, inside try/catch: a failure only logs [WARN]).
WINDOWS_HARDENING_MODES = ("Apply", "Audit", "Undo")  # -Mode values; Apply is the default (what Setup runs)
WINDOWS_HARDENING_STATE_DIR = "EPMA"
WINDOWS_HARDENING_STATE_FILE = "hardening-state.json"
WINDOWS_HARDENING_STATE = "%ProgramData%\\" + WINDOWS_HARDENING_STATE_DIR + "\\" + WINDOWS_HARDENING_STATE_FILE
# Settings that only an explicit -DisableLegacyNetwork applies (never SetupComplete.cmd, never by default).
WINDOWS_HARDENING_OPTIN = ("netbios", "wpad")

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
     "Inserted USB sticks and discs no longer start installers or show the AutoPlay prompt, and phones and cameras "
     "no longer show the import-photos prompt; open them from File Explorer."),
    ("firewall", "Windows Firewall on for all network profiles, inbound blocked unless a rule allows it",
     "A program that must accept incoming connections (game server, file sharing, remote tools) needs an allow rule. "
     "The script runs once at the end of Setup and does not retry; the log says [WARN] if the firewall settings are not in effect."),
    ("defender_cloud", "Defender: block potentially unwanted apps and turn cloud protection on",
     "Some bundled freeware may be flagged, and cloud protection sends file metadata to Microsoft. "
     "The script runs once at the end of Setup and does not retry; Tamper Protection, another antivirus or a Defender "
     "that is not ready yet can stop the change, and the log then says [WARN]."),
    ("asr_lsass", "Defender attack surface rule in Block mode: no credential stealing from LSASS",
     "Rarely, security or backup tools that read LSASS memory are blocked and Defender shows a notification. "
     "The script runs once at the end of Setup and does not retry; the log says [WARN] if the rule is not in effect."),
    ("asr_audit", "Defender attack surface rules in Audit mode (log only): email executable content, Office child processes, obfuscated scripts, script-launched downloads",
     "Audit mode only writes events and blocks nothing. Review the Defender event log before switching any rule to Block. "
     "The script runs once at the end of Setup and does not retry; the log says [WARN] for a rule that is not in effect."),
    ("asr_audit_extra", "Defender attack surface rules in Audit mode (log only), more: abuse of exploited vulnerable signed drivers, process creation from PsExec and WMI commands, untrusted processes that run from USB drives",
     "Audit mode only writes events and blocks nothing; running programs from a USB stick or with remote-management tools adds events. Review the Defender event log before switching any rule to Block. "
     "The script runs once at the end of Setup and does not retry; the log says [WARN] for a rule that is not in effect."),
    ("wdigest", "Do not keep plain-text WDigest credentials in memory",
     "Only legacy digest authentication against very old web servers is affected."),
    ("ps_logging", "PowerShell script block logging",
     "Adds events to the PowerShell log; secrets typed inside a script would be logged as well."),
    ("ps2", "Disable the PowerShell 2.0 optional feature",
     "Very old scripts or tools that insist on running with -Version 2 stop working."),
    ("remote_assist", "Turn off Remote Assistance invitations",
     "Old-style Remote Assistance invitations stop working; Quick Assist and Remote Desktop are not changed."),
    ("audit", "Advanced audit policy: sign-ins, account lockouts, account and group changes, audit-policy changes, process creation; Security log size raised to 128 MiB",
     "The Security event log fills much faster (process creation and sign-ins are frequent events), so its maximum size is raised "
     "to 128 MiB (never lowered). Retention is still limited: on a busy PC the oldest events can be overwritten within days, "
     "so export the log if you need to keep it."),
    ("uac", "Keep User Account Control switched on",
     "Only acts when UAC was switched off; takes effect after the next restart."),
    ("netbios", "Opt-in (-DisableLegacyNetwork, never applied by default): turn off NetBIOS over TCP/IP on all network adapters",
     "Looking up or browsing machines by their NetBIOS name stops working on the adapters that exist now (very old file shares, printers or NAS boxes reached by a short name). "
     "It takes effect when the adapter reconnects or after a restart; adapters added later keep their default."),
    ("wpad", "Opt-in (-DisableLegacyNetwork, never applied by default): turn off WPAD proxy auto-discovery for WinHTTP",
     "A network that hands out its proxy only through WPAD (some offices and schools) no longer gives it to Windows services and apps that use WinHTTP, so they can lose internet access until a proxy is set by hand. "
     "The WinHTTP auto-proxy service itself is left running."),
)

# Deliberately NOT done, with the reason (shown in the script header and available to the README / help text).
WINDOWS_HARDENING_NOT_CHANGED = (
    ("bitlocker", "BitLocker is not turned on automatically",
     "It needs a TPM, a choice of where the recovery key goes and the owner's consent; a wrong default can lock someone out of their own data."),
    ("ntlm", "NTLM authentication levels are left as they are",
     "Stricter levels can break access to older file shares, printers and NAS devices without any warning."),
    ("accounts_disks", "Accounts, passwords, disks, language, licence and product key",
     "Windows Setup stays fully interactive; the hardening script never touches them."),
    ("device_guard", "Memory Integrity (HVCI), Credential Guard and Exploit Protection are only reported, never turned on",
     "They depend on the hardware, drivers and apps of each PC and can stop a PC from starting or a program from running; Audit mode shows their state so the owner can decide."),
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


# ===== hardening2: windows script (harden.ps1 with -Mode Apply|Audit|Undo) =====
# The script has three modes (-Mode Apply|Audit|Undo). Every setting has ONE code block per mode, kept in three
# dicts with the same keys: _WINDOWS_PS_CODE (Apply), _WINDOWS_PS_AUDIT (Audit, read-only) and _WINDOWS_PS_UNDO
# (Undo, puts back what Apply recorded). Each block runs inside its own try/catch and logs one line (or, for a
# few multi-part settings, one line per part): Apply and Undo use [OK]/[SKIP]/[WARN]/[FAIL] (Undo: [OK]/[SKIP]/
# [WARN]), Audit uses [OK] in effect / [DIFF] not in effect / [N/A]. `@WHAT@` is replaced by the setting's text
# from WINDOWS_HARDENING_SETTINGS. Only PowerShell 5.1 syntax; no network access, no downloads.
#
# NOTHING in this file was ever executed: pwsh is not available where it was written, so the PowerShell is
# checked structurally by the tests and nothing else. Test it on a throw-away Windows 11 first (Audit mode is
# a safe way to start: it changes nothing).

# Pairs (what Apply calls to record + change, what Undo calls to put it back). A test checks that every
# setting whose Apply block uses the first name has the second name in its Undo block.
WINDOWS_HARDENING_STATE_PAIRS = (
    ("Set-RegDword", "Restore-RegValue"),
    ("Set-AsrRule", "Restore-AsrRule"),
    ("Set-AuditSubcategory", "Restore-AuditSubcategory"),
    ("Save-FirewallState", "Restore-FirewallState"),
    ("Save-DefenderValue", "Restore-DefenderValue"),
    ("Save-FeatureState", "Restore-FeatureState"),
    ("Save-EventLogState", "Restore-EventLogState"),
)

# Attack surface reduction rules by GUID (Microsoft documentation names in the comments). Only rules whose GUID
# is certain are listed; the three of the second group are only ever set to Audit mode.
WINDOWS_ASR_LSASS = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"  # block credential stealing from LSASS (Block mode)
WINDOWS_ASR_AUDIT_RULES = (
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",  # block executable content from email client and webmail
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a",  # block all Office applications from creating child processes
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc",  # block execution of potentially obfuscated scripts
    "d3e037e1-3eb8-44c8-a917-57927947596d",  # block JavaScript or VBScript from launching downloaded executable content
)
WINDOWS_ASR_AUDIT_EXTRA_RULES = (
    "56a863a9-875e-4185-98a7-b882c64b5ce5",  # block abuse of exploited vulnerable signed drivers
    "d1e49aac-8f56-4280-b9ba-993a6d77406c",  # block process creations originating from PSExec and WMI commands
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4",  # block untrusted and unsigned processes that run from USB
)

# Advanced audit policy subcategories, addressed by GUID because their names are translated on non-English
# Windows. The GUIDs are not checked against a live system here: if auditpol rejects one, a FAIL line names it.
# List the valid ones with: auditpol /list /subcategory:* /v
# (guid, name, success wanted, failure wanted): Logon, Account Lockout, User Account Management, Security Group
# Management, Audit Policy Change (success and failure); Process Creation (success only, no command-line capture).
WINDOWS_AUDIT_SUBCATEGORIES = (
    ("{0CCE9215-69AE-11D9-BED3-505054503030}", "Logon", True, True),
    ("{0CCE9217-69AE-11D9-BED3-505054503030}", "Account Lockout", True, True),
    ("{0CCE9235-69AE-11D9-BED3-505054503030}", "User Account Management", True, True),
    ("{0CCE9237-69AE-11D9-BED3-505054503030}", "Security Group Management", True, True),
    ("{0CCE922F-69AE-11D9-BED3-505054503030}", "Audit Policy Change", True, True),
    ("{0CCE922B-69AE-11D9-BED3-505054503030}", "Process Creation", True, False),
)


def _ps_bool(value):
    return "$true" if value else "$false"


def _ps_reg_code(rows, optin=False, absent_ok=False):
    """(apply, audit, undo) PowerShell for a setting that is only DWORD registry values.

    rows = ((path, name, wanted int), ...). optin=True: Apply does nothing without -DisableLegacyNetwork and Audit
    does not count a missing setting. absent_ok=True: a value that does not exist counts as in effect in Audit
    (the Windows default already is the wanted state).
    """
    apply_l = ["try {"]
    names = []
    for i, (path, name, value) in enumerate(rows, 1):
        apply_l.append(f"    $c{i} = Set-RegDword -Path '{path}' -Name '{name}' -Value {value}")
        names.append(f"$c{i}")
    apply_l.append(f"    Write-Result 'OK' '@WHAT@' (Get-ChangeText ({' -or '.join(names)}))")
    apply_l += ["} catch {", "    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message", "}"]
    audit_l = ["try {", "    $good = @()", "    $bad = @()"]
    for path, name, value in rows:
        audit_l.append(f"    $cur = Get-RegDword -Path '{path}' -Name '{name}'")
        if absent_ok:
            audit_l.append(f"    if ($null -eq $cur) {{ $good += '{name} is not set (the Windows default is already {value})' }}")
            audit_l.append(f"    elseif ([int]$cur -eq {value}) {{ $good += '{name} is {value}' }}")
        else:
            audit_l.append(f"    if (($null -ne $cur) -and ([int]$cur -eq {value})) {{ $good += '{name} is {value}' }}")
        audit_l.append(f"    else {{ $bad += '{name} is ' + (Format-Value $cur) + ', wanted {value}' }}")
    flag = " -OptIn $true" if optin else ""
    audit_l += [
        "    if ($bad.Count -eq 0) {",
        "        Write-Audit 'OK' '@WHAT@' ($good -join '; ')",
        "    } else {",
        f"        Write-Audit 'DIFF' '@WHAT@' ($bad -join '; '){flag}",
        "    }",
        "} catch {",
        "    Write-Audit 'NA' '@WHAT@' ('could not be checked: ' + $_.Exception.Message)",
        "}",
    ]
    undo_l = ["try {", "    $r = @()"]
    for path, name, _value in rows:
        undo_l.append(f"    $r += Restore-RegValue -Path '{path}' -Name '{name}'")
    undo_l += [
        "    Write-UndoSummary '@WHAT@' $r",
        "} catch {",
        "    Write-Result 'WARN' '@WHAT@ not put back' $_.Exception.Message",
        "}",
    ]
    if optin:
        apply_l = (["try {",
                    "    if (-not $DisableLegacyNetwork) {",
                    "        Write-Result 'SKIP' '@WHAT@' 'opt-in, not requested (run with -DisableLegacyNetwork)'",
                    "    } else {"]
                   + ["    " + ln for ln in apply_l[1:-3]]
                   + ["    }", "} catch {", "    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message", "}"])
    return "\n".join(apply_l) + "\n", "\n".join(audit_l) + "\n", "\n".join(undo_l) + "\n"


def _ps_asr_audit_code(rules):
    """(apply, audit, undo) for a group of attack surface rules that are only ever set to Audit mode."""
    ids = ",\n".join(f"            '{r}'" for r in rules)
    ids_u = ",\n".join(f"        '{r}'" for r in rules)
    apply_code = f"""try {{
    if (-not (Get-Command Add-MpPreference -ErrorAction SilentlyContinue)) {{
        Write-Result 'SKIP' '@WHAT@' 'Defender cmdlets not available'
    }} else {{
        $rules = @(
{ids}
        )
        $applied = 0
        $missing = 0
        foreach ($id in $rules) {{
            $r = Set-AsrRule -Id $id -Action 'AuditMode'
            if ($r -eq 'changed') {{ $applied++ }}
            # In effect when the rule is in Audit mode, or already stricter (Block 1 or Warn 6).
            $now = Get-AsrAction $id
            if (($now -ne 2) -and ($now -ne 1) -and ($now -ne 6)) {{ $missing++ }}
        }}
        if ($missing -gt 0) {{
            Write-Result 'WARN' '@WHAT@ not in effect' ('' + $missing + ' of ' + $rules.Count + ' rules are not active; likely reason: Tamper Protection, another antivirus is active, or Defender is not ready yet')
        }} else {{
            Write-Result 'OK' '@WHAT@' ('' + $applied + ' of ' + $rules.Count + ' rules changed, the others were already set')
        }}
    }}
}} catch {{
    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message
}}
"""
    audit_code = f"""try {{
    if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {{
        Write-Audit 'NA' '@WHAT@' 'Defender cmdlets not available'
    }} else {{
        $rules = @(
{ids}
        )
        $off = @()
        foreach ($id in $rules) {{
            $now = Get-AsrAction $id
            if (($now -ne 2) -and ($now -ne 1) -and ($now -ne 6)) {{ $off += $id + ' (' + (Get-AsrActionName $now) + ')' }}
        }}
        if ($off.Count -eq 0) {{
            Write-Audit 'OK' '@WHAT@' ('all ' + $rules.Count + ' rules are in Audit mode or stricter')
        }} else {{
            Write-Audit 'DIFF' '@WHAT@' ('' + $off.Count + ' of ' + $rules.Count + ' rules not active: ' + ($off -join ', '))
        }}
    }}
}} catch {{
    Write-Audit 'NA' '@WHAT@' ('could not be checked: ' + $_.Exception.Message)
}}
"""
    undo_code = f"""try {{
    $r = @()
    foreach ($id in @(
{ids_u}
    )) {{
        $r += Restore-AsrRule $id
    }}
    Write-UndoSummary '@WHAT@' $r
}} catch {{
    Write-Result 'WARN' '@WHAT@ not put back' $_.Exception.Message
}}
"""
    return apply_code, audit_code, undo_code


def _ps_audit_items(indent):
    pad = " " * indent
    rows = [f"{pad}@('{g}', '{n}', {_ps_bool(s)}, {_ps_bool(f)})" for g, n, s, f in WINDOWS_AUDIT_SUBCATEGORIES]
    return ",\n".join(rows)


_REG_LLMNR = _ps_reg_code(((r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast", 0),))
_REG_AUTORUN = _ps_reg_code(((r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun", 255),
                             (r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoAutorun", 1)))
_REG_WDIGEST = _ps_reg_code(((r"HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential", 0),),
                            absent_ok=True)
_REG_PSLOG = _ps_reg_code(((r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
                            "EnableScriptBlockLogging", 1),))
_REG_REMOTE = _ps_reg_code(((r"HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance", "fAllowToGetHelp", 0),
                            (r"HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance", "fAllowFullControl", 0)))
# Only the WinHTTP DisableWpad value. The "WinHTTP Web Proxy Auto-Discovery" service (WinHttpAutoProxySvc) is left
# alone on purpose: stopping or disabling it breaks proxy handling for apps that need it. The per-user Internet
# Explorer "detect settings" switch lives under HKCU and belongs to each user, so a machine-wide script skips it.
_REG_WPAD = _ps_reg_code(((r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp", "DisableWpad", 1),),
                         optin=True)
_ASR_EXTRA = _ps_asr_audit_code(WINDOWS_ASR_AUDIT_EXTRA_RULES)
_ASR_BASE = _ps_asr_audit_code(WINDOWS_ASR_AUDIT_RULES)

_WINDOWS_PS_CODE = {
    "smb1": r"""
try {
    $c1 = Set-RegDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1' -Value 0
    $note = 'server side already off'
    if ($c1) { $note = 'server side turned off' }
    $state = Get-FeatureState 'SMB1Protocol'
    if ($null -eq $state) {
        $note = $note + '; optional feature not present'
    } elseif ($state -eq 'Enabled') {
        Save-FeatureState 'SMB1Protocol' $state
        Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -NoRestart | Out-Null
        $note = $note + '; optional feature disabled'
    } else {
        $note = $note + '; optional feature already off'
    }
    Write-Result 'OK' '@WHAT@' $note
} catch {
    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message
}
""",
    "llmnr": _REG_LLMNR[0],
    "autorun": _REG_AUTORUN[0],
    "firewall": r"""
try {
    $profiles = @(Get-NetFirewallProfile -Profile Domain,Private,Public)
    $todo = @($profiles | Where-Object { ($_.Enabled -ne 'True') -or ($_.DefaultInboundAction -ne 'Block') })
    $changedNote = 'already set'
    if ($todo.Count -gt 0) {
        Save-FirewallState
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block
        $changedNote = 'changed on ' + $todo.Count + ' profile(s)'
    }
    # Read the profiles back: "no error" is not the same as "in effect" (a Group Policy or another firewall can win).
    $after = @(Get-NetFirewallProfile -Profile Domain,Private,Public)
    $off = @($after | Where-Object { ($_.Enabled -ne 'True') -or ($_.DefaultInboundAction -ne 'Block') })
    if ($off.Count -eq 0) {
        Write-Result 'OK' '@WHAT@' $changedNote
    } else {
        Write-Result 'WARN' '@WHAT@ not in effect' ('still off or open on ' + $off.Count + ' profile(s); likely reason: Group Policy, another firewall product or the firewall service not ready yet')
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
            Save-DefenderValue 'PUAProtection' ([int]$pref.PUAProtection)
            Set-MpPreference -PUAProtection Enabled
            $changed += 'PUA protection'
        }
        if ([int]$pref.MAPSReporting -ne 2) {
            Save-DefenderValue 'MAPSReporting' ([int]$pref.MAPSReporting)
            Set-MpPreference -MAPSReporting Advanced
            $changed += 'cloud protection'
        }
        # Read the values back: the cmdlets can return without an error and still change nothing.
        $after = Get-MpPreference
        $missing = @()
        if ([int]$after.PUAProtection -ne 1) { $missing += 'PUA protection' }
        if ([int]$after.MAPSReporting -ne 2) { $missing += 'cloud protection' }
        if ($missing.Count -gt 0) {
            Write-Result 'WARN' '@WHAT@ not in effect' (($missing -join ', ') + ' still off; likely reason: Tamper Protection, another antivirus is active, or Defender is not ready yet')
        } elseif ($changed.Count -eq 0) {
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
        $ruleId = '@LSASS@'
        $r = Set-AsrRule -Id $ruleId -Action 'Enabled'
        $now = Get-AsrAction $ruleId
        if ($now -eq 1) {
            Write-Result 'OK' '@WHAT@' $r
        } else {
            Write-Result 'WARN' '@WHAT@ not in effect' 'rule is not in Block mode; likely reason: Tamper Protection, another antivirus is active, or Defender is not ready yet'
        }
    }
} catch {
    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message
}
""".replace("@LSASS@", WINDOWS_ASR_LSASS),
    "asr_audit": _ASR_BASE[0],
    "asr_audit_extra": _ASR_EXTRA[0],
    "wdigest": _REG_WDIGEST[0],
    "ps_logging": _REG_PSLOG[0],
    "ps2": r"""
try {
    $found = $false
    $disabled = $false
    foreach ($name in @('MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2')) {
        $state = Get-FeatureState $name
        if ($null -ne $state) {
            $found = $true
            if ($state -eq 'Enabled') {
                Save-FeatureState $name $state
                Disable-WindowsOptionalFeature -Online -FeatureName $name -NoRestart | Out-Null
                $disabled = $true
            }
        }
    }
    if (-not $found) {
        Write-Result 'SKIP' '@WHAT@' 'feature not present on this Windows build'
    } elseif ($disabled) {
        Write-Result 'OK' '@WHAT@' 'feature disabled'
    } else {
        Write-Result 'OK' '@WHAT@' 'already off'
    }
} catch {
    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message
}
""",
    "remote_assist": _REG_REMOTE[0],
    "audit": r"""
try {
    $items = @(
@AUDIT_ITEMS@
    )
    $bad = 0
    $changed = 0
    $backedUp = $false
    foreach ($item in $items) {
        $cur = Get-AuditSetting $item[0]
        # Already enough (or stricter) is left alone; an unreadable setting is set again.
        $satisfied = $cur.known -and ($cur.success -or (-not $item[2])) -and ($cur.failure -or (-not $item[3]))
        if (-not $satisfied) {
            try {
                if (-not $backedUp) {
                    Save-AuditBackup
                    $backedUp = $true
                }
                Set-AuditSubcategory $item[0] $item[2] $item[3]
                $changed++
            } catch {
                $bad++
                Write-Result 'FAIL' ('Audit subcategory ' + $item[1] + ' ' + $item[0]) ($_.Exception.Message + ' List valid GUIDs with: auditpol /list /subcategory:* /v')
            }
        }
    }
    # The Security log wraps quickly with these events, so raise its maximum size to 128 MiB. Only ever raised.
    $wantBytes = 134217728
    $sizeOk = $true
    $sizeNote = ''
    try {
        $oldBytes = [int64](Get-WinEvent -ListLog Security).MaximumSizeInBytes
        if ($oldBytes -ge $wantBytes) {
            $sizeNote = 'Security log size left at ' + [math]::Round($oldBytes / 1MB) + ' MiB (already 128 MiB or more)'
        } else {
            Save-EventLogState $oldBytes
            & wevtutil.exe sl Security ('/ms:' + $wantBytes) | Out-Null
            $newBytes = [int64](Get-WinEvent -ListLog Security).MaximumSizeInBytes
            if ($newBytes -ge $wantBytes) {
                $sizeNote = 'Security log size raised from ' + [math]::Round($oldBytes / 1MB) + ' MiB to ' + [math]::Round($newBytes / 1MB) + ' MiB'
            } else {
                $sizeOk = $false
                $sizeNote = 'Security log size is still ' + [math]::Round($newBytes / 1MB) + ' MiB (was ' + [math]::Round($oldBytes / 1MB) + ' MiB); a Group Policy may control it'
            }
        }
    } catch {
        $sizeOk = $false
        $sizeNote = 'could not raise the Security log size: ' + $_.Exception.Message
    }
    if (($bad -gt 0) -or (-not $sizeOk)) {
        Write-Result 'WARN' '@WHAT@ not fully in effect' ('' + $bad + ' of ' + $items.Count + ' subcategories rejected; ' + $sizeNote)
    } else {
        Write-Result 'OK' '@WHAT@' ('' + $items.Count + ' subcategories in effect (' + $changed + ' changed); ' + $sizeNote)
    }
} catch {
    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message
}
""".replace("@AUDIT_ITEMS@", _ps_audit_items(8)),
    "uac": r"""
try {
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $cur = Get-RegDword -Path $key -Name 'EnableLUA'
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
    "netbios": r"""
try {
    if (-not $DisableLegacyNetwork) {
        Write-Result 'SKIP' '@WHAT@' 'opt-in, not requested (run with -DisableLegacyNetwork)'
    } else {
        $base = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
        $names = @()
        if (Test-Path -LiteralPath $base) {
            $names = @(Get-ChildItem -LiteralPath $base | Where-Object { $_.PSChildName -like 'Tcpip_*' } | ForEach-Object { [string]$_.PSChildName })
        }
        if ($names.Count -eq 0) {
            Write-Result 'SKIP' '@WHAT@' 'no network interfaces found in the NetBT settings'
        } else {
            # NetbiosOptions: 0 = use the DHCP setting, 1 = on, 2 = off. Interfaces added later keep their default.
            $changed = 0
            foreach ($n in $names) {
                if (Set-RegDword -Path ($base + '\' + $n) -Name 'NetbiosOptions' -Value 2) { $changed++ }
            }
            Write-Result 'OK' '@WHAT@' ('' + $changed + ' of ' + $names.Count + ' interfaces changed, the others were already set; effective after the adapters reconnect or after a restart')
        }
    }
} catch {
    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message
}
""",
    "wpad": _REG_WPAD[0],
}

_WINDOWS_PS_AUDIT = {
    "smb1": r"""
try {
    $cur = Get-RegDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1'
    $state = Get-FeatureState 'SMB1Protocol'
    $bad = @()
    if (($null -eq $cur) -or ([int]$cur -ne 0)) { $bad += 'SMB1 server value is ' + (Format-Value $cur) + ', wanted 0' }
    if ($state -eq 'Enabled') { $bad += 'optional feature SMB1Protocol is Enabled' }
    if ($bad.Count -eq 0) {
        Write-Audit 'OK' '@WHAT@' 'SMB1 server value is 0 and the optional feature is off or not present'
    } else {
        Write-Audit 'DIFF' '@WHAT@' ($bad -join '; ')
    }
} catch {
    Write-Audit 'NA' '@WHAT@' ('could not be checked: ' + $_.Exception.Message)
}
""",
    "llmnr": _REG_LLMNR[1],
    "autorun": _REG_AUTORUN[1],
    "firewall": r"""
try {
    $after = @(Get-NetFirewallProfile -Profile Domain,Private,Public)
    $off = @($after | Where-Object { ($_.Enabled -ne 'True') -or ($_.DefaultInboundAction -ne 'Block') })
    if ($off.Count -eq 0) {
        Write-Audit 'OK' '@WHAT@' 'all three profiles are on with inbound blocked'
    } else {
        Write-Audit 'DIFF' '@WHAT@' ('off or open on ' + $off.Count + ' of ' + $after.Count + ' profile(s): ' + (($off | ForEach-Object { [string]$_.Name }) -join ', '))
    }
} catch {
    Write-Audit 'NA' '@WHAT@' ('could not be checked: ' + $_.Exception.Message)
}
""",
    "defender_cloud": r"""
try {
    if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
        Write-Audit 'NA' '@WHAT@' 'Defender cmdlets not available'
    } else {
        $pref = Get-MpPreference
        $bad = @()
        if ([int]$pref.PUAProtection -ne 1) { $bad += 'PUA protection is ' + [int]$pref.PUAProtection + ', wanted 1' }
        if ([int]$pref.MAPSReporting -ne 2) { $bad += 'cloud protection (MAPS) is ' + [int]$pref.MAPSReporting + ', wanted 2' }
        if ($bad.Count -eq 0) {
            Write-Audit 'OK' '@WHAT@' 'PUA protection and cloud protection are on'
        } else {
            Write-Audit 'DIFF' '@WHAT@' ($bad -join '; ')
        }
    }
} catch {
    Write-Audit 'NA' '@WHAT@' ('could not be checked: ' + $_.Exception.Message)
}
""",
    "asr_lsass": r"""
try {
    if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
        Write-Audit 'NA' '@WHAT@' 'Defender cmdlets not available'
    } else {
        $now = Get-AsrAction '@LSASS@'
        if ($now -eq 1) {
            Write-Audit 'OK' '@WHAT@' 'the rule is in Block mode'
        } else {
            Write-Audit 'DIFF' '@WHAT@' ('the rule action is: ' + (Get-AsrActionName $now))
        }
    }
} catch {
    Write-Audit 'NA' '@WHAT@' ('could not be checked: ' + $_.Exception.Message)
}
""".replace("@LSASS@", WINDOWS_ASR_LSASS),
    "asr_audit": _ASR_BASE[1],
    "asr_audit_extra": _ASR_EXTRA[1],
    "wdigest": _REG_WDIGEST[1],
    "ps_logging": _REG_PSLOG[1],
    "ps2": r"""
try {
    $found = $false
    $on = @()
    foreach ($name in @('MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2')) {
        $state = Get-FeatureState $name
        if ($null -ne $state) {
            $found = $true
            if ($state -eq 'Enabled') { $on += $name }
        }
    }
    if (-not $found) {
        Write-Audit 'NA' '@WHAT@' 'feature not present on this Windows build'
    } elseif ($on.Count -eq 0) {
        Write-Audit 'OK' '@WHAT@' 'the feature is off'
    } else {
        Write-Audit 'DIFF' '@WHAT@' ('still enabled: ' + ($on -join ', '))
    }
} catch {
    Write-Audit 'NA' '@WHAT@' ('could not be checked: ' + $_.Exception.Message)
}
""",
    "remote_assist": _REG_REMOTE[1],
    "audit": r"""
try {
    $items = @(
@AUDIT_ITEMS@
    )
    $bad = @()
    $unknown = 0
    foreach ($item in $items) {
        $cur = Get-AuditSetting $item[0]
        if (-not $cur.known) {
            $unknown++
        } else {
            $satisfied = ($cur.success -or (-not $item[2])) -and ($cur.failure -or (-not $item[3]))
            if (-not $satisfied) { $bad += $item[1] + ' is: ' + $cur.raw }
        }
    }
    $oldBytes = [int64](Get-WinEvent -ListLog Security).MaximumSizeInBytes
    if ($oldBytes -lt 134217728) { $bad += 'Security log size is ' + [math]::Round($oldBytes / 1MB) + ' MiB, wanted 128 MiB or more' }
    if ($bad.Count -gt 0) {
        Write-Audit 'DIFF' '@WHAT@' ($bad -join '; ')
    } elseif ($unknown -gt 0) {
        Write-Audit 'NA' '@WHAT@' ('the auditpol output of ' + $unknown + ' subcategories could not be read (a non-English Windows prints other words)')
    } else {
        Write-Audit 'OK' '@WHAT@' ('all ' + $items.Count + ' subcategories are set; Security log is ' + [math]::Round($oldBytes / 1MB) + ' MiB')
    }
} catch {
    Write-Audit 'NA' '@WHAT@' ('could not be checked: ' + $_.Exception.Message)
}
""".replace("@AUDIT_ITEMS@", _ps_audit_items(8)),
    "uac": r"""
try {
    $cur = Get-RegDword -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA'
    if (($null -ne $cur) -and ([int]$cur -eq 0)) {
        Write-Audit 'DIFF' '@WHAT@' 'EnableLUA is 0, so User Account Control is off'
    } else {
        Write-Audit 'OK' '@WHAT@' ('EnableLUA is ' + (Format-Value $cur) + ' (not 0)')
    }
} catch {
    Write-Audit 'NA' '@WHAT@' ('could not be checked: ' + $_.Exception.Message)
}
""",
    "netbios": r"""
try {
    $base = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
    $names = @()
    if (Test-Path -LiteralPath $base) {
        $names = @(Get-ChildItem -LiteralPath $base | Where-Object { $_.PSChildName -like 'Tcpip_*' } | ForEach-Object { [string]$_.PSChildName })
    }
    if ($names.Count -eq 0) {
        Write-Audit 'NA' '@WHAT@' 'no network interfaces found in the NetBT settings'
    } else {
        $on = @()
        foreach ($n in $names) {
            $cur = Get-RegDword -Path ($base + '\' + $n) -Name 'NetbiosOptions'
            if (($null -eq $cur) -or ([int]$cur -ne 2)) { $on += $n }
        }
        if ($on.Count -eq 0) {
            Write-Audit 'OK' '@WHAT@' ('NetBIOS over TCP/IP is off on all ' + $names.Count + ' interfaces')
        } else {
            Write-Audit 'DIFF' '@WHAT@' ('' + $on.Count + ' of ' + $names.Count + ' interfaces still use NetBIOS over TCP/IP') -OptIn $true
        }
    }
} catch {
    Write-Audit 'NA' '@WHAT@' ('could not be checked: ' + $_.Exception.Message)
}
""",
    "wpad": _REG_WPAD[1],
}

_WINDOWS_PS_UNDO = {
    "smb1": r"""
try {
    $r = @()
    $r += Restore-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1'
    Write-UndoSummary '@WHAT@' $r
    # An optional feature that was turned off is NOT turned on again here: that would bring SMBv1 back.
    $note = Restore-FeatureState 'SMB1Protocol'
    if ($null -ne $note) { Write-Result 'WARN' '@WHAT@ (optional feature not turned on again)' $note }
} catch {
    Write-Result 'WARN' '@WHAT@ not put back' $_.Exception.Message
}
""",
    "llmnr": _REG_LLMNR[2],
    "autorun": _REG_AUTORUN[2],
    "firewall": r"""
try {
    $r = @()
    $r += Restore-FirewallState
    Write-UndoSummary '@WHAT@' $r
} catch {
    Write-Result 'WARN' '@WHAT@ not put back' $_.Exception.Message
}
""",
    "defender_cloud": r"""
try {
    $r = @()
    $r += Restore-DefenderValue 'PUAProtection'
    $r += Restore-DefenderValue 'MAPSReporting'
    Write-UndoSummary '@WHAT@' $r
} catch {
    Write-Result 'WARN' '@WHAT@ not put back' ($_.Exception.Message + ' (Tamper Protection or another antivirus can block this)')
}
""",
    "asr_lsass": r"""
try {
    $r = @()
    $r += Restore-AsrRule '@LSASS@'
    Write-UndoSummary '@WHAT@' $r
} catch {
    Write-Result 'WARN' '@WHAT@ not put back' $_.Exception.Message
}
""".replace("@LSASS@", WINDOWS_ASR_LSASS),
    "asr_audit": _ASR_BASE[2],
    "asr_audit_extra": _ASR_EXTRA[2],
    "wdigest": _REG_WDIGEST[2],
    "ps_logging": _REG_PSLOG[2],
    "ps2": r"""
try {
    $notes = @()
    foreach ($name in @('MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2')) {
        $n = Restore-FeatureState $name
        if ($null -ne $n) { $notes += $n }
    }
    if ($notes.Count -eq 0) {
        Write-Result 'SKIP' '@WHAT@' 'nothing recorded, this script did not change it'
    } else {
        Write-Result 'WARN' '@WHAT@ (optional feature not turned on again)' ($notes -join ' | ')
    }
} catch {
    Write-Result 'WARN' '@WHAT@ not put back' $_.Exception.Message
}
""",
    "remote_assist": _REG_REMOTE[2],
    "audit": r"""
try {
    $r = @()
    foreach ($guid in @(
@AUDIT_GUIDS@
    )) {
        try {
            $r += Restore-AuditSubcategory $guid
        } catch {
            Write-Result 'WARN' ('Audit subcategory ' + $guid + ' not put back') $_.Exception.Message
        }
    }
    $sizeNote = Restore-EventLogState
    if ($null -ne $sizeNote) { $r += $sizeNote }
    Write-UndoSummary '@WHAT@' $r
} catch {
    Write-Result 'WARN' '@WHAT@ not put back' $_.Exception.Message
}
""".replace("@AUDIT_GUIDS@", ",\n".join(f"        '{g}'" for g, _n, _s, _f in WINDOWS_AUDIT_SUBCATEGORIES)),
    "uac": r"""
try {
    $r = @()
    $r += Restore-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA'
    Write-UndoSummary '@WHAT@' $r
} catch {
    Write-Result 'WARN' '@WHAT@ not put back' $_.Exception.Message
}
""",
    "netbios": r"""
try {
    $r = @()
    foreach ($k in @($script:State.Keys)) {
        if ($k -like 'reg|*\NetBT\Parameters\Interfaces\*|NetbiosOptions') {
            $rec = $script:State[$k]
            $r += Restore-RegValue -Path $rec.path -Name $rec.name
        }
    }
    if ($r.Count -eq 0) { $r += 'no record' }
    Write-UndoSummary '@WHAT@' $r
} catch {
    Write-Result 'WARN' '@WHAT@ not put back' $_.Exception.Message
}
""",
    "wpad": _REG_WPAD[2],
}

_WINDOWS_PS_HELPERS = r"""
$ErrorActionPreference = 'Stop'
$script:CountOk = 0
$script:CountSkip = 0
$script:CountWarn = 0
$script:CountFail = 0
$script:CountDiff = 0
$script:CountNa = 0
$script:LogToFile = $true
$script:State = @{}
$script:StateError = ''
$script:StateDir = Join-Path $env:ProgramData '@STATE_DIR@'
$script:StatePath = Join-Path $script:StateDir '@STATE_FILE@'
$script:AuditBackupPath = Join-Path $script:StateDir 'audit-policy-before.csv'

# Every line goes to the console; the log file gets it as well, unless Setup is running this script (see below).
function Write-Log {
    param([string]$Line)
    Write-Host $Line
    if ($script:LogToFile) {
        try {
            Add-Content -LiteralPath $LogPath -Value $Line -Encoding UTF8
        } catch {
            $script:LogToFile = $false
            Write-Host ('[WARN] cannot write the log file ' + $LogPath + ': ' + $_.Exception.Message)
        }
    }
}

# Apply and Undo: one log line per setting: [OK], [SKIP], [WARN] or [FAIL], what it was, and why. [OK] means the
# value was read back and is in effect; [WARN] means the command did not fail but the value is not in effect.
function Write-Result {
    param([string]$Status, [string]$What, [string]$Why)
    if ($Status -eq 'OK') { $script:CountOk++ }
    elseif ($Status -eq 'SKIP') { $script:CountSkip++ }
    elseif ($Status -eq 'WARN') { $script:CountWarn++ }
    else { $script:CountFail++ }
    Write-Log ('[' + $Status + '] ' + $What + ' (' + $Why + ')')
}

# Audit: [OK] in effect, [DIFF] not in effect, [N/A] cannot be told. With -OptIn a missing opt-in setting is
# reported as [N/A] (it was never requested) and is not counted as a difference.
function Write-Audit {
    param([string]$Verdict, [string]$What, [string]$Detail, [bool]$OptIn = $false)
    if (($Verdict -eq 'DIFF') -and $OptIn -and (-not $DisableLegacyNetwork)) {
        $Verdict = 'NA'
        $Detail = $Detail + '; opt-in setting, not requested (use -DisableLegacyNetwork), not counted'
    }
    if ($Verdict -eq 'OK') {
        $script:CountOk++
        Write-Log ('[OK] ' + $What + ' -- in effect (' + $Detail + ')')
    } elseif ($Verdict -eq 'DIFF') {
        $script:CountDiff++
        Write-Log ('[DIFF] ' + $What + ' -- not in effect (' + $Detail + ')')
    } else {
        $script:CountNa++
        Write-Log ('[N/A] ' + $What + ' -- ' + $Detail)
    }
}

function Write-Info {
    param([string]$Text)
    Write-Log ('[INFO] ' + $Text)
}

# Undo: one line for a setting from the results of the Restore-* calls ('no record' = nothing was recorded).
function Write-UndoSummary {
    param([string]$What, [string[]]$Results)
    $done = @($Results | Where-Object { $_ -ne 'no record' })
    if ($done.Count -eq 0) {
        Write-Result 'SKIP' $What 'nothing recorded, this script did not change it'
    } else {
        Write-Result 'OK' $What ('put back: ' + ($done -join ', '))
    }
}

function Get-ChangeText {
    param([bool]$Changed)
    if ($Changed) { return 'changed' }
    return 'already set'
}

function Format-Value {
    param($Value)
    if ($null -eq $Value) { return 'not set' }
    return [string]$Value
}

# Current value of a registry value or $null when the key or the value does not exist.
function Get-RegDword {
    param([string]$Path, [string]$Name)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    return $item.$Name
}

# ---- State for -Mode Undo --------------------------------------------------------------------------------------
# Before Apply changes a setting, the previous value is written to the state file (a JSON file under ProgramData).
# A value that is already in the file is never overwritten: it is the first value this script ever saw, which is
# what Undo puts back. The folder is created on the first change and limited to Administrators and SYSTEM.
# Audit mode never reads, creates or writes any of this.
function Initialize-StateFolder {
    if (Test-Path -LiteralPath $script:StateDir) { return }
    New-Item -ItemType Directory -Path $script:StateDir -Force | Out-Null
    try {
        $acl = Get-Acl -LiteralPath $script:StateDir
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sidText in @('S-1-5-18', 'S-1-5-32-544')) {
            $sid = New-Object System.Security.Principal.SecurityIdentifier($sidText)
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $acl.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $script:StateDir -AclObject $acl
    } catch {
        Write-Log ('[WARN] the state folder ' + $script:StateDir + ' could not be limited to Administrators and SYSTEM: ' + $_.Exception.Message)
    }
}

# Reads the state file into $script:State (a hashtable of hashtables). $false when the file exists but is unreadable.
function Import-State {
    $script:State = @{}
    if (-not (Test-Path -LiteralPath $script:StatePath)) { return $true }
    try {
        $raw = Get-Content -LiteralPath $script:StatePath -Raw -Encoding UTF8
        $doc = $raw | ConvertFrom-Json
        foreach ($p in $doc.entries.PSObject.Properties) {
            $h = @{}
            foreach ($q in $p.Value.PSObject.Properties) { $h[$q.Name] = $q.Value }
            $script:State[$p.Name] = $h
        }
        return $true
    } catch {
        $script:State = @{}
        $script:StateError = $_.Exception.Message
        return $false
    }
}

function Save-State {
    Initialize-StateFolder
    $doc = @{ version = 1; entries = $script:State }
    $json = $doc | ConvertTo-Json -Depth 6
    Set-Content -LiteralPath $script:StatePath -Value $json -Encoding UTF8
}

# Records one previous value, but only the first time. If the file cannot be written the exception stops the
# change that was about to follow (nothing is changed without a way back).
function Add-StateOnce {
    param([string]$Key, [hashtable]$Entry)
    if ($script:State.ContainsKey($Key)) { return }
    $script:State[$Key] = $Entry
    try {
        Save-State
    } catch {
        [void]$script:State.Remove($Key)
        throw
    }
}

function Remove-StateEntry {
    param([string]$Key)
    [void]$script:State.Remove($Key)
    Save-State
}

# Writes one DWORD only when it differs; the previous value (or its absence) is recorded first.
# Returns $true when it changed something.
function Set-RegDword {
    param([string]$Path, [string]$Name, [int]$Value)
    $current = $null
    $existed = $false
    $kind = ''
    if (Test-Path -LiteralPath $Path) {
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $item) {
            $existed = $true
            $current = $item.$Name
            $kind = [string](Get-Item -LiteralPath $Path).GetValueKind($Name)
        }
    }
    if ($existed -and ($kind -eq 'DWord') -and ([int]$current -eq $Value)) { return $false }
    Add-StateOnce ('reg|' + $Path + '|' + $Name) @{ kind = 'reg'; path = $Path; name = $Name; existed = $existed; type = $kind; value = $current } | Out-Null
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
    return $true
}

# Puts a registry value back (or removes it when it did not exist). An empty key that Apply created is left.
function Restore-RegValue {
    param([string]$Path, [string]$Name)
    $key = 'reg|' + $Path + '|' + $Name
    if (-not $script:State.ContainsKey($key)) { return 'no record' }
    $rec = $script:State[$key]
    if ($rec.existed) {
        $kind = [string]$rec.type
        if ($kind -eq 'DWord') { $val = [int]$rec.value }
        elseif ($kind -eq 'QWord') { $val = [int64]$rec.value }
        elseif (($kind -eq 'String') -or ($kind -eq 'ExpandString')) { $val = [string]$rec.value }
        else { throw ('the earlier value of ' + $Name + ' has the type ' + $kind + ', which this script cannot put back') }
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        New-ItemProperty -LiteralPath $Path -Name $Name -Value $val -PropertyType $kind -Force | Out-Null
        $result = 'restored ' + $Name
    } else {
        if (Test-Path -LiteralPath $Path) {
            Remove-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
        }
        $result = 'removed ' + $Name
    }
    Remove-StateEntry $key
    return $result
}

# State of an optional Windows feature ('Enabled', 'Disabled', ...) or $null when it does not exist. The list is
# read ONCE, on first use, and kept: Get-WindowsOptionalFeature is slow and Setup should finish quickly.
$script:Features = $null
$script:FeaturesError = $null
function Get-FeatureState {
    param([string]$Name)
    if ($null -eq $script:Features) {
        $script:Features = @{}
        try {
            foreach ($f in @(Get-WindowsOptionalFeature -Online)) {
                $script:Features[[string]$f.FeatureName] = [string]$f.State
            }
        } catch {
            $script:FeaturesError = $_.Exception.Message
        }
    }
    if ($null -ne $script:FeaturesError) { throw $script:FeaturesError }
    if ($script:Features.ContainsKey($Name)) { return $script:Features[$Name] }
    return $null
}

# An optional feature that is turned off cannot be turned on again by Undo (that could bring back SMBv1 or
# PowerShell 2.0 by accident): Undo only says which command to run.
function Save-FeatureState {
    param([string]$Name, [string]$State)
    Add-StateOnce ('feature|' + $Name) @{ kind = 'feature'; name = $Name; state = $State } | Out-Null
}

function Restore-FeatureState {
    param([string]$Name)
    $key = 'feature|' + $Name
    if (-not $script:State.ContainsKey($key)) { return $null }
    $rec = $script:State[$key]
    Remove-StateEntry $key
    return ($Name + ' was ' + $rec.state + ' before; to turn it on again run, as administrator: Enable-WindowsOptionalFeature -Online -FeatureName ' + $Name)
}

# Current action of one attack surface reduction rule (0 off, 1 Block, 2 Audit, 6 Warn) or $null when not listed.
function Get-AsrAction {
    param([string]$Id)
    $pref = Get-MpPreference
    if ($null -eq $pref.AttackSurfaceReductionRules_Ids) { return $null }
    $ids = @($pref.AttackSurfaceReductionRules_Ids)
    $actions = @($pref.AttackSurfaceReductionRules_Actions)
    for ($i = 0; $i -lt $ids.Count; $i++) {
        if ([string]$ids[$i] -ieq $Id) { return [int]$actions[$i] }
    }
    return $null
}

function Get-AsrActionName {
    param($Action)
    if ($null -eq $Action) { return 'not set' }
    if ($Action -eq 0) { return 'off' }
    if ($Action -eq 1) { return 'Block' }
    if ($Action -eq 2) { return 'Audit' }
    if ($Action -eq 6) { return 'Warn' }
    return ('action ' + $Action)
}

# Attack surface reduction rule: 'Enabled' (Block) or 'AuditMode'. A rule that is already Block or Warn is
# never weakened to Audit. The earlier action (or "not listed") is recorded first. Returns 'changed' or
# 'already set'; the caller reads the result back.
function Set-AsrRule {
    param([string]$Id, [string]$Action)
    $current = Get-AsrAction $Id
    $wanted = 2
    if ($Action -eq 'Enabled') { $wanted = 1 }
    if ($null -ne $current) {
        if ($current -eq $wanted) { return 'already set' }
        if (($wanted -eq 2) -and (($current -eq 1) -or ($current -eq 6))) { return 'already set' }
    }
    $listed = $true
    $was = -1
    if ($null -eq $current) { $listed = $false } else { $was = $current }
    Add-StateOnce ('asr|' + $Id.ToLower()) @{ kind = 'asr'; id = $Id.ToLower(); listed = $listed; action = $was } | Out-Null
    if ($wanted -eq 1) {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $Id -AttackSurfaceReductionRules_Actions Enabled
    } else {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $Id -AttackSurfaceReductionRules_Actions AuditMode
    }
    return 'changed'
}

# Puts a rule back to its recorded action (or removes it when it was not listed) and reads the result back.
function Restore-AsrRule {
    param([string]$Id)
    $key = 'asr|' + $Id.ToLower()
    if (-not $script:State.ContainsKey($key)) { return 'no record' }
    $rec = $script:State[$key]
    if ($rec.listed) {
        $names = @{ 0 = 'Disabled'; 1 = 'Enabled'; 2 = 'AuditMode'; 6 = 'Warn' }
        $name = $names[[int]$rec.action]
        if ($null -eq $name) { throw ('the earlier action ' + $rec.action + ' of rule ' + $Id + ' is not one this script knows') }
        Add-MpPreference -AttackSurfaceReductionRules_Ids $Id -AttackSurfaceReductionRules_Actions $name
    } else {
        Remove-MpPreference -AttackSurfaceReductionRules_Ids $Id
    }
    $now = Get-AsrAction $Id
    if ($rec.listed) { $ok = ($now -eq [int]$rec.action) } else { $ok = ($null -eq $now) }
    if (-not $ok) { throw ('rule ' + $Id + ' is not back at its earlier action (Tamper Protection, another antivirus or a Defender that is not ready can block this)') }
    Remove-StateEntry $key
    return ('rule ' + $Id.Substring(0, 8))
}

# Windows Firewall: the profile settings of the local store as they were before Apply.
function Save-FirewallState {
    foreach ($p in @(Get-NetFirewallProfile -Profile Domain,Private,Public -PolicyStore PersistentStore)) {
        Add-StateOnce ('fw|' + [string]$p.Name) @{ kind = 'fw'; name = [string]$p.Name; enabled = [string]$p.Enabled; inbound = [string]$p.DefaultInboundAction } | Out-Null
    }
}

function Restore-FirewallState {
    $done = @()
    foreach ($n in @('Domain', 'Private', 'Public')) {
        $key = 'fw|' + $n
        if (-not $script:State.ContainsKey($key)) { continue }
        $rec = $script:State[$key]
        $splat = @{ Profile = $n }
        # A value of NotConfigured cannot be set in the local store, so that part is left as it is now.
        if (($rec.enabled -eq 'True') -or ($rec.enabled -eq 'False')) { $splat['Enabled'] = $rec.enabled }
        if (($rec.inbound -eq 'Allow') -or ($rec.inbound -eq 'Block')) { $splat['DefaultInboundAction'] = $rec.inbound }
        if ($splat.Count -gt 1) { Set-NetFirewallProfile @splat }
        Remove-StateEntry $key
        $done += ('profile ' + $n)
    }
    if ($done.Count -eq 0) { return 'no record' }
    return ($done -join ', ')
}

# Defender preference (PUAProtection, MAPSReporting): the earlier numeric value.
function Save-DefenderValue {
    param([string]$Name, [int]$Value)
    Add-StateOnce ('mp|' + $Name) @{ kind = 'mp'; name = $Name; value = $Value } | Out-Null
}

function Restore-DefenderValue {
    param([string]$Name)
    $key = 'mp|' + $Name
    if (-not $script:State.ContainsKey($key)) { return 'no record' }
    $rec = $script:State[$key]
    $splat = @{}
    $splat[$Name] = [int]$rec.value
    Set-MpPreference @splat
    $pref = Get-MpPreference
    if ([int]$pref.$Name -ne [int]$rec.value) { throw ($Name + ' is not back at ' + $rec.value + ' (Tamper Protection or another antivirus can block this)') }
    Remove-StateEntry $key
    return ('restored ' + $Name)
}

# Advanced audit policy. auditpol prints the words of the Windows language, so only the English words are
# understood; anything else is reported as not known. The whole earlier policy is also saved once with
# "auditpol /backup" (a file that can be restored by hand in any language).
function Get-AuditSetting {
    param([string]$Guid)
    $out = @(& auditpol.exe /get ('/subcategory:' + $Guid) /r)
    $line = ''
    foreach ($l in $out) {
        if (([string]$l).Trim() -ne '') { $line = [string]$l }
    }
    $raw = ''
    $fields = $line.Split(',')
    if (($LASTEXITCODE -eq 0) -and ($fields.Count -ge 6)) { $raw = $fields[4].Trim() }
    $known = $true
    $s = $false
    $f = $false
    if ($raw -eq 'No Auditing') { }
    elseif ($raw -eq 'Success') { $s = $true }
    elseif ($raw -eq 'Failure') { $f = $true }
    elseif ($raw -eq 'Success and Failure') { $s = $true; $f = $true }
    else { $known = $false }
    return @{ raw = $raw; known = $known; success = $s; failure = $f }
}

function Save-AuditBackup {
    Initialize-StateFolder
    if (Test-Path -LiteralPath $script:AuditBackupPath) { return }
    try {
        & auditpol.exe /backup ('/file:' + $script:AuditBackupPath) | Out-Null
        if ($LASTEXITCODE -ne 0) { throw ('auditpol /backup exit code ' + $LASTEXITCODE) }
    } catch {
        Write-Log ('[WARN] could not save the whole earlier audit policy to ' + $script:AuditBackupPath + ': ' + $_.Exception.Message)
    }
}

# Turns on the wanted flags of one subcategory (never turns a flag off); the earlier setting is recorded first.
function Set-AuditSubcategory {
    param([string]$Guid, [bool]$Success, [bool]$Failure)
    $cur = Get-AuditSetting $Guid
    Add-StateOnce ('audit|' + $Guid) @{ kind = 'audit'; guid = $Guid; raw = $cur.raw; known = $cur.known; success = $cur.success; failure = $cur.failure } | Out-Null
    $flags = @()
    if ($Success) { $flags += '/success:enable' }
    if ($Failure) { $flags += '/failure:enable' }
    $out = & auditpol.exe /set ('/subcategory:' + $Guid) @flags | Out-String
    if ($LASTEXITCODE -ne 0) { throw ('auditpol rejected it (exit code ' + $LASTEXITCODE + '): ' + $out.Trim()) }
}

function Restore-AuditSubcategory {
    param([string]$Guid)
    $key = 'audit|' + $Guid
    if (-not $script:State.ContainsKey($key)) { return 'no record' }
    $rec = $script:State[$key]
    if (-not $rec.known) {
        throw ('the earlier setting of ' + $Guid + ' could not be read when it was recorded (' + $rec.raw + '), so it is not guessed; restore the whole earlier policy by hand with: auditpol /restore /file:' + $script:AuditBackupPath)
    }
    $s = '/success:disable'
    $f = '/failure:disable'
    if ($rec.success) { $s = '/success:enable' }
    if ($rec.failure) { $f = '/failure:enable' }
    $out = & auditpol.exe /set ('/subcategory:' + $Guid) $s $f | Out-String
    if ($LASTEXITCODE -ne 0) { throw ('auditpol rejected it (exit code ' + $LASTEXITCODE + '): ' + $out.Trim()) }
    Remove-StateEntry $key
    return ('audit ' + $Guid)
}

# The Security event log size is only ever raised; Undo never shrinks it (it only reports that).
function Save-EventLogState {
    param([int64]$Bytes)
    Add-StateOnce 'eventlog|Security' @{ kind = 'eventlog'; name = 'Security'; bytes = $Bytes } | Out-Null
}

function Restore-EventLogState {
    $key = 'eventlog|Security'
    if (-not $script:State.ContainsKey($key)) { return $null }
    $rec = $script:State[$key]
    Remove-StateEntry $key
    return ('Security log size not shrunk (it was ' + [math]::Round([int64]$rec.bytes / 1MB) + ' MiB before Apply and stays as it is)')
}
"""


# The script starts with its parameters. Everything is safe by default: no argument means "Apply", exactly what
# SetupComplete.cmd has always run; -DisableLegacyNetwork is an opt-in switch; the log path defaults to the file
# SetupComplete.cmd already appends to.
_WINDOWS_PS_PARAMS = r"""[CmdletBinding()]
param(
    [ValidateSet('Apply', 'Audit', 'Undo')]
    [string]$Mode = 'Apply',
    [switch]$DisableLegacyNetwork,
    [string]$LogPath = (Join-Path $env:windir 'Temp\epma-hardening.log')
)
"""

# Who is running, the log file decision, the state file. Runs after the helpers and before the first setting.
_WINDOWS_PS_START = r"""
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$isSystem = $identity.IsSystem

# Two ways to get here. (1) Windows Setup: SetupComplete.cmd runs this as SYSTEM with no arguments and appends the
# console output to the log file itself, so the script must not write the same lines to the file again.
# (2) An administrator on an installed Windows 11 (harden.cmd): the script writes the log file itself.
# Audit mode changes nothing, so it writes a file only when -LogPath is given on purpose.
if ((-not $PSBoundParameters.ContainsKey('LogPath')) -and ($isSystem -or ($Mode -eq 'Audit'))) {
    $script:LogToFile = $false
}

if (-not $isAdmin) {
    Write-Host '[FAIL] This script must run as administrator: right-click harden.cmd and choose Run as administrator, or start PowerShell as administrator. Nothing was changed.'
    if ($isSystem) { exit 0 }
    exit 1
}

if ($script:LogToFile) {
    try {
        $logDir = Split-Path -Parent $LogPath
        if ($logDir -and (-not (Test-Path -LiteralPath $logDir))) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
    } catch {
        $script:LogToFile = $false
        Write-Host ('[WARN] cannot create the folder of the log file ' + $LogPath + ': ' + $_.Exception.Message)
    }
}

Write-Log ('[START] EPMA hardening, mode ' + $Mode + ', ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
if ($Mode -eq 'Audit') {
    Write-Info 'Audit mode: nothing is changed, no state file is read or written.'
} else {
    Write-Info ('Earlier values are recorded in ' + $script:StatePath)
}

if ($Mode -ne 'Audit') {
    if (-not (Import-State)) {
        if ($Mode -eq 'Undo') {
            Write-Log ('[WARN] the state file ' + $script:StatePath + ' cannot be read (' + $script:StateError + '); nothing was put back.')
            if ($isSystem) { exit 0 }
            exit 1
        }
        # Apply: keep the unreadable file for the owner and start a new record.
        try {
            $aside = $script:StatePath + '.unreadable-' + (Get-Date -Format 'yyyyMMddHHmmss')
            Move-Item -LiteralPath $script:StatePath -Destination $aside -Force
            Write-Log ('[WARN] the state file could not be read (' + $script:StateError + '); it was renamed to ' + $aside + ' and a new one is started')
        } catch {
            Write-Log ('[FAIL] the state file ' + $script:StatePath + ' cannot be read and cannot be set aside (' + $_.Exception.Message + '); nothing was changed, because without a record there would be no way back.')
            if ($isSystem) { exit 0 }
            exit 1
        }
    } elseif (($Mode -eq 'Undo') -and ($script:State.Count -eq 0)) {
        Write-Info 'no earlier values are recorded (there is no state file or it is empty): every setting will be skipped'
    }
}
"""

# Audit mode only: read-only facts that this script never changes. They are NOT counted in the summary.
# None of this could be run where it was written (no Windows, no pwsh): every query is wrapped in its own
# try/catch and says what it could not read. Memory Integrity (HVCI) and Credential Guard are read from
# Win32_DeviceGuard and from the registry; "cannot verify offline" applies to this whole block.
_WINDOWS_PS_AUDIT_INFO = r"""
Write-Log ''
Write-Log '--- Read-only information (reported only; this script never turns these on) ---'

# BitLocker status of the system drive.
try {
    if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
        $vol = Get-BitLockerVolume -MountPoint $env:SystemDrive
        Write-Info ('BitLocker on ' + $env:SystemDrive + ' protection ' + (Format-Value $vol.ProtectionStatus) + ', volume status ' + (Format-Value $vol.VolumeStatus) + ', method ' + (Format-Value $vol.EncryptionMethod))
    } else {
        Write-Info 'BitLocker: the BitLocker cmdlets are not available on this Windows edition'
    }
} catch {
    Write-Info ('BitLocker: cannot read the status (' + $_.Exception.Message + ')')
}

# TPM.
try {
    if (Get-Command Get-Tpm -ErrorAction SilentlyContinue) {
        $tpm = Get-Tpm
        Write-Info ('TPM: present ' + (Format-Value $tpm.TpmPresent) + ', ready ' + (Format-Value $tpm.TpmReady) + ', enabled ' + (Format-Value $tpm.TpmEnabled))
    } else {
        Write-Info 'TPM: the Get-Tpm cmdlet is not available'
    }
} catch {
    Write-Info ('TPM: cannot read the status (' + $_.Exception.Message + ')')
}

# Secure Boot: the cmdlet throws on a PC that boots in legacy BIOS mode or that does not support it.
try {
    if (Confirm-SecureBootUEFI) {
        Write-Info 'Secure Boot: on'
    } else {
        Write-Info 'Secure Boot: off'
    }
} catch {
    Write-Info ('Secure Boot: cannot tell (' + $_.Exception.Message + ')')
}

# Microsoft Defender service and Tamper Protection.
try {
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        $mp = Get-MpComputerStatus
        Write-Info ('Microsoft Defender: service ' + (Format-Value $mp.AMServiceEnabled) + ', antivirus ' + (Format-Value $mp.AntivirusEnabled) + ', real-time protection ' + (Format-Value $mp.RealTimeProtectionEnabled) + ', Tamper Protection ' + (Format-Value $mp.IsTamperProtected))
    } else {
        Write-Info 'Microsoft Defender: the Defender cmdlets are not available'
    }
} catch {
    Write-Info ('Microsoft Defender: cannot read the status (' + $_.Exception.Message + ')')
}

# Every attack surface reduction rule that is configured, with its action.
try {
    if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
        $pref = Get-MpPreference
        $ids = @()
        if ($null -ne $pref.AttackSurfaceReductionRules_Ids) {
            $ids = @($pref.AttackSurfaceReductionRules_Ids)
        }
        $actions = @($pref.AttackSurfaceReductionRules_Actions)
        if ($ids.Count -eq 0) {
            Write-Info 'Attack surface reduction: no rule is configured'
        }
        for ($i = 0; $i -lt $ids.Count; $i++) {
            Write-Info ('Attack surface reduction rule ' + [string]$ids[$i] + ': ' + (Get-AsrActionName $actions[$i]))
        }
    }
} catch {
    Write-Info ('Attack surface reduction: cannot read the rules (' + $_.Exception.Message + ')')
}

# Memory Integrity (HVCI) and Credential Guard.
try {
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard'
    $running = @($dg.SecurityServicesRunning)
    $configured = @($dg.SecurityServicesConfigured)
    Write-Info ('Memory Integrity (HVCI): running ' + ($running -contains 2) + ', configured ' + ($configured -contains 2))
    Write-Info ('Credential Guard: running ' + ($running -contains 1) + ', configured ' + ($configured -contains 1))
    Write-Info ('Virtualization-based security status: ' + (Format-Value $dg.VirtualizationBasedSecurityStatus) + ' (0 off, 1 configured, 2 running)')
} catch {
    Write-Info ('Memory Integrity / Credential Guard: cannot read Win32_DeviceGuard (' + $_.Exception.Message + ')')
}
try {
    $hv = Get-RegDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name 'Enabled'
    $cg = Get-RegDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LsaCfgFlags'
    Write-Info ('Registry: Memory Integrity Enabled = ' + (Format-Value $hv) + ', Credential Guard LsaCfgFlags = ' + (Format-Value $cg))
} catch {
    Write-Info ('Registry: cannot read the Memory Integrity / Credential Guard values (' + $_.Exception.Message + ')')
}

# Exploit Protection (system-wide defaults).
try {
    if (Get-Command Get-ProcessMitigation -ErrorAction SilentlyContinue) {
        $mit = Get-ProcessMitigation -System
        Write-Info ('Exploit Protection (system): DEP ' + (Format-Value $mit.DEP.Enable) + ', SEHOP ' + (Format-Value $mit.SEHOP.Enable) + ', ASLR bottom-up ' + (Format-Value $mit.ASLR.BottomUp))
    } else {
        Write-Info 'Exploit Protection: the Get-ProcessMitigation cmdlet is not available'
    }
} catch {
    Write-Info ('Exploit Protection: cannot read the settings (' + $_.Exception.Message + ')')
}
"""

_WINDOWS_PS_END = {
    "Audit": r"""
Write-Log ('[DONE] ' + $script:CountOk + ' in effect, ' + $script:CountDiff + ' not in effect')
""",
    "Undo": r"""
try {
    if (($script:State.Count -eq 0) -and (Test-Path -LiteralPath $script:StatePath)) {
        Remove-Item -LiteralPath $script:StatePath -Force
        Write-Info 'nothing is left to put back: the state file was removed'
    }
} catch {
    Write-Log ('[WARN] the empty state file could not be removed: ' + $_.Exception.Message)
}
Write-Log '[NOTE] Not undone by this script: optional features that Apply turned off (SMBv1, PowerShell 2.0) stay off; the lines above give the Enable-WindowsOptionalFeature command if you really need them.'
Write-Log '[NOTE] The Security event log keeps its raised size (this script never shrinks it).'
Write-Log '[NOTE] A setting that was already in the wanted state before Apply was not recorded, so Undo leaves it alone.'
Write-Log '[NOTE] Audit policy is put back per subcategory from the recorded auditpol output (English Windows only). The whole earlier policy was also saved once; restore it by hand with: auditpol /restore /file:<that file>'
Write-Log '[NOTE] UAC and NetBIOS changes take full effect after a restart.'
Write-Log ('[DONE] ' + $script:CountOk + ' put back, ' + $script:CountSkip + ' skipped, ' + $script:CountWarn + ' warnings')
""",
    "Apply": r"""
Write-Log ('[DONE] ' + $script:CountOk + ' ok, ' + $script:CountSkip + ' skipped, ' + $script:CountWarn + ' not in effect, ' + $script:CountFail + ' failed')
""",
}


def _windows_ps_comment_lines(rows):
    out = []
    for sid, text, note in rows:
        out.append(f"#   {sid}: {text}")
        out.append(f"#       risk/why: {note}")
    return out


def _windows_ps_indent(code):
    return "\n".join(("    " + ln) if ln.strip() else ln for ln in code.strip("\n").split("\n"))


def _windows_harden_ps1():
    ids = [s[0] for s in WINDOWS_HARDENING_SETTINGS]
    if not (ids == list(_WINDOWS_PS_CODE) == list(_WINDOWS_PS_AUDIT) == list(_WINDOWS_PS_UNDO)):
        raise RuntimeError("PowerShell code blocks and hardening settings do not match")
    head = [
        "# EPMA USB CREATOR - optional hardened setup for Windows 11 (recommended settings inspired by common",
        "# baselines; this is NOT a compliance profile). One script, three situations:",
        "#   * Windows Setup: SetupComplete.cmd runs it once as SYSTEM with no arguments (mode Apply, today's behaviour).",
        "#   * An installed Windows 11: an administrator runs it (harden.cmd does), in any of the three modes.",
        "# Parameters:",
        "#   -Mode Apply   (default) applies the settings below. Before a setting is changed, its previous value is",
        "#                 recorded in " + WINDOWS_HARDENING_STATE + " (a value already recorded is",
        "#                 never overwritten). Safe to run again: it changes nothing that is already set.",
        "#   -Mode Audit   changes NOTHING and writes no state file: prints [OK] in effect / [DIFF] not in effect / [N/A]",
        "#                 per setting, then read-only facts (BitLocker, TPM, Secure Boot, Defender, attack surface",
        "#                 rules, Memory Integrity, Credential Guard, Exploit Protection), then a [DONE] line.",
        "#   -Mode Undo    puts back every recorded value (or removes a value that did not exist). It cannot turn",
        "#                 optional features on again (it prints the Enable-WindowsOptionalFeature command), it does not",
        "#                 shrink the Security log, and a setting that Apply found already set was never recorded.",
        "#   -DisableLegacyNetwork  opt-in: also turns off NetBIOS over TCP/IP and WPAD auto-discovery. Never applied",
        "#                 without it, and never from SetupComplete.cmd.",
        "#   -LogPath      log file (default %windir%\\Temp\\epma-hardening.log). Every line is also shown on the console.",
        "# PowerShell 5.1; no network access, no downloads, no extra tools (auditpol.exe and wevtutil.exe are part of",
        "# Windows). Every setting has its own error handler and writes one line per mode. Apply and Undo use [OK],",
        "# [SKIP], [WARN] or [FAIL]. It must be run as administrator (it refuses otherwise). The exit code is 0 in",
        "# Windows Setup; run by hand it is 1 only when it refuses to start (not an administrator, unreadable state).",
        "#",
        "# NOTHING in this file has been run on a real Windows: it was checked by structure tests only. Try Audit mode",
        "# first, on a test PC.",
        "#",
        "# The script runs ONCE, at the end of Windows Setup, and does NOT retry. Firewall, Defender and the attack",
        "# surface rules are read back after they are set: [OK] means the value is in effect; [WARN] means the command",
        "# did not fail but the value is not in effect (Tamper Protection, another antivirus, Defender or the firewall",
        "# service not ready yet). Run this file again as administrator to try those settings once more.",
        "#",
        "# Settings, each with the risk it carries:",
        *_windows_ps_comment_lines(WINDOWS_HARDENING_SETTINGS),
        "#",
        "# Deliberately NOT changed:",
        *_windows_ps_comment_lines(WINDOWS_HARDENING_NOT_CHANGED),
    ]
    body = []
    for sid, text, _risk in WINDOWS_HARDENING_SETTINGS:
        what = text.replace("'", "''")
        parts = [_windows_ps_indent(table[sid].replace("@WHAT@", what))
                 for table in (_WINDOWS_PS_CODE, _WINDOWS_PS_AUDIT, _WINDOWS_PS_UNDO)]  # Apply, Audit, Undo
        code = (
            "if ($Mode -eq 'Apply') {\n" + parts[0] + "\n"
            "} elseif ($Mode -eq 'Audit') {\n" + parts[1] + "\n"
            "} else {\n" + parts[2] + "\n"
            "}"
        )
        body.append(f"\n# setting: {sid}\n{code}\n")
    helpers = (_WINDOWS_PS_HELPERS
               .replace("@STATE_DIR@", WINDOWS_HARDENING_STATE_DIR)
               .replace("@STATE_FILE@", WINDOWS_HARDENING_STATE_FILE))
    tail = (
        "\nif ($Mode -eq 'Audit') {\n"
        + _windows_ps_indent(_WINDOWS_PS_AUDIT_INFO) + "\n"
        + _windows_ps_indent(_WINDOWS_PS_END["Audit"]) + "\n"
        + "} elseif ($Mode -eq 'Undo') {\n"
        + _windows_ps_indent(_WINDOWS_PS_END["Undo"]) + "\n"
        + "} else {\n"
        + _windows_ps_indent(_WINDOWS_PS_END["Apply"]) + "\n"
        + "}\nexit 0\n"
    )
    text = (
        "\n".join(head) + "\n"
        + _WINDOWS_PS_PARAMS
        + helpers
        + _WINDOWS_PS_START
        + "".join(body) + tail
    )
    return b"\xef\xbb\xbf" + text.replace("\n", "\r\n").encode("ascii")  # BOM: PowerShell 5.1 reads ANSI without it


def windows_hardening_ps1(profile):
    """The exact bytes of harden.ps1 (UTF-8 BOM, CRLF, pure ASCII) that hardening_files_windows() ships.

    Other parts of the program (the Windows seed drive) call this instead of private names. Empty bytes for
    HARDENING_NONE (nothing to add, like hardening_files_windows); an unknown profile raises ValueError.
    """
    if not _windows_hardening_check(profile):
        return b""
    return _windows_harden_ps1()
# ===== end hardening2: windows script =====


def hardening_files_windows(profile):
    """The files the Windows 11 install media gets for the hardened setup: {relative posix path: bytes}.

    Exactly two files, both under sources/$OEM$/$$/Setup/Scripts (Windows Setup copies `$$` to %windir%, so
    no answer file is needed and Setup stays fully interactive): SetupComplete.cmd and harden.ps1 (applied
    once at the end of Setup, logged to %windir%\\Temp\\epma-hardening.log). SetupComplete.cmd runs harden.ps1
    with no arguments (mode Apply); the same harden.ps1 (see windows_hardening_ps1) also has the Audit and Undo
    modes and the opt-in -DisableLegacyNetwork switch for an administrator on an installed Windows 11.
    Empty for HARDENING_NONE; an unknown profile raises ValueError.
    """
    if not _windows_hardening_check(profile):
        return {}
    return {
        WINDOWS_HARDENING_CMD: _windows_setupcomplete_cmd(),
        WINDOWS_HARDENING_PS1: _windows_harden_ps1(),
    }
# ===== end hardening: windows content =====


# ===== hardening2: windows xml =====
# The answer file (autounattend.xml) of the EXPERIMENTAL "during setup" seed drive. It lives on a SECOND small USB
# next to the Windows installer USB: Windows Setup looks for autounattend.xml on the root of removable drives.
#
# Design: the smallest file that can work, and nothing that could change how Setup behaves.
# * ONE pass, `specialize`, ONE component, Microsoft-Windows-Deployment, ONE RunSynchronousCommand. Every other
#   pass and setting is absent on purpose, so Windows Setup stays fully interactive (disk, language, licence,
#   account). No disk, product key, licence, account, locale, autologon, hardware-check or restart setting is declared.
# * The same command works whatever drive letter the seed drive gets: Setup caches the answer file and runs the
#   specialize pass on the first start of the new system, when the letters can differ from the ones seen in Setup.
#   So the command looks for the marker file on the drives D: to Z: and only acts where it finds it.
# * Path is a command line, not a batch file: nothing is doubled. It is handed to cmd.exe, which is also what makes
#   `for` and `if exist` available. The text after `/c` starts with `(`, not with a quote, so cmd does not strip any
#   quote character (it only strips when the first character after /c is a quote). `%d` is the single-percent loop
#   variable of the command line (a batch file would need `%%d`); it holds `D:` ... `Z:` (with the colon), so
#   the text never contains `%d:`, which cmd could read as the substring/replace syntax of a variable. The only character that XML must escape is `&`
#   (written `&amp;` in the file; a parser hands the plain `&` back, and a test re-reads it).
# * `exit 0` after the script (stops the search: the first drive with the marker wins) and `exit 0` after the loop
#   (nothing found): the exit code of this step is always 0, so a missing seed or a failing script never makes the
#   installation fail. Nothing restarts, shuts down or downloads anything.
# * amd64 only. UNVERIFIED: a processorArchitecture="arm64" component of the same name is probably right for
#   Windows 11 on ARM, but it could not be confirmed offline, so it is left out: those PCs simply skip this step
#   (use the "after install" mode there).
# * UNVERIFIED (no Windows, no ADK schema and no web access where this was written; never run on real Windows):
#   (1) that Setup accepts an answer file with only a specialize pass and stays interactive (published samples and
#   common practice say yes); (2) that a removable drive already has a letter when the specialize pass runs, i.e.
#   that the seed drive must stay plugged in until the first screens of the new Windows (region, network) appear;
#   (3) that Setup does not expand `%d` itself before the command runs; (4) that `if exist` on an empty card reader
#   or an unready drive is silent (cmd normally is); (5) the order Order/Path/Description (taken from published
#   Microsoft samples) and whether a non-zero exit would stop Setup (not relied on: the step always exits 0).
WINDOWS_SEED_ANSWER_FILE = "autounattend.xml"
WINDOWS_SEED_MARKER = "EPMA-SEED.txt"  # root of the seed drive; the answer file acts only where it finds this
WINDOWS_SEED_SCRIPT = "harden.ps1"  # root of the seed drive; run with -Mode Apply
WINDOWS_SEED_DRIVE_LETTERS = "DEFGHIJKLMNOPQRSTUVWXYZ"  # C: is the installed system; A: and B: are floppy letters
WINDOWS_SEED_PATH_MAX = 259  # documented limit of the Path element of RunSynchronousCommand
WINDOWS_SEED_DESCRIPTION = "EPMA USB CREATOR: run harden.ps1 from the seed drive, if one is plugged in"
WINDOWS_SEED_COMMAND = (
    "cmd /c (for %d in (" + " ".join(c + ":" for c in WINDOWS_SEED_DRIVE_LETTERS) + ") do if exist %d\\" + WINDOWS_SEED_MARKER
    + " (powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"%d\\" + WINDOWS_SEED_SCRIPT
    + "\" -Mode Apply & exit 0)) & exit 0"
)
WINDOWS_SEED_NAMESPACE = "urn:schemas-microsoft-com:unattend"


def windows_seed_autounattend(profile):
    """The autounattend.xml of the EXPERIMENTAL "during setup" Windows seed drive, as bytes.

    UTF-8 (ASCII only) with an XML declaration, CRLF line ends, deterministic. Only the specialize pass is declared
    (see the block comment above). Empty bytes for HARDENING_NONE; an unknown profile raises ValueError.
    """
    if not _windows_hardening_check(profile):
        return b""
    command = WINDOWS_SEED_COMMAND
    if len(command) > WINDOWS_SEED_PATH_MAX:  # a constant today; the check keeps a later edit honest
        raise ValueError("the seed answer file command is longer than the documented Path limit")
    lines = (
        '<?xml version="1.0" encoding="utf-8"?>',
        '<unattend xmlns="' + WINDOWS_SEED_NAMESPACE + '">',
        '  <settings pass="specialize">',
        '    <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64"'
        ' publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"'
        ' xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"'
        ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">',
        "      <RunSynchronous>",
        '        <RunSynchronousCommand wcm:action="add">',
        "          <Order>1</Order>",
        "          <Path>" + command.replace("&", "&amp;") + "</Path>",
        "          <Description>" + WINDOWS_SEED_DESCRIPTION + "</Description>",
        "        </RunSynchronousCommand>",
        "      </RunSynchronous>",
        "    </component>",
        "  </settings>",
        "</unattend>",
    )
    return ("\r\n".join(lines) + "\r\n").encode("ascii")


def describe_windows_seed_during_setup():
    """Plain English lines (ASCII) for the GUI and the help: what the EXPERIMENTAL "during setup" mode does and does not do.

    Every line has an entry in PT_BR (the GUI shows them through _()).
    """
    return [
        "EXPERIMENTAL: this mode has not been tested on a real Windows installation. If anything looks wrong, use the \"run after install\" mode instead.",
        "The seed drive carries an answer file (autounattend.xml). Windows Setup looks for that file on the root of removable drives, so plug the seed drive in next to the Windows installer drive before you start.",
        "The answer file adds one step, early on the first start of the new system: it looks for the file EPMA-SEED.txt on the drives D: to Z: and, where it finds it, runs harden.ps1 from that drive in Apply mode.",
        "Keep both drives plugged in until the first screens of the new Windows (region, keyboard, network) appear. If the seed drive is gone by then, nothing is hardened and the installation goes on normally.",
        "It does not choose or erase a disk, set a product key, accept licence terms, create accounts, set the language or region, skip the hardware checks, download anything or restart the PC. Setup stays interactive.",
        "If no drive has the marker file, nothing happens and Setup continues as usual.",
        "Only 64-bit Intel/AMD PCs (x64) are covered. On any other PC the answer file does nothing: use the \"run after install\" mode.",
    ]
# ===== end hardening2: windows xml =====


# ===== hardening: seed content =====
# The files of the "seed drive": a small second USB that is plugged in next to a Linux installer USB.
# Nothing here selects a disk, creates an account or stores a secret: storage, accounts and the final
# summary stay interactive in every installer. The hardening script is embedded as base64 inside the
# seed itself (so the seed works even when the other files are not read) and is also written as a
# plain file for reading and for running by hand. Output is deterministic: same input, same bytes.
SEED_LABELS = {SEED_UBUNTU: "CIDATA", SEED_FEDORA: "OEMDRV", SEED_DEBIAN: "EPMA-SEED"}
SEED_HARDEN_FILE = "harden-linux.sh"
SEED_LOG_NAME = "epma-hardening.log"  # written inside the installed system, in /var/log
SEED_BASE64_WIDTH = 76
# Debian's late_command is ONE command line handed to a shell, so every `echo` costs a few dozen bytes
# of overhead; long base64 lines keep that overhead small. A single argument may not be longer than
# MAX_ARG_STRLEN (131072 bytes on Linux): the generated command is refused above SEED_DEBIAN_LATE_MAX.
SEED_DEBIAN_B64_WIDTH = 4096
SEED_DEBIAN_LATE_MAX = 100000
SEED_README_WIDTH = 78
SEED_README_TITLES = {
    SEED_UBUNTU: "Ubuntu (autoinstall)",
    SEED_FEDORA: "Fedora / RHEL / Rocky / Alma (kickstart)",
    SEED_DEBIAN: "Debian (script + preseed)",
}
# The installer screens that stay interactive for Ubuntu: "*" means EVERY section, so storage and
# identity (and all the others) are asked on screen; the seed only adds late-commands.
SEED_UBUNTU_INTERACTIVE = ("*",)
SEED_PACKAGES_DEB = ("ufw", "auditd", "unattended-upgrades")
SEED_PACKAGES_RPM = ("firewalld", "audit", "dnf-automatic")


def _seed_check_args(target, profile):
    if target not in SEED_TARGETS:
        raise ValueError(f"Unknown seed target: {target!r} (use one of {', '.join(SEED_TARGETS)})")
    if profile == HARDENING_NONE:
        raise ValueError("The 'none' hardening profile has no seed files")
    if profile not in HARDENING_PROFILES:
        raise ValueError(f"Unknown hardening profile: {profile!r}")


def _seed_b64_lines(data, width=SEED_BASE64_WIDTH):
    """The base64 text of `data` cut into lines of `width` characters (plain ASCII: no '%', no quotes, no spaces)."""
    import base64
    text = base64.b64encode(data).decode("ascii")
    return [text[i:i + width] for i in range(0, len(text), width)]


def _seed_failure_echo(log):
    return ('echo "EPMA hardening failed (exit status $?); the installation goes on. Run it again later '
            'with: sudo bash /root/' + SEED_HARDEN_FILE + '" >> ' + log)


def _seed_ubuntu_user_data(script):
    log = "/target/var/log/" + SEED_LOG_NAME
    lines = [
        "#cloud-config",
        "# EPMA hardening seed for the Ubuntu installer (autoinstall). Read README.txt first.",
        "# Every section is interactive ('*'): all installer screens are asked on screen as usual and",
        "# this file only adds the late-commands below. No disk layout, no account, no password and no",
        "# key is stored here, and no packages: the script installs what it needs on the first boot.",
        "autoinstall:",
        "  version: 1",
        "  interactive-sections:",
    ]
    lines += ['    - "' + name + '"' for name in SEED_UBUNTU_INTERACTIVE]
    lines += [
        "  late-commands:",
        "    - |",
        "      mkdir -p /target/root /target/var/log",
        "      base64 -d > /target/root/" + SEED_HARDEN_FILE + " <<'EPMA_B64'",
    ]
    lines += ["      " + chunk for chunk in _seed_b64_lines(script)]
    lines += [
        "      EPMA_B64",
        "      chmod 700 /target/root/" + SEED_HARDEN_FILE,
        "      true",
        "    - |",
        "      if curtin in-target --target=/target -- /bin/bash /root/" + SEED_HARDEN_FILE
        + " --yes --chroot; then",
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
        "base64 -d > /root/" + SEED_HARDEN_FILE + " <<'EPMA_B64'",
    ]
    lines += _seed_b64_lines(script)
    lines += [
        "EPMA_B64",
        "chmod 700 /root/" + SEED_HARDEN_FILE,
        "if /bin/bash /root/" + SEED_HARDEN_FILE + " --yes --chroot; then",
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
        "base64 -d /root/harden-linux.b64 > /root/" + SEED_HARDEN_FILE
        + " && chmod 700 /root/" + SEED_HARDEN_FILE
        + " && rm -f /root/harden-linux.b64"
        + " && /bin/bash /root/" + SEED_HARDEN_FILE + " --yes --chroot"
        + " && echo EPMA-hardening-finished >> " + log
        + " || echo EPMA-hardening-failed-installation-goes-on >> " + log
    )
    steps = ["mkdir -p /target/root", ": > " + b64]
    steps += ["echo " + chunk + " >> " + b64 for chunk in _seed_b64_lines(script, SEED_DEBIAN_B64_WIDTH)]
    steps += ["in-target /bin/sh -c '" + inner + "'", "true"]
    size = len("; ".join(steps))
    if size > SEED_DEBIAN_LATE_MAX:
        raise ValueError(
            f"The Debian preseed late_command would be {size} bytes (the limit is {SEED_DEBIAN_LATE_MAX}; "
            "a single command argument may not exceed 131072 bytes): the hardening script is too large")
    lines = [
        "# EPMA hardening seed for the Debian installer (preseed). Read README.txt first.",
        "# Debian's installer does not find this drive by itself: see README.txt.",
        "# Only non-disk, language-neutral settings are here; disk, accounts and the rest are asked.",
        "d-i pkgsel/include string " + " ".join(SEED_PACKAGES_DEB),
        "d-i pkgsel/update-policy select unattended-upgrades",
        "# The script is carried as base64 text and rebuilt inside the new system. Any failure",
        "# is logged and ignored, so the installation always finishes.",
        "d-i preseed/late_command string \\",
    ]
    lines += ["    " + step + "; \\" for step in steps[:-1]]
    lines.append("    " + steps[-1])
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
             "files. Every installer screen stays interactive (the seed marks all sections as "
             "interactive): it still asks for language, keyboard, network, disk, your account and "
             "time zone, as usual. The seed only adds a hardening step at the end.")
        blank()
        para("The seed does not install any package during the install. The settings that need "
             "no package are written then; the packages ufw, auditd and unattended-upgrades are "
             "installed by the hardening script on the first boot of the installed system, so "
             "that first boot needs an internet connection (it tries again at the next boot, up "
             "to 5 times, and then gives up).")
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
        para("If sudo is not installed (Debian does not install it when you give root a password "
             "during the install), become root first and run it from there:")
        code("su -", "bash /path/to/harden-linux.sh")
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
    if target == SEED_FEDORA:
        firewall = ("the firewalld firewall is switched on; its default zone is left exactly as "
                    "Fedora/RHEL set it (the script does not make it stricter), and SSH is "
                    "allowed in that zone when the SSH server is in use")
    else:
        firewall = ("the ufw firewall blocks incoming connections by default, with SSH kept open "
                    "when the SSH server is in use (it is not switched on when Docker, libvirt or "
                    "LXD is found and you did not pass --yes)")
    for item in (firewall,
                 "audit logging of security-relevant events",
                 "automatic security updates",
                 "safer kernel and network settings (a setting that is already stricter is not "
                 "lowered)",
                 "conservative SSH server settings. The script tries not to lock you out, but "
                 "it cannot promise your login keeps working: it refuses root logins over SSH "
                 "only when a normal user in the sudo (Debian/Ubuntu) or wheel (Fedora/RHEL) "
                 "group exists, and refuses password logins only when such a user has a key in "
                 "authorized_keys. Otherwise it leaves those logins as they are and prints a "
                 "[WARN] line. It then asks sshd what is really in effect, because another "
                 "file (for example 50-cloud-init.conf) can override it. Keep your first SSH "
                 "session open and try a second one before you close it"):
        para(item, "- ", "  ")
    para("Every file it edits is first copied once to a .epma-bak backup, running it twice "
         "changes nothing more, and --dry-run shows what it would do without changing anything.")
    heading("How to undo")
    para("On the installed system run:")
    code("sudo bash harden-linux.sh --undo")
    if target == SEED_DEBIAN:
        para("(without sudo: become root with su - and run bash harden-linux.sh --undo. With the "
             "preseed of option (b), a copy of the script is also kept in /root/"
             + SEED_HARDEN_FILE + ").")
    else:
        para("(a copy of the script is also kept in /root/" + SEED_HARDEN_FILE
             + " on the installed system).")
    heading("A note on the word 'hardened'")
    para("These settings are inspired by common security baselines. They are a sensible starting "
         "point, not a compliance claim, certification or guarantee.")
    return "\n".join(out) + "\n"


def hardening_files_seed(target, profile, during_setup=False):
    """(FAT32 volume label, {relative_path: bytes}) of the seed drive for `target`.

    target: SEED_UBUNTU, SEED_FEDORA, SEED_DEBIAN or SEED_WINDOWS. profile: HARDENING_BASELINE (HARDENING_NONE
    has no files and raises ValueError, as do unknown targets and profiles). The files never choose a disk and
    never contain a password, hash or key; harden-linux.sh is exactly linux_hardening_script(profile).
    during_setup only matters for SEED_WINDOWS (EXPERIMENTAL answer file for Windows Setup); the three
    Linux targets ignore it."""
    _seed_check_args(target, profile)
    if target == SEED_WINDOWS:
        return _windows_seed_files(profile, bool(during_setup))
    text = linux_hardening_script(profile)
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
    files[SEED_HARDEN_FILE] = script
    files["README.txt"] = _seed_readme(target).encode("ascii")
    return SEED_LABELS[target], files
# ===== end hardening: seed content =====


# ===== hardening2: win-seed =====
# The Windows 11 seed drive: a second small USB with harden.cmd / audit.cmd / undo.cmd (double-click launchers that
# ask for administrator rights), harden.ps1 (windows_hardening_ps1) and a README. With during_setup=True (EXPERIMENTAL)
# it also carries autounattend.xml (windows_seed_autounattend) and a marker file the answer file looks for. Nothing
# here selects a disk, creates an account or stores a secret. Output is deterministic: same input, same bytes.
SEED_WINDOWS_LABEL = "EPMA-SEED"
SEED_LABELS[SEED_WINDOWS] = SEED_WINDOWS_LABEL
SEED_WINDOWS_MARKER = "EPMA-SEED.txt"
SEED_WINDOWS_README_WIDTH = 76
SEED_WINDOWS_LOG_SHOWN = "C:\\Windows\\Temp\\epma-hardening.log"  # the log of harden.ps1, as shown to the user
# (file name, harden.ps1 -Mode, asks "Continue? [y/N]" first, lines echoed before anything happens)
SEED_WINDOWS_LAUNCHERS = (
    ("harden.cmd", "Apply", True, (
        "EPMA USB CREATOR - hardening of this Windows PC. EXPERIMENTAL scripts.",
        "This applies a small set of recommended security settings with harden.ps1.",
        "Nothing is installed and nothing is downloaded. A log is written to",
        SEED_WINDOWS_LOG_SHOWN + ". Run audit.cmd first to see a report.",
    )),
    ("audit.cmd", "Audit", False, (
        "EPMA USB CREATOR - report on this Windows PC. EXPERIMENTAL scripts.",
        "This only reports which settings are in effect. It changes nothing.",
        "Nothing is installed and nothing is downloaded. Administrator rights are",
        "still needed because some of the checks cannot be read without them.",
    )),
    ("undo.cmd", "Undo", True, (
        "EPMA USB CREATOR - undo the hardening of this Windows PC. EXPERIMENTAL scripts.",
        "This asks harden.ps1 to put back the settings it changed earlier.",
        "Nothing is installed and nothing is downloaded. A log is written to",
        SEED_WINDOWS_LOG_SHOWN + ".",
    )),
)


def _windows_seed_launcher(name, mode, confirm, banner):
    """The bytes of one double-click launcher (CRLF, plain ASCII, no BOM).

    It re-launches itself as administrator when it is not (a UAC prompt), optionally asks `Continue? [y/N]`,
    runs harden.ps1 from its own folder (`%~dp0`, quoted: paths with spaces work) in the given mode and waits
    for a key so that the window stays open. It never deletes, formats or partitions anything."""
    ps = f'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0harden.ps1" -Mode {mode}'
    lines = [
        "@echo off",
        "setlocal",
        f"rem {name}: EPMA hardening seed for Windows 11 (EXPERIMENTAL scripts, see README.txt).",
        f"rem Runs harden.ps1 -Mode {mode} from this folder. Nothing is installed or downloaded.",
        f"title EPMA hardening - {mode}",
        'set "SELF=%~f0"',
        "echo.",
        *("echo " + text for text in banner),
        "echo.",
        "net session >nul 2>&1",
        "if not errorlevel 1 goto :admin",
        "fltmc >nul 2>&1",
        "if not errorlevel 1 goto :admin",
        'if /i "%~1"=="elevated" goto :noadmin',
        "echo Administrator rights are needed. Windows will now show a prompt:",
        "echo choose Yes to continue. A new window opens for the work.",
        "set \"SELF_PS=%SELF:'=''%\"",
        'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command '
        '"Start-Process -FilePath \'%SELF_PS%\' -ArgumentList \'elevated\' -Verb RunAs"',
        "if errorlevel 1 goto :noadmin",
        "exit /b 0",
        "",
        ":noadmin",
        "echo.",
        "echo Administrator rights were not granted. Nothing was changed.",
        "pause",
        "exit /b 1",
        "",
        ":admin",
    ]
    if confirm:
        lines += [
            'set "ANSWER="',
            'set /p "ANSWER=Continue? [y/N] "',
            'if /i "%ANSWER%"=="y" goto :run',
            'if /i "%ANSWER%"=="yes" goto :run',
            "echo.",
            "echo Cancelled. Nothing was changed.",
            "pause",
            "exit /b 1",
            "",
            ":run",
        ]
    lines += [
        ps,
        'set "RC=%errorlevel%"',
        "echo.",
        "echo Finished with exit code %RC%. Read the lines above: a WARN line means a",
        "echo setting is not in effect. A restart may be needed for a few settings.",
        "pause",
        "exit /b %RC%",
    ]
    return ("\r\n".join(lines) + "\r\n").encode("ascii")


def _windows_seed_readme(profile, during_setup):
    """README.txt of the Windows seed drive: ASCII, CRLF (Notepad), lines of at most 76 characters."""
    import textwrap
    out = []

    def para(text, bullet="", indent=""):
        out.extend(textwrap.wrap(text, SEED_WINDOWS_README_WIDTH, initial_indent=indent + bullet,
                                 subsequent_indent=indent + " " * len(bullet),
                                 break_on_hyphens=False, break_long_words=False))

    def blank():
        out.append("")

    def heading(text):
        blank()
        out.append(text.upper())

    out.append("EPMA HARDENING SEED - Windows 11 (experimental scripts)")
    out.append("=" * 60)
    heading("What this drive is")
    para("A small helper drive made by EPMA USB CREATOR. It holds a PowerShell script and three "
         "double-click launchers that apply a small set of recommended security settings to "
         "Windows 11. It is a SECOND small USB. It is NOT a Windows installer and it does not "
         "boot by itself. Nothing is installed and nothing is downloaded.")
    heading("Way 1 (recommended): run it after Windows is installed")
    for n, text in enumerate((
            "Install Windows 11 as usual, then sign in with an administrator account.",
            "Plug this drive in and open it in File Explorer.",
            "Right-click audit.cmd and choose Open (or double-click it) FIRST. It only shows a "
            "report of what is in effect and changes nothing.",
            "Then double-click harden.cmd. Windows asks for permission (the User Account Control "
            "prompt): choose Yes. Type y at 'Continue? [y/N]' to apply the settings.",
            "Read the lines it prints. A [WARN] line means that a setting is NOT in effect. "
            "Nothing was forced.",
            "To go back, double-click undo.cmd and type y.",
    ), 1):
        para(text, f"{n}. ")
    blank()
    para("A log is written to " + SEED_WINDOWS_LOG_SHOWN + ". A restart may be needed for a few "
         "settings. Running harden.cmd twice changes nothing more.")
    heading("What the script changes")
    for line in describe_hardening_windows(profile):
        para(line.split(" -- risk:", 1)[0], "- ", "  ")
    heading("What it leaves alone")
    for _sid, text, why in WINDOWS_HARDENING_NOT_CHANGED:
        para(text + ". " + why, "- ", "  ")
    heading("Read the files before you run them")
    para("harden.cmd, audit.cmd, undo.cmd and harden.ps1 are plain text files. Open them in "
         "Notepad (right-click, Open with) and read them first. Each launcher only asks for "
         "administrator rights, asks you to confirm, and runs harden.ps1 from this drive.")
    heading("Honest caveats")
    for text in (
            "These settings are inspired by common security baselines. They are a sensible "
            "starting point, not a compliance claim, certification or guarantee.",
            "The PowerShell script was never executed by its authors on a real Windows PC. Try it "
            "on a spare PC or in a virtual machine before you use it on a PC you depend on.",
            "Another antivirus program or Windows Tamper Protection can stop the Windows Defender "
            "settings from being changed. The script then prints a [WARN] line.",
            "Nothing here selects a disk, partitions or erases anything, and nothing creates an "
            "account or sets a password.",
    ):
        para(text, "- ", "  ")
    if during_setup:
        heading("EXPERIMENTAL: apply it while Windows is being installed")
        para("This drive also holds an answer file, autounattend.xml, and a small marker file, "
             + SEED_WINDOWS_MARKER + " (the answer file looks for it to find the letter of this "
             "drive: do not rename or remove it). This way of using the drive is EXPERIMENTAL "
             "and has not been tried by its authors on a real Windows PC. Way 1 above is the "
             "safer path.")
        blank()
        for n, text in enumerate((
                "Plug this drive in next to the Windows installer USB, before you start Setup.",
                "Start Windows Setup from the installer USB as usual.",
                "Setup then runs harden.ps1 at the end of the specialize phase. Setup still asks "
                "for the language, the disk, the edition and your account, as usual.",
                "Afterwards, run audit.cmd to see what is in effect.",
        ), 1):
            para(text, f"{n}. ")
        blank()
        para("If Setup complains about the answer file, unplug this drive and install normally, "
             "then use harden.cmd after installing.")
        para("If the installer USB already has its own autounattend.xml, it is not defined which "
             "one Windows uses: use only one of them.")
    return ("\r\n".join(out) + "\r\n").encode("ascii")


def _windows_seed_files(profile, during_setup):
    """(label, files) of the Windows seed drive; see hardening_files_seed."""
    ps1 = windows_hardening_ps1(profile)  # noqa: F821  (defined by the WIN-SCRIPT part)
    if not isinstance(ps1, bytes) or not ps1.strip():
        raise ValueError("The Windows hardening script is empty")
    files = {name: _windows_seed_launcher(name, mode, confirm, banner)
             for name, mode, confirm, banner in SEED_WINDOWS_LAUNCHERS}
    files["harden.ps1"] = ps1
    files["README.txt"] = _windows_seed_readme(profile, during_setup)
    if during_setup:
        xml = windows_seed_autounattend(profile)  # noqa: F821  (defined by the WIN-XML part)
        if not isinstance(xml, bytes) or not xml.strip():
            raise ValueError("The Windows answer file is empty")
        files["autounattend.xml"] = xml
        files[SEED_WINDOWS_MARKER] = (
            "EPMA hardening seed drive. This file marks the drive; the answer file looks for it.\r\n"
        ).encode("ascii")
    return SEED_WINDOWS_LABEL, files
# ===== end hardening2: win-seed =====


# ===== hardening: engine-seed =====
# The "seed drive": a small GPT + FAT32 drive with a special volume label that carries only the
# hardening seed files (cloud-init / kickstart / preseed + a script). It holds no operating system,
# so none of the ISO machinery is involved; the erase, the copy, the read-back and the eject follow
# the Windows-mode path (macos_build_usb / linux_build_usb) and keep all of its protections.
SEED_MAX_FILE_BYTES = 256 * 1024          # one seed file
SEED_MAX_TOTAL_BYTES = 2 * 1024 * 1024    # all seed files together
SEED_MAX_PATH_CHARS = 240                 # a relative path on the drive
SEED_MAX_FILES = 128
SEED_MIN_DRIVE_BYTES = 64 * 1024 * 1024   # a smaller drive is refused (it cannot hold a FAT32 volume anyway)
SEED_LABEL_MAX = 11                       # FAT volume labels have 11 characters at most
SEED_LABEL_RE = re.compile(r"[A-Z0-9_][A-Z0-9_-]{0,10}")  # used with fullmatch(); never starts with "-"
SEED_FAT_FORBIDDEN_CHARS = frozenset('"*:<>?|')  # not allowed in a FAT long file name (slashes are handled apart)
SEED_RESERVED_NAMES = frozenset(["CON", "PRN", "AUX", "NUL"]
                                + [f"COM{i}" for i in range(1, 10)] + [f"LPT{i}" for i in range(1, 10)])
# What the seed drive needs on Linux: no rsync, no wimlib-imagex (those are for copying a Windows ISO).
LINUX_SEED_TOOLS = ["parted", "mkfs.vfat", "wipefs", "partprobe"]
# Printed by the root seed script (exit status 0) when it stops on request: the drive was not touched yet,
# or it was (and is now incomplete).
SEED_UNTOUCHED_MARKER = "SEED_NOT_TOUCHED"
SEED_CANCELED_MARKER = "SEED_CANCELED"


def _seed_name(path):
    """A path for an error message: short and printable, whatever it contains."""
    text = path if len(path) <= 80 else path[:77] + "..."
    return repr(text)


def validate_seed_label(label):
    """The FAT32 volume label of a seed drive: 1 to 11 characters of A-Z 0-9 _ -, not starting with "-".

    Returns the label; raises ValueError otherwise. The label reaches `mkfs.vfat -n` / `diskutil eraseDisk` as
    one separate argument, but it is validated all the same so that nothing odd can ever get that far.
    """
    if not isinstance(label, str) or not SEED_LABEL_RE.fullmatch(label):
        raise ValueError(f"Invalid seed drive label {_seed_name(str(label))}: use 1 to {SEED_LABEL_MAX} characters "
                         "from A-Z, 0-9, '_' and '-' (not starting with '-').")
    return label


def _check_seed_path(path):
    """Raise ValueError unless `path` is a safe relative POSIX path that FAT32 can store."""
    shown = _seed_name(path)
    if not path:
        raise ValueError("A seed file has an empty path.")
    if "\x00" in path:
        raise ValueError(f"Seed file path {shown} contains a NUL character.")
    if "\\" in path:
        raise ValueError(f"Seed file path {shown} contains a backslash; use '/' to separate folders.")
    if len(path) > SEED_MAX_PATH_CHARS:
        raise ValueError(f"Seed file path {shown} is longer than {SEED_MAX_PATH_CHARS} characters.")
    if path.startswith("/"):
        raise ValueError(f"Seed file path {shown} is absolute; it must be relative to the root of the drive.")
    try:
        path.encode("utf-8")
    except UnicodeError:
        raise ValueError(f"Seed file path {shown} is not valid text.") from None
    if any(ord(c) < 32 or ord(c) == 127 for c in path):
        raise ValueError(f"Seed file path {shown} contains a control character.")
    for part in path.split("/"):
        if part in ("", "."):
            raise ValueError(f"Seed file path {shown} has an empty or '.' component.")
        if part == "..":
            raise ValueError(f"Seed file path {shown} contains '..'.")
        if part.endswith((" ", ".")):
            raise ValueError(f"Seed file path {shown} has a name ending in a space or a dot.")
        bad = SEED_FAT_FORBIDDEN_CHARS.intersection(part)
        if bad:
            raise ValueError(f"Seed file path {shown} contains {''.join(sorted(bad))!r}, which FAT32 cannot store.")
        if part.split(".")[0].rstrip().upper() in SEED_RESERVED_NAMES:
            raise ValueError(f"Seed file path {shown} uses a reserved device name.")


def validate_seed_files(files):
    """Check the files that are going to be written to a drive and return a cleaned copy.

    `files` is {relative_posix_path: bytes}. Every path must be relative (no leading "/", no "..", no
    backslash, no NUL, no control characters, at most 240 characters, nothing FAT32 cannot store); every
    file at most 256 KiB, all together at most 2 MiB; no two names may differ only by case (FAT32 is case
    insensitive), and no name may be both a file and a folder. "$" is an ordinary character (Windows media
    needs `sources/$OEM$/$$/...`). Raises ValueError with a message that names the first offending path.
    """
    if not isinstance(files, dict) or not files:
        raise ValueError("There are no seed files to write.")
    if len(files) > SEED_MAX_FILES:
        raise ValueError(f"Too many seed files ({len(files)}); the limit is {SEED_MAX_FILES}.")
    clean, folded, total = {}, {}, 0
    for path, data in files.items():
        if not isinstance(path, str):
            raise ValueError(f"A seed file path is not text: {type(path).__name__}.")
        _check_seed_path(path)
        if isinstance(data, (bytearray, memoryview)):
            data = bytes(data)
        if not isinstance(data, bytes):
            raise ValueError(f"Seed file {_seed_name(path)} is not bytes.")
        if len(data) > SEED_MAX_FILE_BYTES:
            raise ValueError(f"Seed file {_seed_name(path)} is {human_size(len(data))}; "
                             f"the limit is {human_size(SEED_MAX_FILE_BYTES)} per file.")
        total += len(data)
        if total > SEED_MAX_TOTAL_BYTES:
            raise ValueError(f"The seed files are larger than {human_size(SEED_MAX_TOTAL_BYTES)} together.")
        key = path.casefold()
        if key in folded:
            raise ValueError(f"Seed file {_seed_name(path)} has the same name as {_seed_name(folded[key])} "
                             "(FAT32 ignores letter case).")
        folded[key] = path
        clean[path] = data
    for key, path in folded.items():
        parts = key.split("/")
        for i in range(1, len(parts)):
            if "/".join(parts[:i]) in folded:
                raise ValueError(f"Seed file {_seed_name(path)} is inside {_seed_name(folded['/'.join(parts[:i])])}, "
                                 "which is a file.")
    return clean


def _seed_manifest_sha256(files):
    """SHA-256 over the names and contents of the seed files (for the audit trail)."""
    digest = hashlib.sha256()
    for path in sorted(files):
        digest.update(path.encode("utf-8") + b"\0" + str(len(files[path])).encode() + b"\0" + files[path])
    return digest.hexdigest()


def _seed_local_path(root, rel):
    """`rel` (already validated) below `root`; refuses anything that would resolve outside it."""
    full = os.path.join(root, *rel.split("/"))
    if os.path.commonpath([os.path.abspath(root), os.path.abspath(full)]) != os.path.abspath(root):
        raise ValueError(f"Seed file path {_seed_name(rel)} would leave the drive.")
    return full


def stage_seed_files(files):
    """Write the (validated) seed files to a new private directory and return its path (owner only, 0700)."""
    stage = tempfile.mkdtemp(prefix="epmaseed_")
    try:
        for rel, data in files.items():
            path = _seed_local_path(stage, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW, PRIVATE_FILE_MODE)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    return stage


def copy_seed_files(stage_dir, dst_root, files, log, progress=None, cancel_event=None):
    """Copy the staged seed files onto the mounted drive, flushing each one. Cancelable between files."""
    total = sum(len(d) for d in files.values())
    done = 0
    log(f"Copying {len(files)} seed file(s) to the USB drive...")
    for rel, data in files.items():
        check_canceled(cancel_event)
        dst = _seed_local_path(dst_root, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(_seed_local_path(stage_dir, rel), "rb") as src, open(dst, "wb") as out:
            shutil.copyfileobj(src, out)
            out.flush()
            os.fsync(out.fileno())
        done += len(data)
        log(rel)
        if progress:
            progress(min(done, total), total, "Copying files...")
    if progress:
        progress(total, total, "Flushing data to the drive...")
    check_canceled(cancel_event)
    log("Syncing writes to disk...")
    run_cmd(["sync"], log, check=False)


def verify_seed_files(files, dst_root, log, progress=None, cancel_event=None):
    """Read every seed file back from the drive and compare it byte for byte. Raises on any mismatch."""
    log("Verifying the seed files (reading them back from the drive)...")
    if progress:
        progress(0, 0, "Verifying the copied files...")
    bad = []
    for rel, data in files.items():
        check_canceled(cancel_event, written=True)
        path = _seed_local_path(dst_root, rel)
        try:
            if os.path.islink(path) or not os.path.isfile(path):
                bad.append(f"{rel} (missing)")
            elif os.path.getsize(path) != len(data):
                bad.append(f"{rel} (size differs)")
            else:
                with open(path, "rb") as fh:
                    if fh.read(len(data) + 1) != data:
                        bad.append(f"{rel} (content differs)")
        except OSError as e:
            bad.append(f"{rel} (unreadable: {e.strerror or type(e).__name__})")
    if bad:
        audit(f"VERIFICATION FAILED: {len(bad)} seed file(s) differ", logging.ERROR)
        raise RuntimeError(
            f"Verification FAILED: {len(bad)} file(s) on the drive are missing or differ from the seed "
            f"files (for example: {bad[0]}).\n\nThe drive was NOT ejected and should not be used.")
    audit("Verification passed (seed files match)")
    log("Verification passed: the seed files on the drive are identical to the originals.")


# Root script of the Linux seed drive: unmount, wipe, GPT + one FAT32 partition, label, mount for the user.
# Values arrive as "$1".."$6", never pasted into the text. "$6" is the cancel flag file (see cancel_flag):
# the script looks at it between its steps. Nothing is printed on success.
LINUX_SEED_PREP_SCRIPT = (
    'set -eu\n'
    "trap '' INT\n"
    'DEV="$1"; PART="$2"; LABEL="$3"; USB_MNT="$4"; OWNER="$5"; FLAG="$6"\n'
    'umount_parts() { for p in "$DEV"[0-9]* "$DEV"p[0-9]*; do umount "$p" 2>/dev/null || true; done; }\n'
    'if [ -e "$FLAG" ]; then echo SEED_NOT_TOUCHED; exit 0; fi\n'
    'umount_parts\n'
    # Unmounting changes no data, so a cancel seen here still leaves the drive as it was.
    'if [ -e "$FLAG" ]; then echo SEED_NOT_TOUCHED; exit 0; fi\n'
    'wipefs -a "$DEV"\n'
    'parted -s "$DEV" mklabel gpt\n'
    # No "esp" flag: this is a data drive, and an installer must never take it for an EFI system partition.
    'parted -s "$DEV" mkpart primary fat32 1MiB 100%\n'
    'partprobe "$DEV"\n'
    'udevadm settle --timeout=15 2>/dev/null || sleep 2\n'
    'i=0\n'
    'while [ ! -b "$PART" ] && [ "$i" -lt 20 ]; do sleep 1; i=$((i + 1)); done\n'
    '[ -b "$PART" ] || { echo "The new partition $PART did not appear." >&2; exit 1; }\n'
    'umount_parts\n'
    'if [ -e "$FLAG" ]; then echo SEED_CANCELED; exit 0; fi\n'
    'mkfs.vfat -F 32 -n "$LABEL" "$PART"\n'
    'udevadm settle --timeout=15 2>/dev/null || true\n'
    'umount_parts\n'
    'mount -o uid="${OWNER%%:*}",gid="${OWNER##*:}" "$PART" "$USB_MNT"\n'
)
# Remount the partition read-only so the check reads from the device and not from the cache.
LINUX_SEED_REMOUNT_SCRIPT = (
    'set -eu\n'
    "trap '' INT\n"
    'sync\n'
    'umount "$2"\n'
    '{ echo 3 > /proc/sys/vm/drop_caches; } 2>/dev/null || true\n'
    'mount -o ro,uid="${3%%:*}",gid="${3##*:}" "$1" "$2"\n'
)
LINUX_SEED_CLEANUP_SCRIPT = (
    'set -eu\n'
    "trap '' INT\n"
    'umount "$1" || true\n'
)


def macos_build_seed_usb(label, files, stage_dir, dev, log, progress=None, cancel_event=None, eject=True):
    check_canceled(cancel_event, drive_touched=False)  # nothing has been changed yet
    log(f"Erasing and formatting /dev/{dev} as GPT + FAT32 ('{label}')...")
    run_cmd(["diskutil", "eraseDisk", "FAT32", label, "GPT", f"/dev/{dev}"], log, timeout=600)
    try:
        target = macos_find_mountpoint_by_volname(dev, label)
        log(f"USB drive ready at: {target}")
        check_canceled(cancel_event)
        copy_seed_files(stage_dir, target, files, log, progress, cancel_event)
        log("Remounting the drive to read it back from the device...")
        macos_unmount(dev, log)
        run_cmd(["diskutil", "mountDisk", f"/dev/{dev}"], log, timeout=DISKUTIL_TIMEOUT)
        target = macos_find_mountpoint_by_volname(dev, label)
        verify_seed_files(files, target, log, progress, cancel_event)
    except OperationCanceled as e:
        if e.written:
            log("Canceled during verification. Unmounting the drive; the files were copied completely "
                "but NOT verified.")
        else:
            log("Canceled. Unmounting the drive; it is left incomplete and unusable.")
        macos_unmount(dev, log, check=False)
        raise
    ejected = macos_eject(dev, log) if eject else None
    log("Done! The seed drive is ready: plug it in next to the installer USB drive.")
    report_eject(ejected, log, skipped=not eject)
    return ejected


def linux_build_seed_usb(label, files, stage_dir, dev_name, log, priv, progress=None, cancel_event=None,
                         eject=True):
    check_canceled(cancel_event, drive_touched=False)  # nothing has been changed yet
    dev = f"/dev/{dev_name}"
    part = linux_partition_path(dev_name, 1)
    owner = f"{os.getuid()}:{os.getgid()}"
    usb_mount = tempfile.mkdtemp(prefix="epmaseed_usb_")
    state = {"untouched": False, "canceled": False}
    mounted = False

    def watch(line):
        text = line.strip()
        if text == SEED_UNTOUCHED_MARKER:
            state["untouched"] = True
        elif text == SEED_CANCELED_MARKER:
            state["canceled"] = True
        else:
            log(line)

    log(f"Erasing and formatting {dev} as GPT + FAT32 ('{label}') (administrator privileges required)...")
    try:
        # Marked BEFORE the script runs: its last command is the mount, and an interrupt (or an error) that
        # arrives right after it must still reach the unmount below. Unmounting a volume that was never
        # mounted is harmless (`umount ... || true`).
        mounted = True
        with cancel_flag(cancel_event) as flag:
            # Every value arrives as a positional parameter ("$1".."$6"), never pasted into the script.
            priv.run_script(LINUX_SEED_PREP_SCRIPT, watch, args=[dev, part, label, usb_mount, owner, flag])
        if state["untouched"]:
            mounted = False  # the script stopped on request before the mount
            log("Canceled before the drive was touched; nothing was changed.")
            raise OperationCanceled("Canceled by the user before the drive was touched.", drive_touched=False)
        if state["canceled"]:
            mounted = False  # stopped between the wipe and the format: nothing is mounted
            raise OperationCanceled("Canceled by the user.")
        check_canceled(cancel_event)
        copy_seed_files(stage_dir, usb_mount, files, log, progress, cancel_event)
        log("Remounting the drive read-only to read it back from the device...")
        priv.run_script(LINUX_SEED_REMOUNT_SCRIPT, log, args=[part, usb_mount, owner])
        verify_seed_files(files, usb_mount, log, progress, cancel_event)
    except OperationCanceled as e:
        if e.written:
            log("Canceled during verification. The files were copied completely but NOT verified.")
        elif e.drive_touched:
            log("Canceled. The drive is left incomplete and unusable.")
        raise
    finally:
        if mounted:
            log("Unmounting...")
            try:
                priv.run_script(LINUX_SEED_CLEANUP_SCRIPT, log, args=[usb_mount])
            except Exception as cleanup_err:
                log(f"Warning: cleanup failed: {cleanup_err}")
        _silent_rmdir(usb_mount)

    ejected = linux_eject(dev_name, log, priv) if eject else None
    log("Done! The seed drive is ready: plug it in next to the installer USB drive.")
    report_eject(ejected, log, skipped=not eject)
    return ejected


def check_seed_target_size(size):
    """Refuse a drive whose KNOWN size (bytes) is under SEED_MIN_DRIVE_BYTES; an unknown size (0/None) passes.

    Pure and cheap: the window and the command line call it right after the drive is chosen, before any
    dialog or password prompt; build_seed_usb calls it again. Raises ValueError with a friendly message.
    """
    if size and size < SEED_MIN_DRIVE_BYTES:
        raise ValueError(f"The drive ({human_size(size)}) is too small for a seed drive "
                         f"(at least {human_size(SEED_MIN_DRIVE_BYTES)}). Nothing was changed.")


def build_seed_usb(target, dev, log, priv, expected_size=None, progress=None, cancel_event=None, eject=True,
                   profile=HARDENING_BASELINE, during_setup=False):
    """Create a seed drive for `target` (ubuntu, fedora, debian or windows): GPT + FAT32 with the label and the
    files `hardening_files_seed(target, profile)` returns, verified by reading every file back, then ejected.

    `during_setup` (EXPERIMENTAL) is only valid with SEED_WINDOWS: the drive then also carries an answer
    file (autounattend.xml) that makes Windows Setup run the hardening script. Any other target raises
    ValueError before anything is touched.

    Returns True if the drive was ejected. Raises ValueError (nothing touched) for a bad target, label, file
    set or drive, and OperationCanceled on a cancel (see its docstring: `drive_touched` is False when nothing on
    the drive was changed).
    """
    if target not in SEED_TARGETS:
        raise ValueError(f"Unknown seed target: {target!r}")
    if profile not in HARDENING_PROFILES:
        raise ValueError(f"Unknown hardening profile: {profile!r}")
    during_setup = bool(during_setup)
    if during_setup and target != SEED_WINDOWS:  # hardening2: the answer-file mode exists for Windows only
        raise ValueError("The during-setup (answer file) mode is only available for the Windows seed drive. "
                         "Nothing was changed.")
    validate_device_name(dev)
    if target == SEED_WINDOWS:  # the other targets have no such option
        label, files = hardening_files_seed(target, profile, during_setup=during_setup)
    else:
        label, files = hardening_files_seed(target, profile)
    label = validate_seed_label(label)
    files = validate_seed_files(files)
    check_seed_target_size(expected_size)
    missing = get_missing_dependencies(MODE_SEED)
    if missing:
        raise ValueError(f"Cannot continue: required tool(s) not found: {', '.join(missing)}. "
                         f"{missing_dependencies_hint(missing)} Nothing was changed.")
    stage_dir = stage_seed_files(files)  # still before the drive is touched
    try:
        try:
            reverify_target_disk(dev, expected_size, log)
            check_canceled(cancel_event, drive_touched=False)
        except OperationCanceled:
            # The safety re-check changes nothing: the drive is exactly as it was.
            audit(f"OPERATION CANCELED by the user before the drive was touched (/dev/{dev}); nothing was changed",
                  logging.WARNING)
            raise OperationCanceled("Canceled by the user before the drive was touched.",
                                    drive_touched=False) from None
        audit(f"DESTRUCTIVE OPERATION START: erasing /dev/{dev} and writing the {target} hardening seed "
              f"(profile={profile}, label={label}, {'during_setup=True, ' if during_setup else ''}"
              f"files={len(files)}, "
              f"bytes={sum(len(d) for d in files.values())}, sha256={_seed_manifest_sha256(files)})")
        try:
            with prevent_sleep(log):
                if IS_MAC:
                    ejected = macos_build_seed_usb(label, files, stage_dir, dev, log, progress=progress,
                                                   cancel_event=cancel_event, eject=eject)
                else:
                    ejected = linux_build_seed_usb(label, files, stage_dir, dev, log, priv, progress,
                                                   cancel_event, eject)
        except OperationCanceled as e:
            if not e.drive_touched:
                audit(f"DESTRUCTIVE OPERATION CANCELED by the user on /dev/{dev} before the drive was touched; "
                      "nothing was changed", logging.WARNING)
            elif e.written:
                audit(f"DESTRUCTIVE OPERATION CANCELED by the user on /dev/{dev} during verification; "
                      "the seed files were written but NOT verified", logging.WARNING)
            else:
                audit(f"DESTRUCTIVE OPERATION CANCELED by the user on /dev/{dev}; the drive was left unusable",
                      logging.WARNING)
            raise
        except Exception as e:
            audit(f"DESTRUCTIVE OPERATION FAILED on /dev/{dev}: {type(e).__name__}", logging.ERROR)
            raise
        audit(f"DESTRUCTIVE OPERATION COMPLETED on /dev/{dev} (ejected={bool(ejected)}"
              f"{', during_setup=True' if during_setup else ''})")
        return bool(ejected)
    finally:
        shutil.rmtree(stage_dir, ignore_errors=True)
# ===== end hardening: engine-seed =====


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
    windows_settings = "\n".join("• " + line.split(" -- risk:")[0] for line in
                                 describe_hardening_windows(HARDENING_BASELINE))
    windows_not_changed = "\n".join("• " + text + ": " + why for _id, text, why in WINDOWS_HARDENING_NOT_CHANGED)
    return [
        ("Overview", f"""EPMA USB CREATOR {__version__} writes a bootable USB drive from an ISO image on macOS and Linux.

## Four image types and the hardening seed (five cards)
• Google Chrome — ChromeOS Flex, Google's free ChromeOS for PCs and Macs. The disk image is written byte for byte, like a Linux ISO. The program can download Google's official image for you.
• Windows 11 — erases the drive, creates a GPT partition table with one FAT32 partition (label {VOL_NAME}) and copies the files of the ISO. The result boots on UEFI computers. Windows' install.wim / install.esd is usually larger than the 4 GB FAT32 limit, so it is split into .swm parts with wimlib-imagex.
• Linux and Other ISO — both write the ISO byte for byte to the whole drive (like dd). Use Linux for Ubuntu, Debian, Fedora, Mint, Arch and other "hybrid" images, and Other ISO for any other bootable image. An ISO that cannot boot from a USB drive is refused before anything is erased.
• Hardening seed (optional, the fifth card) — needs no image. It erases a second, small USB drive and writes auto-install settings on it for Ubuntu, Fedora/RHEL or Debian. See "Hardened setup (optional)".

## What always happens
• Only drives attached over USB are offered. The system disk and internal disks are never listed.
• Everything on the selected drive is erased. Nothing is kept.
• After writing, the drive is read back and compared with the ISO (a hardening seed drive: every file compared byte for byte). Only a drive that passes is ejected.

## The window, from top to bottom
• The top row shows the program name and version, a status chip for the tools it needs ("Ready" in green, "Missing tools" in amber with "Install missing dependencies" next to it) and "Help", which opens this documentation (F1 does the same).
• The page has three numbered steps. 1 Image type: five equal cards. Four choose the type of image (Google Chrome (ChromeOS Flex), Windows 11, Linux and Other ISO); the fifth, "Hardening seed", makes a separate drive and needs no image file.
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
• Wait for the progress bar. When the green box says the drive was verified and ejected, unplug it.

## Optional: hardened settings
• On the "Windows 11" card, tick "Add hardening settings to the Windows installation (optional)" before you click Create. Click "What does it change?" to read the list. See "Hardened setup (optional)" for what it does and does not do.

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

## Optional: a hardened install
• Linux ISOs cannot take extra files after they are written, so the hardening settings go on a SECOND, small USB drive made with the "Hardening seed" card. See "Hardened setup (optional)".

## 3. On macOS: the drive will not appear in Finder
• macOS cannot read Linux (ISO 9660 / ext) images, so Finder shows nothing and macOS may say "The disk you attached was not readable".
• Click "Ignore". Never click "Initialize" — it would erase what was just written.
• This is normal. The content was already verified byte for byte."""),

        ("Hardened setup (optional)", f"""## What it is
• Optional files that make a fresh install start from safer settings ("Hardened (recommended settings)"). The settings are inspired by common security baselines. This program does NOT claim that the result complies with, or is certified by, any standard.
• Nothing here chooses a disk, creates an account or sets a password or key. Windows Setup and the Linux installers stay interactive: you still pick the disk, the language and your own account.
• Every hardening script prints each change, keeps a backup of anything it modifies and can be undone. They were checked with simulated systems and automated tests only, so try them on a spare computer or a virtual machine before relying on them.
• Want to read the files first? The command line "harden-files" writes them into a folder without touching any drive.

## Windows 11 (same USB drive)
• Tick "Add hardening settings to the Windows installation (optional)" on the "Windows 11" card. The files are copied onto the same USB drive and checked byte for byte with the rest.
• Windows Setup runs a script at the END of the installation. Its log will be C:\\Windows\\Temp\\epma-hardening.log. The script runs once and does not retry: a line marked [WARN] means a setting was not in effect (for example another antivirus or Tamper Protection got in the way).
• If the image already contains one of these files, the program stops BEFORE erasing the drive and tells you, because the files would replace the image's own.

## What the Windows option changes
{windows_settings}

## What it deliberately leaves alone
{windows_not_changed}

## Linux and others (a second USB drive)
• Choose the "Hardening seed" card, pick the target system, select a small USB drive (64 MiB or more) and click "Create Seed Drive". The drive is erased and checked like any other; it is NOT an installer.
• Keep your normal installer USB and plug the seed drive in next to it before you start the installer.
• Ubuntu (autoinstall): the drive is named CIDATA. At the boot menu add the word autoinstall to the boot line (the README.txt on the drive shows the exact steps). Every installer screen stays interactive.
• Fedora / RHEL (kickstart): the drive is named OEMDRV and the installer finds it by itself. Disk, accounts and the summary stay interactive.
• Debian (script + preseed): the installer does NOT find this drive by itself. After installing, mount the drive and run the script as administrator (sudo bash harden-linux.sh, or su - if there is no sudo).
• The script harden-linux.sh is a plain text file on the drive: read it before you use it. It supports --dry-run (changes nothing), --yes, --undo and --help, and it appends to /var/log/epma-hardening.log.
• It tries not to lock you out of SSH: it only turns off root login or password login when an administrator account with a key exists, and it says so. It does not enable a firewall on a computer that runs Docker, libvirt or LXD unless you pass --yes. Test a second SSH session before you close the first.

## Undo
• Linux: run the script again with --undo. It restores the files it backed up and removes the ones it created. It does not uninstall packages or turn services off.
• Windows: the changes are ordinary Windows settings; the log lists each one.""".replace("\\\\", "\\")),

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
• Hardening seed: a separate small drive (GPT + FAT32) with auto-install files; no image file is needed, so the image step is hidden and the button reads "Create Seed Drive".

## Dependencies
• Windows mode needs wimlib (macOS: brew install wimlib). On Linux it also needs parted, mkfs.vfat (dosfstools), wipefs, partprobe, rsync and wimlib-imagex.
• The Google Chrome, Linux and Other ISO cards need nothing extra. The Hardening seed card needs only parted, mkfs.vfat, wipefs and partprobe on Linux and nothing extra on macOS.
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
• write --iso ISO --disk DISK [--mode auto|windows|linux|chromeos] [--hardened] [--dry-run] [--yes] [--no-eject] [--json] [-v] — write a drive.
• harden-seed --target ubuntu|fedora|debian|windows [--during-setup] --disk DISK [--dry-run] [--yes] [--no-eject] [--json] [-v] — erase a small separate USB drive and write the hardening seed files on it. --during-setup (EXPERIMENTAL) is only for --target windows.
• harden-files --target windows|windows-seed|ubuntu|fedora|debian [--during-setup] --out DIR [--json] — write the hardening files into a new or empty folder. "windows" is the set for the same USB drive as Windows; "windows-seed" is the set for the Windows seed drive. --during-setup (EXPERIMENTAL) is only for windows-seed. No drive is involved and no administrator rights are needed.
• gui, or no command — open this window.
• --version, --help — program version and the full help.

## write
• --dry-run shows the plan and changes nothing. It is the safest way to try a command.
• Without --yes you are asked to type the disk identifier. When there is no terminal, --yes is required.
• Verification is always performed. There is no option to skip it.
• --hardened (Windows mode only; anything else is a usage error) adds the optional Hardened (recommended settings) files to the same USB drive. --dry-run lists their names.

## harden-seed and harden-files
• harden-seed asks for the same confirmation as write (type the disk identifier, or pass --yes), checks the drive the same way, verifies what it wrote and ejects. The seed drive is erased like any other target.
• The seed files never choose a disk, never partition or format anything and never create accounts or set passwords: storage and the user account stay interactive in the installer.
• harden-seed --target windows makes the Windows 11 seed drive (label EPMA-SEED): harden.cmd, audit.cmd, undo.cmd, harden.ps1 and a README to run as administrator on an installed Windows. With --during-setup (EXPERIMENTAL) it also adds an answer file (autounattend.xml) and a marker file so that Windows Setup runs the hardening script by itself; --dry-run lists every file name and says so. Any other target with --during-setup is a usage error (exit {EXIT_USAGE}).
• harden-files refuses a folder that is not empty and never overwrites anything.

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
    """A square, clickable choice: one of the cards (image types and the hardening seed) at the top of the window.

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
        elif self.key == CARD_SEED:             # a shield with a tick: the hardening seed
            self.create_polygon(cx, cy - 21, cx + 17, cy - 14, cx + 17, cy + 2, cx + 10, cy + 14, cx, cy + 21,
                                cx - 10, cy + 14, cx - 17, cy + 2, cx - 17, cy - 14, outline=glyph, fill="",
                                width=3, joinstyle="round")
            self.create_line(cx - 8, cy, cx - 2, cy + 7, cx + 8, cy - 6, fill=glyph, width=3, capstyle="round",
                             joinstyle="round")
        else:                                   # a disc
            self.create_oval(cx - 20, cy - 20, cx + 20, cy + 20, outline=glyph, width=3)
            self.create_oval(cx - 6, cy - 6, cx + 6, cy + 6, outline=glyph, width=3)
        font, shown = self._fit(self._title_font, self._title)
        self.create_text(cx, 82, text=shown, fill=text_color, font=font)
        font, shown = self._fit(self._sub_font, self._subtitle)
        self.create_text(cx, 103, text=shown, fill="#8e8e93", font=font)

    def _fit_font(self, font, text):
        """`font` (a family, size[, style] tuple), made smaller until `text` fits inside the card (never below
        8 pt): five cards share the width of the window, so a longer title or a translation must not overflow."""
        return self._fit(font, text)[0]

    def _fit(self, font, text):
        """(font, text) that fit inside the card: the font shrinks down to 8 pt, and when the text is still too
        wide at 8 pt it is cut and ends with an ellipsis (it is never clipped silently by the card edge)."""
        family, size, *style = font
        room = self._cw - 16
        weight = "bold" if style else "normal"
        while size > 8 and tkfont.Font(family=family, size=size, weight=weight).measure(text) > room:
            size -= 1
        measure = tkfont.Font(family=family, size=size, weight=weight).measure
        if measure(text) > room:
            ellipsis = "\u2026"
            cut = len(text)
            while cut > 0 and measure(text[:cut].rstrip() + ellipsis) > room:
                cut -= 1
            text = text[:cut].rstrip() + ellipsis
        return (family, size, *style), text


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


# ===== hardening: gui =====
WINDOWS_HARDENING_LOG_SHOWN = "C:\\Windows\\Temp\\epma-hardening.log"  # where the log is after Windows setup
# ===== end hardening: gui =====

# ===== hardening2: GUI =====
# The choices of the "Hardening seed" card. Each radio button has a key; this table says what the key means for the
# engine: (seed target, during_setup). Windows has two choices: run the scripts after Windows is installed (the
# robust one) or let Windows Setup run them through an answer file (EXPERIMENTAL).
SEED_CHOICE_WINDOWS_SETUP = "windows-setup"
SEED_CHOICES = {
    SEED_UBUNTU: (SEED_UBUNTU, False),
    SEED_FEDORA: (SEED_FEDORA, False),
    SEED_DEBIAN: (SEED_DEBIAN, False),
    SEED_WINDOWS: (SEED_WINDOWS, False),
    SEED_CHOICE_WINDOWS_SETUP: (SEED_WINDOWS, True),
}
# ===== end hardening2: GUI =====


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
        for column in range(len(CARD_ORDER)):  # equal columns sharing the window width
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
            (CARD_SEED, _("Hardening seed"), _("Auto-install files")),
        )):
            card = OptionCard(row, key, title, subtitle, self.select_card)
            # Worked out for five cards: each card is its cell minus 10 px wide and two neighbours are 12 px
            # apart (the left padding grows by 2 px per column, the right one shrinks by 2 px).
            card.grid(row=0, column=column, sticky="ew", padx=(2 * column, 10 - 2 * column))
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
        self._build_hardening_option(f)
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

        self._build_seed_panel(self.panels[CARD_SEED])

        for panel in self.panels.values():
            panel.grid_remove()
        # The progress bars appear only when a download runs.
        self.windows_dl.hide_bar()
        self.flex_dl.hide_bar()

    # ===== hardening: GUI =====
    # The Windows option (a checkbox on the Windows 11 card) and the "Hardening seed" card. The files themselves
    # and the writing of the second drive come from the engine (hardening_files_*, build_usb(hardening=...),
    # build_seed_usb); this part only asks for them and goes through the same safety flow as every other write.
    @staticmethod
    def seed_target_texts():
        """(choice key, translated name) for the five radio buttons of the Hardening seed card. The key is a
        key of SEED_CHOICES (it says which seed target and whether the answer file is included)."""
        return (
            (SEED_UBUNTU, _("Ubuntu (autoinstall)")),
            (SEED_FEDORA, _("Fedora / RHEL (kickstart)")),
            (SEED_DEBIAN, _("Debian (script + preseed)")),
            (SEED_WINDOWS, _("Windows 11 (run after install)")),
            (SEED_CHOICE_WINDOWS_SETUP, _("Windows 11 (during setup, experimental)")),
        )

    def _build_hardening_option(self, panel):
        """The optional hardening checkbox of the Windows 11 card: off by default, remembered only while the
        program runs (the variable lives as long as the window), with a one-line explanation and a link that
        lists what it changes."""
        self.hardening_var = tk.BooleanVar(self, value=False)  # master=self: never another window's interpreter
        box = ttk.Frame(panel)
        box.pack(fill="x", pady=(10, 0))
        self.hardening_check = ttk.Checkbutton(
            box, text=_("Add hardening settings to the Windows installation (optional)"),
            variable=self.hardening_var)
        self.hardening_check.pack(anchor="w")
        ttk.Label(
            box, justify="left", wraplength=PANEL_WRAP - 24, foreground="#8e8e93",
            text=_("Adds a few files to the same drive. A script applies the settings at the END of Windows setup "
                   "and writes its log to {log}.").format(log=WINDOWS_HARDENING_LOG_SHOWN)
        ).pack(anchor="w", padx=(24, 0))
        self.hardening_toggle = _Disclosure(box, _("What does it change?"), _("Hide the list"),
                                            self._on_hardening_details_toggled)
        self.hardening_toggle.pack(anchor="w", padx=(24, 0), pady=(2, 0))
        self.hardening_details = ttk.Label(box, justify="left", wraplength=PANEL_WRAP - 40, text="")

    @staticmethod
    def _hardening_details_text():
        """The list of settings the Windows option applies, straight from the engine's own description."""
        lines = [_(text) for text in map(str, describe_hardening_windows(HARDENING_BASELINE))]
        lines = [line if line.startswith("•") else "• " + line for line in lines]
        footer = _("The settings are applied at the end of Windows setup by a script, and every change is written "
                   "to {log}. You choose the disk, the account and the edition during setup as usual."
                   ).format(log=WINDOWS_HARDENING_LOG_SHOWN)
        return "\n".join([*lines, "", footer])

    def _on_hardening_details_toggled(self, is_open):
        if is_open:
            self.hardening_details.config(text=self._hardening_details_text())
            self.hardening_details.pack(anchor="w", padx=(24, 0), pady=(2, 0), after=self.hardening_toggle)
        else:
            self.hardening_details.pack_forget()
        self.after_idle(self._fit_window)

    def hardening_selected(self, mode=None):
        """HARDENING_BASELINE when the Windows option is ticked and Windows is what is written, else HARDENING_NONE.
        The tick is ignored on every other card (it is only shown on the Windows one)."""
        mode = mode or self.mode_var.get()
        return HARDENING_BASELINE if (mode == MODE_WINDOWS and self.hardening_var.get()) else HARDENING_NONE

    def _build_seed_panel(self, panel):
        """The "Hardening seed" card: what the second drive is, and which system it is for. No image file."""
        ttk.Label(
            panel, justify="left", wraplength=PANEL_WRAP,
            text=_("Makes a SECOND, small USB drive (not the installer) that carries settings for a hardened "
                   "Linux install or a hardened Windows 11. For Linux, write the installer to its own drive with "
                   "the Linux card, then plug both drives into the computer you install on. The files never "
                   "choose or erase a disk on that computer: you still pick the disk and create the account "
                   "yourself. No image file is needed; writing this drive ERASES it. The Windows scripts were "
                   "never run on a real Windows computer: try them on a test machine first.")
        ).pack(anchor="w", pady=(0, 6))
        self.seed_target_var = tk.StringVar(self, value=SEED_UBUNTU)  # the choice key (see SEED_CHOICES)
        self.seed_radios = {}
        ttk.Label(panel, text=_("Install target:")).pack(anchor="w")
        # Five radio buttons do not fit one row of a 780 px window (the texts are long, more so in Portuguese):
        # two rows, each one sized by its own radios (the three Linux targets, then the two Windows ones).
        grid = ttk.Frame(panel)
        grid.pack(fill="x", pady=(2, 0))
        rows = (ttk.Frame(grid), ttk.Frame(grid))
        for row in rows:
            row.pack(anchor="w", pady=(0, 2))
        for index, (choice, text) in enumerate(self.seed_target_texts()):
            radio = ttk.Radiobutton(rows[0 if index < 3 else 1], text=text, value=choice,
                                    variable=self.seed_target_var, command=self._on_seed_target_changed)
            radio.pack(side="left", padx=(0, 16))
            self.seed_radios[choice] = radio
        self.seed_radio_area = grid
        self.seed_note = ttk.Label(panel, justify="left", wraplength=PANEL_WRAP, foreground="#8e8e93")
        self.seed_note.pack(anchor="w", pady=(6, 0))
        self._on_seed_target_changed()

    @staticmethod
    def _seed_experimental_note():
        """The warning of the Windows "during setup" choice: the first lines of the engine's own description of
        the answer file (translated line by line), and always the word EXPERIMENTAL."""
        raw = describe_windows_seed_during_setup()  # noqa: F821  (written by the WIN-XML part of the feature)
        lines = raw.splitlines() if isinstance(raw, str) else [str(line) for line in raw]
        stripped = [line.strip() for line in lines if line.strip()]
        text = " ".join([_(text) for text in stripped[:3]])  # the engine owns these lines and their PT_BR entries
        if "experimental" not in text.lower():
            text = _("EXPERIMENTAL, never tested on real Windows.") + " " + text
        return text

    def seed_target_note(self, choice):
        """A short note about how the chosen system finds the seed drive (or, for Windows, how it is used)."""
        if choice == SEED_CHOICE_WINDOWS_SETUP:
            return App._seed_experimental_note()
        return {
            SEED_UBUNTU: _("Ubuntu's installer looks for settings on a drive labelled CIDATA. It still asks for "
                           "the disk and your account."),
            SEED_FEDORA: _("The installer looks for a kickstart file on a drive labelled OEMDRV. It still asks for "
                           "the disk and your account."),
            SEED_DEBIAN: _("Debian does not look for the drive by itself: the README on it explains the boot "
                           "parameter, and the script to run after the install is on it too."),
            SEED_WINDOWS: _("Run harden.cmd as administrator on a Windows 11 that is already installed; "
                            "audit.cmd shows a report first, undo.cmd goes back."),
        }.get(choice, "")

    def _on_seed_target_changed(self):
        self.seed_note.config(text=self.seed_target_note(self.seed_target_var.get()))
        self.after_idle(self._fit_window)  # the notes differ in length

    def _apply_card_layout(self, key):
        """What changes with the card besides its panel: the seed card needs no image, so the file row, the
        chosen-file card and the SHA-256 link are taken off the page and the heading and the Create button say
        what is being made."""
        seed = CARD_MODE[key] == MODE_SEED
        if seed != self._image_block_hidden:
            self._image_block_hidden = seed
            for widget in (self.image_row, self.iso_card, self.sha_toggle, self.iso_check_frame):
                widget.pack_forget()
            if not seed:  # back in their places, in order (each one anchored to the one above)
                self.image_row.pack(fill="x", pady=(10, 0), after=self._panel_holder)
                self.iso_card.pack(fill="x", pady=(6, 4), after=self.image_row)
                if self.iso_card.has_file:
                    self.sha_toggle.pack(anchor="w", pady=(0, 6), after=self.iso_card)
                    if self.sha_toggle.is_open:
                        self.iso_check_frame.pack(fill="x", pady=(0, 6), after=self.sha_toggle)
        heading = self.step_headings[2]
        heading.title = _("Auto-install files") if seed else _("Image")
        heading.label.config(text=heading.title)
        self.create_btn.config(text=_("Create Seed Drive") if seed else _("Create Bootable USB Drive"))
    # ===== end hardening: GUI =====

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
        self.image_row = row  # taken off the page on the Hardening seed card (see _apply_card_layout)
        self._image_block_hidden = False
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
        self._apply_card_layout(key)
        self.on_mode_change()
        self.after_idle(self._fit_window)  # the panels differ in height

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

    def _image_matches_choice(self, mode, image=None):
        """Stop (or ask) when the selected file is clearly not what the chosen card writes.

        A Linux image under "Windows 11" would otherwise be discovered only after the drive
        was erased ("could not find install.wim"); a non-ChromeOS file under "Google Chrome"
        is refused outright. `image` is the path captured when Create was clicked (default: the current one).
        """
        if mode == MODE_SEED:  # the seed drive carries no image: there is nothing to compare
            return True
        if image is None:
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
        if self.card_var.get() == CARD_SEED:
            # The Hardening seed card needs no image and the user chose it on purpose, so a finished download
            # does not pull them to another card: the image is only remembered for when they choose one.
            self.log(_("Image remembered: {name}. The Hardening seed card does not use it; choose the matching "
                       "card to write it.").format(name=os.path.basename(path)))
            self._reset_iso_sha()
            self.after_idle(self._fit_window)
            return
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
        self.hardening_check.config(state=busy if creating else "normal")  # the choices are read when Create is clicked
        for radio in self.seed_radios.values():
            radio.config(state=busy if creating else "normal")
        self.install_deps_btn.config(state=busy if (creating or self._installing) else "normal")
        self.update_create_button_state()  # Create also waits for a running download or extraction

    def update_create_button_state(self):
        disk = self.selected_disk()
        has_image = bool(self.iso_path.get()) or self.mode_var.get() == MODE_SEED  # the seed card needs no image
        # The tools the chosen mode needs: without them the drive would be erased and the copy would then fail.
        missing = [] if self._creating else get_missing_dependencies(self.mode_var.get())
        downloading = self._download_running or self._flex_busy  # the image (and the card) may still change
        ok = (has_image and disk is not None and not missing and not self._creating and not self._installing
              and not self._closing and not downloading)
        self.create_btn.config(state="normal" if ok else "disabled")
        if self._creating:
            hint = ""
        elif downloading:
            hint = _("Wait for the download to finish or cancel it first.")
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
        # Everything the write depends on is read ONCE, here, before any dialog opens: the confirmation, the
        # password prompt and the worker all use these values, so what is confirmed is what is written even if
        # something else (a finishing download) changes the window's image or card meanwhile.
        disk = self.selected_disk()
        if not disk:
            return
        mode = self.mode_var.get()
        iso = self.iso_path.get()
        seed = mode == MODE_SEED
        choice = self.seed_target_var.get() if seed else None
        target, during_setup = SEED_CHOICES.get(choice, (None, False))  # both read ONCE, like the rest
        hardening = self.hardening_selected(mode)
        if self._download_running or self._flex_busy:  # the button is disabled in this case; this covers a stale one
            messagebox.showerror(_("Download in progress"), _("Wait for the download to finish or cancel it first."))
            return
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
        if seed and target not in SEED_TARGETS:  # the radio buttons only give valid values; never trust the variable
            messagebox.showerror(_("Hardening seed"), _("Choose which system the seed drive is for. "
                                                        "Nothing was changed."))
            return
        if seed:  # a drive known to be too small is refused now, before the confirmation, not after it
            try:
                check_seed_target_size(disk_size)
            except ValueError as e:
                messagebox.showerror(_("Drive too small"), str(e))
                return
        if not seed and not self._image_matches_choice(mode, iso):
            return
        if seed and during_setup:
            what = _("the hardening seed files (experimental: includes an answer file for Windows Setup)")
        elif seed:
            what = _("the hardening seed files")
        elif hardening != HARDENING_NONE:
            what = _("Windows 11 and add the hardening files")
        else:
            what = _image_label(mode, _("the selected Linux image"))
        if mode in RAW_MODES:
            try:
                image_size = os.path.getsize(iso)
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
        dev = disk["id"]
        expected_size = disk_size

        def worker():
            try:
                def progress(done, total, text):
                    self._post(self._on_create_progress, done, total, text)

                if seed:  # the same flow as every other write; only the engine call differs (no image)
                    ejected = build_seed_usb(target, dev, self.log_threadsafe, self.priv,
                                             expected_size=expected_size, progress=progress,
                                             cancel_event=self.create_cancel_event, during_setup=during_setup)
                else:
                    extra = {"hardening": hardening} if hardening != HARDENING_NONE else {}
                    ejected = build_usb(iso, dev, self.log_threadsafe, self.priv,
                                        expected_size=expected_size, mode=mode, progress=progress,
                                        cancel_event=self.create_cancel_event, **extra)
                self._post(self._finish_create_progress, True)
                self._post(self._show_create_success, ejected, mode, hardening, target, during_setup)
            except OperationCanceled as e:
                # Not an error: the user asked for it. Say clearly what state the drive is in.
                log_text, title, body = self._canceled_texts(getattr(e, "drive_touched", True),
                                                             getattr(e, "written", False), seed)
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
    def _canceled_texts(drive_touched, written=False, seed=False):
        """(log line, dialog title, dialog text) after a cancel. The engine says whether it had already
        started to change the drive (when it did not, the drive must not be called unusable) and
        whether the whole image had been written (canceled during the final check)."""
        if drive_touched and written and seed:
            return (_("Canceled during verification. The seed files were written but NOT verified; do not rely "
                      "on this drive."),
                    _("Canceled"),
                    _("The operation was canceled during verification.\n\nThe seed files were written to the "
                      "drive but NOT verified, so do not rely on it. Create it again to verify it."))
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

    def _show_create_success(self, ejected, mode=None, hardening=HARDENING_NONE, target=None, during_setup=False):
        """The write was verified: the inline panel replaces the old "Done" dialog. Without the eject the
        panel is amber and says the drive must be ejected by hand before it is unplugged. `mode` and `hardening`
        say what was written (the seed drive and the Windows hardening files have their own wording)."""
        if self._closing:
            return
        if mode == MODE_SEED and target == SEED_WINDOWS:  # hardening2: its own title and wording
            title, note = self._windows_seed_success_texts(ejected, during_setup)
            self.show_success(title, note, verified_and_ejected=bool(ejected))
            return
        if mode == MODE_SEED:
            note = (_("The seed files were checked on the drive and it was ejected — you can unplug it now. "
                      "Plug it in next to the installer USB drive before you start the installation.") if ejected else
                    _("The seed files were checked on the drive, but it could not be ejected automatically. "
                      "Eject it from the file manager before unplugging, then plug it in next to the installer "
                      "USB drive before you start the installation."))
            self.show_success(_("Seed drive created and verified"), note, verified_and_ejected=bool(ejected))
            return
        note = (_("It was verified against the ISO and ejected — you can unplug it now.") if ejected else
                _("It was verified against the ISO, but could not be ejected automatically. "
                  "Eject it from the file manager before unplugging."))
        if hardening != HARDENING_NONE:
            note += " " + _("The hardening files were written to the drive and checked byte for byte. After "
                            "Windows setup finishes, their log will be at {log}."
                            ).format(log=WINDOWS_HARDENING_LOG_SHOWN)
        self.show_success(_("Bootable USB drive created successfully!"), note, verified_and_ejected=bool(ejected))

    @staticmethod
    def _windows_seed_success_texts(ejected, during_setup):
        """(title, text) of the success panel for the Windows seed drive, per choice (hardening2)."""
        note = (_("The files were checked on the drive and it was ejected — you can unplug it now.") if ejected else
                _("The files were checked on the drive, but it could not be ejected automatically. Eject it from "
                  "the file manager before unplugging."))
        if during_setup:
            return (_("Windows 11 setup drive (experimental) created and verified"),
                    note + " " + _("EXPERIMENTAL: plug it in next to the Windows installer USB drive BEFORE Windows "
                                   "Setup starts; Setup then reads the answer file (autounattend.xml) on it. An "
                                   "invalid answer file can stop an installation, and the scripts were never run "
                                   "on real Windows: try it on a test machine first. harden.cmd, audit.cmd and "
                                   "undo.cmd are on the drive as well."))
        return (_("Windows 11 hardening drive created and verified"),
                note + " " + _("On a Windows 11 that is already installed, open this drive and run audit.cmd "
                               "(shows a report, changes nothing), harden.cmd (as administrator) or undo.cmd (goes "
                               "back). The scripts were never run on real Windows: try them on a test machine first."))

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


def _is_hardening_conflict(exc):
    """True for the engine's refusal when the ISO already holds one of the hardening files (nothing was touched)."""
    return isinstance(exc, ValueError) and "already contain" in str(exc).lower()


def _disk_summary(disk):
    info = {k: v for k, v in disk.items() if v is None or isinstance(v, (str, int, float, bool))}
    info["size_human"] = human_size(disk.get("size") or 0)
    return info


def _write_steps(mode, disk_id, eject, hardening_files=None):
    steps = [f"Re-check that /dev/{disk_id} is still the listed USB drive"]
    if mode in RAW_MODES:
        steps += [f"Unmount /dev/{disk_id} and write the image to it byte for byte",
                  "Read the drive back and compare it with the image"]
    else:
        steps += [f"Erase /dev/{disk_id} and format it as GPT + FAT32 ('{VOL_NAME}')",
                  "Copy the ISO contents (install.wim is split when it exceeds 4 GB)",
                  "Verify the copied files against the ISO"]
        if hardening_files:
            steps.insert(-1, "Add the Hardened (recommended settings) files: " + ", ".join(hardening_files))
    steps.append("Eject the drive" if eject else "Leave the drive connected (--no-eject)")
    return steps


def _print_plan(plan, to_stdout):
    disk = plan["disk"]
    emit = _out if to_stdout else _err
    emit("Plan")
    emit(f"  Disk : /dev/{disk['id']}  {disk.get('size_human', '')}  {disk.get('label', '')}".rstrip())
    if disk.get("model"):
        emit(f"  Model: {disk['model']}")
    if plan["mode"] == MODE_SEED:
        emit(f"  Seed : {plan['target']} (volume label {plan['volume_label']})"
             + (" - during Windows setup, EXPERIMENTAL" if plan.get("during_setup") else ""))
        emit(f"  Files: {', '.join(plan['files'])}")
    else:
        emit(f"  ISO  : {plan['iso']} ({human_size(plan['iso_size'])})")
    emit(f"  Mode : {plan['mode']}")
    if plan.get("hardening_files"):
        emit(f"  Extra: Hardened (recommended settings): {', '.join(plan['hardening_files'])}")
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
    if getattr(args, "hardened", False) and args.mode not in (MODE_AUTO, MODE_WINDOWS):
        raise CliError(HARDENED_WINDOWS_ONLY, EXIT_USAGE)
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
    hardening_files = []
    if getattr(args, "hardened", False):
        if mode != MODE_WINDOWS:  # --mode auto resolved to a Linux or ChromeOS image
            raise CliError(HARDENED_WINDOWS_ONLY, EXIT_USAGE)
        hardening_files = _hardening_file_names(MODE_WINDOWS)
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
            "steps": _write_steps(mode, disk_id, eject, hardening_files), "eject": eject,
            "dry_run": bool(args.dry_run),
            "hardening": HARDENING_BASELINE if hardening_files else HARDENING_NONE,
            "hardening_files": hardening_files}


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


def _call_engine(plan, log, priv, progress, cancel):
    """Run the destructive engine call for `plan` (an image write, or the hardening seed drive)."""
    if plan["mode"] == MODE_SEED:
        return build_seed_usb(plan["target"], plan["disk"]["id"], log, priv,
                              expected_size=plan["disk"].get("size"), progress=progress,
                              cancel_event=cancel, eject=plan["eject"], profile=HARDENING_BASELINE,
                              during_setup=bool(plan.get("during_setup")))
    extra = {"hardening": plan["hardening"]} if plan.get("hardening", HARDENING_NONE) != HARDENING_NONE else {}
    return build_usb(plan["iso"], plan["disk"]["id"], log, priv,
                     expected_size=plan["disk"].get("size"), mode=plan["mode"],
                     progress=progress, eject=plan["eject"], cancel_event=cancel, **extra)


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
    audit(f"CLI write requested: /dev/{plan['disk']['id']} mode={plan['mode']}"
          + (f" target={plan['target']}" if plan["mode"] == MODE_SEED else "")
          + (" during_setup=True" if plan.get("during_setup") else "")
          + (f" hardening={plan['hardening']}" if plan.get("hardening", HARDENING_NONE) != HARDENING_NONE else ""))
    ejected, failure = None, None
    try:
        if needs_priv:
            priv.authenticate()
        # Bind the safety re-check (right before erasing) to exactly the drive that was planned.
        pin_target_identity(plan["disk"]["id"], plan.get("identity"))
        ejected = _call_engine(plan, log, priv, progress, cancel)
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
        if _is_hardening_conflict(failure):  # refused before the drive was touched: a usage problem, not a failure
            return EXIT_USAGE
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


# ===== hardening: cli =====
HARDENED_WINDOWS_ONLY = ("--hardened is only available for Windows images (--mode windows). For Linux use "
                         f"'{CLI_PROG} harden-seed' with a separate USB drive.")
# ===== hardening2: cli =====
# `harden-files --target windows` is the set that goes on the SAME USB as Windows (unchanged); the Windows
# SEED drive (a second small USB) has its own name here, because SEED_WINDOWS is also "windows".
HARDEN_FILES_WINDOWS_SEED = "windows-seed"
HARDEN_FILES_TARGETS = ("windows", HARDEN_FILES_WINDOWS_SEED,
                        *(t for t in SEED_TARGETS if t != SEED_WINDOWS))
DURING_SETUP_ONLY_WINDOWS = ("--during-setup only works with the Windows seed drive "
                             "(harden-seed --target windows, or harden-files --target windows-seed).")
DURING_SETUP_EXPERIMENTAL = ("EXPERIMENTAL: the answer file (autounattend.xml) makes Windows Setup run the "
                             "hardening script. It was never tested on a real installation; an invalid answer "
                             "file can stop Windows Setup. The default (run harden.cmd after install) is safer.")
# ===== end hardening2: cli =====


def _hardening_files(kind, during_setup=False):
    """(volume label or None, validated {relative_path: bytes}) for 'windows', 'windows-seed' or a seed target.

    The shared validator that build_usb()/build_seed_usb() apply is used here too, so a plan or a
    folder never holds files the engine would refuse. A refusal becomes a CliError.
    `during_setup` only matters for the Windows seed drive ('windows-seed'). Note that 'windows' here is always
    the same-USB set; for `harden-seed --target windows` pass 'windows-seed' (see _seed_files_kind).
    """
    try:
        if kind == "windows":
            label, files = None, hardening_files_windows(HARDENING_BASELINE)
        elif kind == HARDEN_FILES_WINDOWS_SEED:
            label, files = hardening_files_seed(SEED_WINDOWS, HARDENING_BASELINE, during_setup=bool(during_setup))
        else:
            label, files = hardening_files_seed(kind, HARDENING_BASELINE)
        return label, validate_seed_files(files)
    except ValueError as e:
        raise CliError(f"The hardening files are not valid: {e}") from None


def _seed_files_kind(target):
    """The _hardening_files() kind of a `harden-seed` target (its 'windows' is the seed drive, not the same-USB set)."""
    return HARDEN_FILES_WINDOWS_SEED if target == SEED_WINDOWS else target


def _hardening_file_names(kind):
    """The names (never the contents) of the hardening files for 'windows' or a seed target, sorted."""
    return sorted(_hardening_files(kind)[1])


def _prepare_seed(args):
    """Validate everything for `harden-seed` and build the plan. Raises CliError; touches nothing."""
    during_setup = bool(getattr(args, "during_setup", False))
    if during_setup and args.target != SEED_WINDOWS:
        raise CliError(DURING_SETUP_ONLY_WINDOWS, EXIT_USAGE)
    try:
        disk_id = validate_device_name(normalize_typed_identifier(args.disk))
    except ValueError as e:
        raise CliError(str(e)) from None
    disks = _list_disks()
    disk = next((d for d in disks if d.get("id") == disk_id), None)
    if disk is None:
        raise CliError(f"/dev/{disk_id} is not an eligible USB drive. "
                       f"Run '{CLI_PROG} list' to see the drives that can be written.")
    try:  # a drive known to be too small is refused first: before the plan, the dry run and any confirmation
        check_seed_target_size(disk.get("size"))
    except ValueError as e:
        raise CliError(str(e), EXIT_USAGE) from None
    label, files = _hardening_files(_seed_files_kind(args.target), during_setup)
    names = sorted(files)
    missing = get_missing_dependencies(MODE_SEED)
    if missing:
        raise CliError("Missing required tools: " + ", ".join(missing) + ". " + missing_dependencies_hint(missing))
    eject = not args.no_eject
    steps = [f"Re-check that /dev/{disk_id} is still the listed USB drive",
             f"Erase /dev/{disk_id} and format it as GPT + FAT32 ('{label}')",
             f"Copy {len(names)} seed files: " + ", ".join(names),
             "Read the drive back and compare every file byte for byte"]
    if during_setup:
        steps.append(DURING_SETUP_EXPERIMENTAL)
    steps.append("Eject the drive" if eject else "Leave the drive connected (--no-eject)")
    # The identity (serial, WWN, ...) is kept for the safety re-check, like in _prepare_write().
    return {"iso": None, "iso_size": 0, "mode": MODE_SEED, "target": args.target, "volume_label": label,
            "files": names, "disk": _disk_summary(disk), "identity": tuple(disk.get("identity") or ()),
            "during_setup": during_setup, "steps": steps, "eject": eject, "dry_run": bool(args.dry_run),
            "hardening": HARDENING_BASELINE, "hardening_files": []}


def cmd_harden_seed(args):
    """Erase a small separate USB drive and write the hardening seed files on it (never an OS image)."""
    result = {"ok": False, "mode": MODE_SEED, "target": args.target,
              "during_setup": bool(getattr(args, "during_setup", False)), "disk": None, "verified": False,
              "ejected": False, "error": None, "exit_code": EXIT_ERROR}
    try:
        plan = _prepare_seed(args)
        result.update(disk=plan["disk"]["id"], volume_label=plan["volume_label"], files=plan["files"])
        if args.dry_run:
            if args.json:
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


def _fill_staging_folder(stage, files):
    """Write `files` into the private staging folder `stage`.

    Nothing the user can see is touched here, so a failure leaves nothing behind (the caller removes
    the staging folder). Folders end up 0700 and files 0600 (private, like every file this program creates), whatever the umask.
    """
    os.chmod(stage, 0o700)
    for rel, data in files.items():
        parts = rel.split("/")
        target = os.path.normpath(os.path.join(stage, *parts))
        # validate_seed_files() already refused these; this is the second lock on the same door.
        if ".." in parts or "" in parts or os.path.commonpath([stage, target]) != stage or target == stage:
            raise ValueError(f"Refusing a path outside the folder: {rel}")
        folder = os.path.dirname(target)
        if folder != stage and not os.path.isdir(folder):
            os.makedirs(folder, mode=0o700)
            part = folder
            while part != stage:  # makedirs applies the umask to every level it creates
                os.chmod(part, 0o700)
                part = os.path.dirname(part)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), PRIVATE_FILE_MODE)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.chmod(target, PRIVATE_FILE_MODE)


def _install_staged(stage, out, out_existed):
    """Move the staged entries to `out` (a new name, or an existing empty folder). Undone on failure."""
    if not out_existed:
        os.rename(stage, out)  # one atomic step: the folder appears complete or not at all
        return
    moved = []
    try:
        for name in sorted(os.listdir(stage)):
            dest = os.path.join(out, name)
            if os.path.lexists(dest):  # the folder was empty a moment ago: never overwrite what appeared
                raise FileExistsError(f"{dest} appeared while the files were being written")
            os.rename(os.path.join(stage, name), dest)
            moved.append(dest)
        os.rmdir(stage)
    except BaseException:
        for dest in moved:
            if os.path.isdir(dest) and not os.path.islink(dest):
                shutil.rmtree(dest, ignore_errors=True)
            else:
                _silent_remove(dest)
        raise


def cmd_harden_files(args):
    """Write the hardening files for one target into a new or empty folder. No drive, no privileges."""
    target = args.target
    during_setup = bool(getattr(args, "during_setup", False))
    if during_setup and target != HARDEN_FILES_WINDOWS_SEED:
        raise CliError("--during-setup only works with --target windows-seed.", EXIT_USAGE)
    out = os.path.abspath(os.path.expanduser(args.out))
    if os.path.islink(out):
        raise CliError(f"{out} is a symbolic link. Pass a real folder that is new or empty.")
    out_existed = os.path.lexists(out)
    if out_existed:
        if not os.path.isdir(out):
            raise CliError(f"Not a folder: {out}")
        if os.listdir(out):
            raise CliError(f"The folder is not empty: {out}. Pass a new folder or an empty one; "
                           "nothing was written.")
    parent = os.path.dirname(out)
    if not os.path.isdir(parent):
        raise CliError(f"The parent folder does not exist: {parent}")
    label, files = _hardening_files(target, during_setup)
    stage = None
    try:
        # Staging beside the destination keeps the final move on one filesystem (an atomic rename).
        stage = tempfile.mkdtemp(prefix=".epma-harden-", dir=parent)
        _fill_staging_folder(stage, files)
        _install_staged(stage, out, out_existed)
    except (OSError, ValueError) as e:
        raise CliError(f"Could not write the hardening files to {out}: "
                       f"{getattr(e, 'strerror', None) or e}. Nothing was left behind.") from None
    finally:
        if stage is not None and os.path.lexists(stage):
            shutil.rmtree(stage, ignore_errors=True)
    names = sorted(files)
    if args.json:
        _out(json.dumps({"target": target, "during_setup": during_setup, "out": out, "volume_label": label,
                         "files": [{"path": n, "bytes": len(files[n])} for n in names]}, indent=2))
    else:
        for name in names:
            _out(name)
    _err(f"Wrote {len(names)} files to {out}. They are plain text: read them before using them. "
         "No drive was touched.")
    if during_setup:
        _err(DURING_SETUP_EXPERIMENTAL)
    return EXIT_OK
# ===== end hardening: cli =====


COMMANDS = {"list": cmd_list, "detect": cmd_detect, "sha256": cmd_sha256, "write": cmd_write,
            "fetch-chromeos": cmd_fetch_chromeos, "harden-seed": cmd_harden_seed,
            "harden-files": cmd_harden_files}


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
            "The written drive is always read back and compared with its source (the ISO, or the seed files).")


def _add_write_flags(p):
    """The confirmation, dry-run, eject, output and verbosity flags every drive-writing command shares."""
    p.add_argument("--yes", action="store_true",
                   help="do not ask for confirmation (required when not in an interactive terminal)")
    p.add_argument("--dry-run", action="store_true", help="print the plan and exit without touching anything")
    p.add_argument("--no-eject", action="store_true", help="leave the drive connected when done")
    p.add_argument("--json", action="store_true", help="machine-readable result on stdout")
    p.add_argument("-v", "--verbose", action="store_true", help="show every engine log line")


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
    p.add_argument("--hardened", action="store_true",
                   help="also add the optional Hardened (recommended settings) files to the Windows drive "
                        "(Windows mode only; --dry-run lists them)")
    _add_write_flags(p)
    p = add("harden-seed", "erase a small separate USB drive and write the hardening seed files on it "
                           "(no operating system image)",
            epilog="The drive is ERASED. Use --dry-run first to see the plan without changing anything. "
                   "The seed files never choose a disk or create accounts.")
    p.add_argument("--target", required=True, choices=SEED_TARGETS,
                   help="ubuntu (autoinstall), fedora (kickstart), debian (script + preseed) or "
                        "windows (Windows 11: harden.cmd to run after install)")
    p.add_argument("--disk", required=True, metavar="DISKID",
                   help="drive id as shown by 'list' (disk4 on macOS, sdb on Linux)")
    p.add_argument("--during-setup", action="store_true",
                   help="EXPERIMENTAL, --target windows only: also add an answer file (autounattend.xml) so "
                        "that Windows Setup runs the hardening script during installation")
    _add_write_flags(p)
    p = add("harden-files", "write the hardening files into a new or empty folder (no drive is touched)",
            epilog="Nothing is overwritten: a folder that is not empty is refused.")
    p.add_argument("--target", required=True, choices=HARDEN_FILES_TARGETS,
                   help="windows (files for the same USB as Windows), windows-seed (files for the Windows seed "
                        "drive), ubuntu, fedora or debian")
    p.add_argument("--during-setup", action="store_true",
                   help="EXPERIMENTAL, --target windows-seed only: include the answer file (autounattend.xml)")
    p.add_argument("--out", required=True, metavar="DIR", help="a new folder, or an empty one")
    p.add_argument("--json", action="store_true", help="machine-readable output")
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
    if command in ("gui", "list", "write", "harden-seed") and not (IS_MAC or IS_LINUX):
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
