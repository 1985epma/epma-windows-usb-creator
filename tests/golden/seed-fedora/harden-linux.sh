#!/usr/bin/env bash
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
