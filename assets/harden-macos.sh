#!/bin/bash
# harden-macos.sh - recommended security settings for a Mac.
#
# Part of EPMA USB CREATOR ("Hardening seed", macOS). The settings are inspired by common macOS
# hardening baselines and kept conservative on purpose. It is a convenience script: it makes no
# claim to meet any standard. It works with the bash that ships with macOS (3.2).
#
# Usage:  sudo bash harden-macos.sh [--dry-run] [--yes] [--undo] [--help]
#         bash harden-macos.sh --dry-run          (a report only; needs no administrator rights)
#
# What it does NOT do: it never partitions, formats or erases anything, never creates users or
# passwords, never turns FileVault on (that needs a recovery key and your decision), never touches
# System Integrity Protection, never changes the Sharing settings and never makes a network request.
#
# Before it changes a value it remembers the original once (in /var/db/epma-hardening), so --undo
# puts back what was there. Running it twice changes nothing the second time.
#
# Layout note: everything below is a function and the very last line calls main. That keeps the
# script safe to run through "bash -s" (no command can swallow the rest of the script from stdin).

usage() {
  cat <<'EOF'
harden-macos.sh - recommended security settings for a Mac

Usage: sudo bash harden-macos.sh [options]

Options:
  --dry-run   show what would be done; change NOTHING (no setting, no state file, no log entry).
              Needs no administrator rights.
  --yes       do not ask for confirmation (needed when there is no terminal)
  --undo      put back the values this script remembered before it changed them
  --help      show this text

Exit status: 0 done, 1 some step failed (see the [WARN] lines), 2 cannot run (not root,
not a Mac, bad option).
Log file: /var/log/epma-hardening.log
EOF
}

die() {
  local code="$1"
  shift
  printf 'harden-macos.sh: %s\n' "$*" >&2
  exit "$code"
}

init_globals() {
  DRY=0
  YES=0
  UNDO=0
  HELP=0
  N_OK=0
  N_SKIP=0
  N_WARN=0
  N_CHANGE=0
  N_ERR=0
  R=""
  TESTMODE=0
  IS_ROOT=0
  STATE_DIR=""
  STATE_FILE=""
  LOG_FILE=""
  LOG_ENABLED=0
  FW_CMD=/usr/libexec/ApplicationFirewall/socketfilterfw
  LOGINWINDOW=/Library/Preferences/com.apple.loginwindow
  SOFTWAREUPDATE=/Library/Preferences/com.apple.SoftwareUpdate
  TAB="$(printf '\t')"
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

info() {
  say "[INFO]   $*"
}

change() {
  N_CHANGE=$((N_CHANGE + 1))
  if [ "$DRY" = 1 ]; then
    say "[CHANGE] (dry-run) $*"
  else
    say "[CHANGE] $*"
  fi
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
    FW_CMD=socketfilterfw
  else
    # The tools used below all live here; a search path someone else prepared is not trusted.
    PATH=/usr/bin:/bin:/usr/sbin:/sbin
    export PATH
  fi
  umask 022
  uid="$(id -u)"
  if [ "$TESTMODE" = 1 ] && [ -n "${EPMA_HARDEN_TEST_UID:-}" ]; then
    uid="$EPMA_HARDEN_TEST_UID"
  fi
  if [ "$uid" = 0 ]; then
    IS_ROOT=1
  elif [ "$DRY" != 1 ]; then
    die 2 "this script must run as root (try: sudo bash harden-macos.sh ...), or use --dry-run for a report"
  fi
}

init_paths() {
  STATE_DIR="$R/var/db/epma-hardening"
  STATE_FILE="$STATE_DIR/previous.list"
  LOG_FILE="$R/var/log/epma-hardening.log"
}

# Run a command that acts on, or asks questions of, the live system. In test mode only the stubs
# in <root>/stubs are ever run, so a test can never reach the real defaults, spctl and so on.
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

shown() {
  local p="$1"
  printf '%s' "${p#"$R"}"
}

check_platform() {
  local os
  os="$(sysrun uname -s 2>/dev/null)" || os=""
  if [ "$os" != Darwin ]; then
    die 2 "this script is for macOS (Darwin); this system reports '${os:-unknown}'"
  fi
}

# ---------------------------------------------------------------------------------------------
# What was there before (so --undo can put it back)
# ---------------------------------------------------------------------------------------------
# previous.list holds one line per remembered value, five tab separated fields, none empty:
#   KIND  A  B  TYPE  VALUE
#   defaults  DOMAIN  KEY  bool|string|int|absent  VALUE      (a preference value)
#   fw        globalstate|stealth  -  state  0|1              (Application Firewall)
#   gk        assessments  -  state  0|1                      (Gatekeeper)

# state_has KIND A B: is that value already remembered?
state_has() {
  [ -f "$STATE_FILE" ] || return 1
  awk -F '\t' -v k="$1" -v a="$2" -v b="$3" '$1 == k && $2 == a && $3 == b { found = 1 } END { exit found ? 0 : 1 }' "$STATE_FILE"
}

# state_put KIND A B TYPE VALUE: remember it once. The FIRST value is the original, so a second run
# never replaces it with what the first run wrote. Returns 0 when a line was added, 1 when not.
state_put() {
  if state_has "$1" "$2" "$3"; then
    return 1
  fi
  mkdir -p "$STATE_DIR"
  chmod 700 "$STATE_DIR"
  printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" >>"$STATE_FILE"
  return 0
}

# state_drop KIND A B: forget a value (used when the change it belongs to did not happen).
state_drop() {
  [ -f "$STATE_FILE" ] || return 0
  awk -F '\t' -v k="$1" -v a="$2" -v b="$3" '!($1 == k && $2 == a && $3 == b)' "$STATE_FILE" >"$STATE_FILE.new"
  mv -f "$STATE_FILE.new" "$STATE_FILE"
}

# ---------------------------------------------------------------------------------------------
# Preferences (defaults)
# ---------------------------------------------------------------------------------------------

# defaults_type DOMAIN KEY: bool, string, int or other (the key must exist).
defaults_type() {
  local out
  out="$(sysrun defaults read-type "$1" "$2" 2>/dev/null)" || {
    printf 'other'
    return 0
  }
  case "$out" in
    *boolean*) printf 'bool' ;;
    *string*) printf 'string' ;;
    *integer*) printf 'int' ;;
    *) printf 'other' ;;
  esac
}

# defaults_write DOMAIN KEY TYPE VALUE: TYPE is bool, string or int; a bool value is 0/1 or true/false.
defaults_write() {
  local domain="$1" key="$2" type="$3" value="$4"
  case "$type" in
    bool)
      case "$value" in
        1 | true) value=true ;;
        *) value=false ;;
      esac
      sysrun defaults write "$domain" "$key" -bool "$value" 2>&1
      ;;
    int) sysrun defaults write "$domain" "$key" -int "$value" 2>&1 ;;
    *) sysrun defaults write "$domain" "$key" -string "$value" 2>&1 ;;
  esac
}

# do_bool DOMAIN KEY WANTED DESCRIPTION: make a boolean preference true or false.
do_bool() {
  local domain="$1" key="$2" wanted="$3" desc="$4" cur type want_read prev_type prev_value added=1 out now
  case "$wanted" in
    true) want_read=1 ;;
    *) want_read=0 ;;
  esac
  if cur="$(sysrun defaults read "$domain" "$key" 2>/dev/null)"; then
    type="$(defaults_type "$domain" "$key")"
    if [ "$type" != bool ]; then
      skip "$desc: $key in $(basename "$domain") is not a yes/no value here; left alone"
      return 0
    fi
    if [ "$cur" = "$want_read" ]; then
      ok "$desc (already as wanted)"
      return 0
    fi
    prev_type=bool
    prev_value="$cur"
  else
    prev_type=absent
    prev_value=-
  fi
  if [ "$DRY" = 1 ]; then
    change "would: $desc"
    return 0
  fi
  if state_put defaults "$domain" "$key" "$prev_type" "$prev_value"; then
    added=0
  fi
  if out="$(defaults_write "$domain" "$key" bool "$wanted")"; then
    now="$(sysrun defaults read "$domain" "$key" 2>/dev/null)" || now=""
    if [ "$now" = "$want_read" ]; then
      change "$desc"
      return 0
    fi
    out="the value read back is '${now:-nothing}'"
  fi
  if [ "$added" = 0 ]; then
    state_drop defaults "$domain" "$key"
  fi
  warn "FAILED: $desc"
  log_line "output: $out"
  N_ERR=$((N_ERR + 1))
  return 0
}

# ---------------------------------------------------------------------------------------------
# The settings
# ---------------------------------------------------------------------------------------------

# fw_value ARG: the Application Firewall answer for socketfilterfw ARG as 0 (off), 1 (on), 2 (block
# all incoming connections) or ? (could not tell).
fw_value() {
  local out
  out="$(sysrun "$FW_CMD" "$1" 2>&1)" || {
    printf '?'
    return 0
  }
  case "$out" in
    *"State = 2"*) printf '2' ;;
    *"State = 0"* | *disabled* | *"is off"*) printf '0' ;;
    *"State = 1"* | *enabled* | *"is on"*) printf '1' ;;
    *) printf '?' ;;
  esac
}

do_firewall() {
  local cur out added=1
  cur="$(fw_value --getglobalstate)"
  case "$cur" in
    1) ok "the Application Firewall is on" ;;
    2) ok "the Application Firewall blocks all incoming connections (stricter than wanted; left as it is)" ;;
    0)
      if [ "$DRY" = 1 ]; then
        change "would: turn the Application Firewall on"
        return 0
      fi
      if state_put fw globalstate - state 0; then
        added=0
      fi
      if out="$(sysrun "$FW_CMD" --setglobalstate on 2>&1)" && [ "$(fw_value --getglobalstate)" = 1 ]; then
        change "turned the Application Firewall on"
      else
        if [ "$added" = 0 ]; then
          state_drop fw globalstate -
        fi
        warn "FAILED: turn the Application Firewall on"
        log_line "output: $out"
        N_ERR=$((N_ERR + 1))
      fi
      ;;
    *) warn "could not read the Application Firewall state; left alone" ;;
  esac
}

do_stealth() {
  local cur out added=1
  cur="$(fw_value --getstealthmode)"
  case "$cur" in
    1 | 2) ok "stealth mode is on" ;;
    0)
      if [ "$DRY" = 1 ]; then
        change "would: turn stealth mode on"
        return 0
      fi
      if state_put fw stealth - state 0; then
        added=0
      fi
      if out="$(sysrun "$FW_CMD" --setstealthmode on 2>&1)" && [ "$(fw_value --getstealthmode)" = 1 ]; then
        change "turned stealth mode on"
      else
        if [ "$added" = 0 ]; then
          state_drop fw stealth -
        fi
        warn "FAILED: turn stealth mode on"
        log_line "output: $out"
        N_ERR=$((N_ERR + 1))
      fi
      ;;
    *) warn "could not read the stealth mode state; left alone" ;;
  esac
}

# gk_value: 1 when Gatekeeper assessments are enabled, 0 when disabled, ? when unknown.
gk_value() {
  local out
  out="$(sysrun spctl --status 2>&1)" || true
  case "$out" in
    *"assessments enabled"*) printf '1' ;;
    *"assessments disabled"*) printf '0' ;;
    *) printf '?' ;;
  esac
}

do_gatekeeper() {
  local cur out added=1
  cur="$(gk_value)"
  case "$cur" in
    1) ok "Gatekeeper is on" ;;
    0)
      if [ "$DRY" = 1 ]; then
        change "would: turn Gatekeeper on"
        return 0
      fi
      if state_put gk assessments - state 0; then
        added=0
      fi
      if out="$(sysrun spctl --master-enable 2>&1)" && [ "$(gk_value)" = 1 ]; then
        change "turned Gatekeeper on"
      else
        if [ "$added" = 0 ]; then
          state_drop gk assessments -
        fi
        warn "FAILED: turn Gatekeeper on"
        log_line "output: $out"
        N_ERR=$((N_ERR + 1))
      fi
      ;;
    *) warn "could not read the Gatekeeper state; left alone" ;;
  esac
}

do_updates() {
  do_bool "$SOFTWAREUPDATE" AutomaticCheckEnabled true "check for software updates automatically"
  do_bool "$SOFTWAREUPDATE" AutomaticDownload true "download updates in the background"
  do_bool "$SOFTWAREUPDATE" CriticalUpdateInstall true "install security responses and system files automatically"
  do_bool "$SOFTWAREUPDATE" ConfigDataInstall true "install system data files automatically"
}

do_guest() {
  do_bool "$LOGINWINDOW" GuestEnabled false "turn the guest account off"
}

do_autologin() {
  local cur type out added=1
  if cur="$(sysrun defaults read "$LOGINWINDOW" autoLoginUser 2>/dev/null)"; then
    type="$(defaults_type "$LOGINWINDOW" autoLoginUser)"
    if [ "$type" != string ]; then
      skip "automatic login: autoLoginUser is not a user name here; left alone"
      return 0
    fi
    if [ "$DRY" = 1 ]; then
      change "would: turn automatic login off (it is on for the user '$cur')"
      return 0
    fi
    if state_put defaults "$LOGINWINDOW" autoLoginUser string "$cur"; then
      added=0
    fi
    if out="$(sysrun defaults delete "$LOGINWINDOW" autoLoginUser 2>&1)" \
      && ! sysrun defaults read "$LOGINWINDOW" autoLoginUser >/dev/null 2>&1; then
      change "turned automatic login off (it was on for the user '$cur')"
    else
      if [ "$added" = 0 ]; then
        state_drop defaults "$LOGINWINDOW" autoLoginUser
      fi
      warn "FAILED: turn automatic login off"
      log_line "output: $out"
      N_ERR=$((N_ERR + 1))
    fi
  else
    ok "automatic login is off"
  fi
}

# What is only reported, never changed.
report_filevault() {
  local out
  if ! have_cmd fdesetup; then
    info "FileVault: fdesetup is not available here; not checked"
    return 0
  fi
  out="$(sysrun fdesetup status 2>&1)" || true
  case "$out" in
    *"FileVault is On"*) ok "FileVault (disk encryption) is on" ;;
    *"FileVault is Off"*)
      warn "FileVault (disk encryption) is OFF. Turn it on in System Settings > Privacy & Security > FileVault. This script never does it: it needs a recovery key."
      ;;
    *) info "FileVault: could not tell ('$out')" ;;
  esac
}

report_sip() {
  local out
  if ! have_cmd csrutil; then
    info "System Integrity Protection: csrutil is not available here; not checked"
    return 0
  fi
  out="$(sysrun csrutil status 2>&1)" || true
  case "$out" in
    *"status: enabled"*) ok "System Integrity Protection is on" ;;
    *"status: disabled"*) warn "System Integrity Protection is OFF. It can only be turned on again from macOS Recovery; this script never touches it." ;;
    *) info "System Integrity Protection: could not tell ('$out')" ;;
  esac
}

report_sharing() {
  if ! have_cmd launchctl; then
    info "Remote Login: launchctl is not available here; not checked"
    return 0
  fi
  if [ "$IS_ROOT" != 1 ]; then
    info "Remote Login (SSH): not checked without administrator rights"
    return 0
  fi
  if sysrun launchctl print system/com.openssh.sshd >/dev/null 2>&1; then
    warn "Remote Login (SSH) looks switched on. If you do not use it, turn it off in System Settings > General > Sharing. This script does not change it."
  else
    ok "Remote Login (SSH) does not look switched on"
  fi
}

# ---------------------------------------------------------------------------------------------
# Plan, confirmation, log
# ---------------------------------------------------------------------------------------------

print_plan() {
  local version=""
  version="$(sysrun sw_vers -productVersion 2>/dev/null)" || version=""
  say "EPMA hardening for macOS ${version:-(version unknown)}"
  if [ "$UNDO" = 1 ]; then
    say "This puts back the values remembered in $(shown "$STATE_FILE")."
  else
    say "This applies: Application Firewall and stealth mode, Gatekeeper, automatic update checks,"
    say "no guest account, no automatic login. It only reports: FileVault, System Integrity"
    say "Protection and Remote Login. Nothing is installed and nothing is downloaded."
  fi
  if [ "$DRY" = 1 ]; then
    say "Dry run: nothing is changed."
  fi
}

confirm_run() {
  local answer=""
  if [ "$DRY" = 1 ] || [ "$YES" = 1 ]; then
    return 0
  fi
  if [ "$TESTMODE" != 1 ] && [ ! -t 0 ]; then
    die 2 "there is no terminal to ask on: pass --yes to go ahead"
  fi
  printf 'Continue? [y/N] '
  read -r answer || answer=""
  case "$answer" in
    y | Y | yes | YES) return 0 ;;
  esac
  say "Cancelled. Nothing was changed."
  exit 1
}

init_log() {
  if [ "$IS_ROOT" = 1 ] && [ "$DRY" != 1 ]; then
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || return 0
    if : >>"$LOG_FILE" 2>/dev/null; then
      chmod 600 "$LOG_FILE" 2>/dev/null || true
      LOG_ENABLED=1
      log_line "---- harden-macos.sh started (dry=$DRY undo=$UNDO) ----"
    fi
  fi
}

# ---------------------------------------------------------------------------------------------
# Undo
# ---------------------------------------------------------------------------------------------

# undo_fw NAME VALUE: put the Application Firewall back to its earlier value.
undo_fw() {
  local name="$1" value="$2" flag out arg
  case "$value" in
    1) flag=on ;;
    *) flag=off ;;
  esac
  case "$name" in
    globalstate) arg=--setglobalstate ;;
    stealth) arg=--setstealthmode ;;
    *)
      warn "unknown firewall entry '$name' in the remembered values; left alone"
      return 1
      ;;
  esac
  if [ "$DRY" = 1 ]; then
    change "would: put the Application Firewall '$name' back to $flag"
    return 0
  fi
  if out="$(sysrun "$FW_CMD" "$arg" "$flag" 2>&1)"; then
    change "put the Application Firewall '$name' back to $flag"
    return 0
  fi
  warn "FAILED: put the Application Firewall '$name' back to $flag"
  log_line "output: $out"
  return 1
}

undo_gk() {
  local value="$1" out verb word
  case "$value" in
    1) verb=--master-enable word=on ;;
    *) verb=--master-disable word=off ;;
  esac
  if [ "$DRY" = 1 ]; then
    change "would: put Gatekeeper back to $word"
    return 0
  fi
  if out="$(sysrun spctl "$verb" 2>&1)"; then
    change "put Gatekeeper back to $word"
    return 0
  fi
  warn "FAILED: put Gatekeeper back to $word"
  log_line "output: $out"
  return 1
}

undo_defaults() {
  local domain="$1" key="$2" type="$3" value="$4" out
  if [ "$type" = absent ]; then
    if [ "$DRY" = 1 ]; then
      change "would: remove $key from $(basename "$domain") (it was not set before)"
      return 0
    fi
    if ! sysrun defaults read "$domain" "$key" >/dev/null 2>&1; then
      ok "$key in $(basename "$domain") is already absent"
      return 0
    fi
    if out="$(sysrun defaults delete "$domain" "$key" 2>&1)"; then
      change "removed $key from $(basename "$domain") (it was not set before)"
      return 0
    fi
  else
    if [ "$DRY" = 1 ]; then
      change "would: put $key in $(basename "$domain") back to $value"
      return 0
    fi
    if out="$(defaults_write "$domain" "$key" "$type" "$value")"; then
      change "put $key in $(basename "$domain") back to $value"
      return 0
    fi
  fi
  warn "FAILED: put $key in $(basename "$domain") back"
  log_line "output: $out"
  return 1
}

do_undo() {
  local kind a b type value failed=0
  if [ ! -f "$STATE_FILE" ]; then
    skip "nothing to undo: there is no record of earlier changes ($(shown "$STATE_FILE"))"
    return 0
  fi
  while IFS="$TAB" read -r kind a b type value; do
    [ -n "$kind" ] || continue
    case "$kind" in
      fw) undo_fw "$a" "$value" || failed=1 ;;
      gk) undo_gk "$value" || failed=1 ;;
      defaults) undo_defaults "$a" "$b" "$type" "$value" || failed=1 ;;
      *) warn "unknown entry '$kind' in the remembered values; left alone" ;;
    esac
  done <"$STATE_FILE"
  if [ "$failed" = 1 ]; then
    N_ERR=$((N_ERR + 1))
    warn "some values could not be put back; the record is kept so --undo can be run again"
  elif [ "$DRY" != 1 ]; then
    rm -f "$STATE_FILE"
    rmdir "$STATE_DIR" 2>/dev/null || true
  fi
}

# ---------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --dry-run) DRY=1 ;;
      --yes | -y) YES=1 ;;
      --undo) UNDO=1 ;;
      --help | -h) HELP=1 ;;
      *) die 2 "unknown option '$1' (try --help)" ;;
    esac
    shift
  done
}

summary() {
  say "Done: $N_CHANGE changed, $N_OK already as wanted, $N_WARN to look at, $N_SKIP skipped, $N_ERR failed."
  if [ "$DRY" = 1 ]; then
    say "This was a dry run: nothing was changed."
  elif [ "$UNDO" != 1 ] && [ "$N_CHANGE" -gt 0 ]; then
    say "Undo with: sudo bash harden-macos.sh --undo"
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
  check_platform
  print_plan
  confirm_run
  init_log
  if [ "$UNDO" = 1 ]; then
    do_undo
  else
    do_firewall
    do_stealth
    do_gatekeeper
    do_updates
    do_guest
    do_autologin
    report_filevault
    report_sip
    report_sharing
  fi
  summary
  if [ "$N_ERR" -gt 0 ]; then
    exit 1
  fi
  exit 0
}

main "$@"
