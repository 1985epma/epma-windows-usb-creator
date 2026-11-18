#!/bin/sh
R="$EPMA_HARDEN_TEST_ROOT"
n="$(basename "$0")"
echo "$n $*" >> "$R/calls.log"
S="$R/state"
mkdir -p "$S"
last=""
for a in "$@"; do last="$a"; done
case "$n" in
sshd)
  case "$1" in
    -t) if [ -e "$S/sshd_t_fail" ]; then echo "Bad configuration option: Nonsense" >&2; exit 1; fi; exit 0 ;;
    -T) if [ -e "$S/sshd_T" ]; then cat "$S/sshd_T"; else
          # like sshd: for every keyword the FIRST value read wins (drop-ins in name order, then the main file)
          first() { cat "$R"/etc/ssh/sshd_config.d/*.conf "$R/etc/ssh/sshd_config" 2>/dev/null \
                    | awk -v k="$1" 'tolower($1) == k { print tolower($2); exit }'; }
          pw="$(first passwordauthentication)"; rl="$(first permitrootlogin)"
          printf 'port 22\npermitrootlogin %s\npasswordauthentication %s\nx11forwarding no\nlogingracetime 30\npermitemptypasswords no\n' \
            "${rl:-prohibit-password}" "${pw:-yes}"
        fi; exit 0 ;;
  esac ;;
dpkg) if [ -e "$S/pkg_$2" ]; then echo "Package: $2"; echo "Status: install ok installed"; exit 0; fi; exit 1 ;;
rpm) if [ -e "$S/pkg_$2" ]; then exit 0; fi; exit 1 ;;
apt-get)
  if [ "$1" = install ]; then
    touch "$S/pkg_$last"
    if [ "$last" = unattended-upgrades ] && [ ! -e "$R/etc/apt/apt.conf.d/50unattended-upgrades" ]; then
      mkdir -p "$R/etc/apt/apt.conf.d"
      printf '// stock\nUnattended-Upgrade::Allowed-Origins {\n        "${distro_id}:${distro_codename}";\n};\n' > "$R/etc/apt/apt.conf.d/50unattended-upgrades"
    fi
  fi; exit 0 ;;
dnf) if [ "$2" = install ]; then touch "$S/pkg_$last"; fi; exit 0 ;;
systemctl)
  case "$1" in
    is-active) if [ -e "$S/active_$last" ]; then exit 0; fi; exit 3 ;;
    is-enabled) if [ -e "$S/enabled_$last" ]; then exit 0; fi; exit 1 ;;
    enable) touch "$S/enabled_$last" "$S/active_$last"; exit 0 ;;
    disable) rm -f "$S/enabled_$last"; exit 0 ;;
    list-unit-files) printf 'dnf-automatic-install.timer disabled\n'; exit 0 ;;
  esac ;;
ufw)
  case "$1" in
    status) if [ -e "$S/ufw_active" ]; then printf 'Status: active\nDefault: deny (incoming), allow (outgoing)\n'; else echo "Status: inactive"; fi ;;
    --force) touch "$S/ufw_active" ;;
  esac ;;
firewall-cmd)
  case "$1" in --get-default-zone) echo public; exit 0 ;; esac
  for a in "$@"; do case "$a" in --query-*) exit 1 ;; esac; done ;;
getenforce) echo Enforcing ;;
ss) printf 'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n'
    if [ -e "$S/ss_out" ]; then cat "$S/ss_out"; fi ;;
esac
exit 0
