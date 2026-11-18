EPMA HARDENING SEED - Fedora / RHEL / Rocky / Alma (kickstart)
============================================================

WHAT THIS DRIVE IS
A small helper drive made by EPMA USB CREATOR. It holds settings files that
make a fresh Linux install start from safer settings (a firewall, audit
logging, automatic security updates and similar). It is not an installer and
it does not boot by itself.

USE IT AS A SECOND USB
Keep your normal installer USB (the one you wrote the Linux ISO to) and plug
this drive in next to it, before you start the installer.

WHAT IT DOES NOT DO
Nothing here selects a disk, partitions, formats or erases anything, and
nothing creates an account or sets a password or key. You still choose the
disk and create your own account in the installer. Check each screen before
you confirm it.

HOW TO USE IT
For Fedora, RHEL, Rocky Linux and AlmaLinux (Anaconda). The drive is named
OEMDRV, which Anaconda detects by itself and reads ks.cfg from.

1. Plug in both USB drives and start the computer from the installer USB.
2. Anaconda opens as usual. Choose the language, the install destination
   (disk), your root/user accounts and, if asked, the software selection.
3. Check the summary and start the installation yourself.

The kickstart adds the packages firewalld, audit and dnf-automatic and runs
the script inside the new system at the end. A log is kept in
/var/log/epma-hardening.log. If the script fails, the installation still
finishes.

WHAT THE SCRIPT CHANGES
harden-linux.sh is a plain text file on this drive: read it before you use it.
It prints every change it makes. Typical changes:
  - the firewalld firewall is switched on; its default zone is left exactly as
    Fedora/RHEL set it (the script does not make it stricter), and SSH is
    allowed in that zone when the SSH server is in use
  - audit logging of security-relevant events
  - automatic security updates
  - safer kernel and network settings (a setting that is already stricter is
    not lowered)
  - conservative SSH server settings. The script tries not to lock you out,
    but it cannot promise your login keeps working: it refuses root logins
    over SSH only when a normal user in the sudo (Debian/Ubuntu) or wheel
    (Fedora/RHEL) group exists, and refuses password logins only when such a
    user has a key in authorized_keys. Otherwise it leaves those logins as
    they are and prints a [WARN] line. It then asks sshd what is really in
    effect, because another file (for example 50-cloud-init.conf) can override
    it. Keep your first SSH session open and try a second one before you close
    it
Every file it edits is first copied once to a .epma-bak backup, running it
twice changes nothing more, and --dry-run shows what it would do without
changing anything.

HOW TO UNDO
On the installed system run:
    sudo bash harden-linux.sh --undo
(a copy of the script is also kept in /root/harden-linux.sh on the installed
system).

A NOTE ON THE WORD 'HARDENED'
These settings are inspired by common security baselines. They are a sensible
starting point, not a compliance claim, certification or guarantee.
