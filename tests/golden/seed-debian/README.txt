EPMA HARDENING SEED - Debian (script + preseed)
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
Debian's installer does NOT detect this drive by itself. Pick one of these:

(a) Recommended. Install Debian normally. When it is done and you are logged
in, plug this drive in (a desktop usually mounts it under /media; otherwise
mount it yourself), open a terminal in the drive's folder and run:
    sudo bash harden-linux.sh
If sudo is not installed (Debian does not install it when you give root a
password during the install), become root first and run it from there:
    su -
    bash /path/to/harden-linux.sh

(b) Advanced. preseed.cfg is an example you can hand to the Debian installer
with boot parameters such as auto=true priority=critical file=... Read the
official Debian installation guide chapter on preseeding first: how the file
is found depends on your Debian version and on how you boot.

preseed.cfg holds no disk, account or password settings. Its last step
rebuilds the script inside the new system and runs it; if that fails, the
install still finishes and the log is in /var/log/epma-hardening.log.

WHAT THE SCRIPT CHANGES
harden-linux.sh is a plain text file on this drive: read it before you use it.
It prints every change it makes. Typical changes:
  - the ufw firewall blocks incoming connections by default, with SSH kept
    open when the SSH server is in use (it is not switched on when Docker,
    libvirt or LXD is found and you did not pass --yes)
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
(without sudo: become root with su - and run bash harden-linux.sh --undo. With
the preseed of option (b), a copy of the script is also kept in
/root/harden-linux.sh).

A NOTE ON THE WORD 'HARDENED'
These settings are inspired by common security baselines. They are a sensible
starting point, not a compliance claim, certification or guarantee.
