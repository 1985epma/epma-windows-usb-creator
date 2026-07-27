# Security Policy

This document describes the security model of **EPMA Windows 11 Creator USB**,
the protections implemented in the code, and the optional environment variables
that tune its security behaviour.

Full audit reports live in [`output/`](output/). *Note: the reports are written
in Portuguese.*

---

## Threat model in one sentence

This is a **desktop application** that runs with the user's privileges and, at
certain points, **as the system administrator** in order to erase and format
disks. There is no server, no database, and no user authentication. Only two
kinds of serious damage are possible:

1. **Data destruction** — erasing the wrong disk.
2. **Code execution as administrator** — a piece of data being interpreted as a command.

Every protection below exists to prevent one of those two outcomes.

### What this application does *not* do

Worth stating explicitly, because it removes entire classes of risk:

- It does not collect, store, or transmit any personal data.
- It has no telemetry, analytics, or crash reporting.
- It does not listen on any network port and accepts no incoming connections.
- It has no user accounts, sessions, or credentials of its own.
- Its only outbound network activity is downloading the ISO file you asked for.

---

## Implemented protections

### 1. Data never becomes a command (injection prevention)

Every privileged command receives its values as **positional shell parameters**
(`"$1"`, `"$2"`, …), never interpolated into the script text. A file path
containing `"`, `;` or `$(...)` is treated as data, not as an instruction.
See `PrivilegeHelper.run_script`.

This is the same principle as the prepared statements that protect databases
from SQL injection: **the data travels through a channel separate from the
command.**

### 2. Strict input validation

| Input | Rule |
|---|---|
| Disk identifier | `^disk[0-9]+$` (macOS) / `^[a-zA-Z0-9_+-]{1,32}$` (Linux). Anything else is rejected. |
| ISO path | Must exist, be a regular file, be readable, and be at least 1 MB. |
| Download URL | `https://` only. A host outside Microsoft's known download servers triggers an explicit warning. |
| SHA-256 checksum | Exactly 64 hexadecimal characters. |
| Package names to install | Only those in the fixed `LINUX_REQUIRED_TOOLS` list. |

The approach is to **reject rather than escape**: there is no legitimate disk
name containing a space or a quote. An allow-list has no forgotten edge cases;
an escaping rule can.

### 3. Fail closed

When the application **cannot confirm** that a disk is external and safe, it
**hides the disk** rather than offering it. Previously, a failed verification
resulted in the disk being listed anyway.

This includes a specific safeguard for machines that boot from removable media
(for example, a Raspberry Pi booting from its SD card, or a USB-booted system):
any disk holding `/`, `/boot`, `/home`, `/usr`, `/var` or `/etc` is hidden, even
when the operating system reports it as removable.

### 4. Re-verification before destruction

Immediately before erasing a disk, the application **re-enumerates the disk
list** and confirms that the chosen identifier still refers to the same device,
with the same size. Names such as `/dev/sdb` are recycled by the operating
system: if a drive is unplugged and another plugged in between selection and
writing, the name can point somewhere else entirely. The operation is aborted in
that case.

### 5. Integrity verification of the downloaded image

The SHA-256 checksum (the file's "fingerprint") is computed during the download
and displayed when it finishes. If an expected value is supplied, a mismatch
causes the file to be **discarded**. Incomplete downloads are discarded as well.

### 6. Handling of the administrator password

- Passed over `stdin` only — **never** on the command line, which is visible to
  other users on the machine through the `ps` command.
- Never written to any log, including the audit log.
- Cleared from memory as soon as the operation completes
  (`PrivilegeHelper.clear_cached_password`).

### 7. Audit logging

Destructive operations and security-relevant events are recorded to a file with
`0600` permissions (owner-read only). The log **never** contains passwords.

Default location: `~/.local/state/epma-win11-usb-creator/audit.log`

Recorded events include: start/completion/failure of destructive operations,
disks hidden for safety reasons, rejected identifiers, download origin, and the
result of integrity verification.

If the home directory is not writable, logging is silently disabled — **failing
to write a log must never stop a user from creating their USB drive.**

### 8. Errors that do not leak information

Unexpected failures show a short message on screen; the technical detail
(internal paths, command lines) goes to the local log and the audit log, not to
a dialog box.

---

## Environment variables

**None are required.** The application works without configuring anything. There
are no secrets, passwords, or API keys in this project.

| Variable | Required? | Purpose |
|---|---|---|
| `WIN11USB_AUDIT_LOG` | Optional | Alternative path for the audit log. |
| `WIN11USB_DISABLE_AUDIT_LOG` | Optional | Set to `1` to disable audit logging. |
| `WIN11USB_TRUSTED_ISO_HOSTS` | Optional | Comma-separated list of trusted download hosts, replacing the default Microsoft list. |
| `WIN11USB_ALLOW_ANY_DOWNLOAD_HOST` | Optional | Set to `1` to disable the unrecognised-server warning. **Reduces security.** |
| `WIN11USB_EXPECTED_SHA256` | Optional | Pre-fills the expected checksum field. |

How to set one (macOS/Linux, in a terminal):

```bash
export WIN11USB_AUDIT_LOG="$HOME/my-logs/usb-creator.log"
python3 win11_usb_creator.py
```

To make it permanent, add the `export ...` line to `~/.zshrc` (macOS) or
`~/.bashrc` (Linux).

---

## Verifying that you are running authentic code

This application asks for your administrator password, which makes a tampered
copy a worthwhile target. Before running it:

```bash
shasum -a 256 win11_usb_creator.py
```

For files obtained from a
[release](https://github.com/1985epma/epma-windows-usb-creator/releases),
compare the result against the published `SHA256SUMS.txt`, or verify the build
provenance attestation issued by GitHub:

```bash
gh attestation verify win11_usb_creator.py --repo 1985epma/epma-windows-usb-creator
```

The attestation proves the file was produced by this project's CI pipeline from
this source code — not assembled on someone else's machine.

---

## Known residual risks

Four risks could not be eliminated in code alone. They are documented honestly
rather than hidden.

| Risk | Severity | Why it remains | What you should do |
|---|---|---|---|
| **Image authenticity depends on the user.** If no expected checksum is supplied, verification does not happen. | High | Microsoft updates the Windows image periodically and does not publish checksums in a stable, automatable form. A value hard-coded here would be wrong after the next update — and an application that rejects the legitimate image is worse than one that warns. | Always download from Microsoft's official site. Paste the published checksum when one is available. |
| **No code signing certificate.** Anyone can edit the `.py` file, and the tampered version would request the administrator password normally. | Medium | Code signing requires a paid certificate and a publishing process beyond the scope of the source code. | Obtain the program only from the official repository or a release, and verify it as shown above. |
| **System utilities are resolved via `PATH`.** A fake `parted` in a directory earlier in `PATH` would be executed. | Medium | Hard-coding absolute paths would break compatibility across Linux distributions, which install these tools in different locations. | No urgent action. Exploiting this requires already controlling the user's account, at which point more direct attacks are available. |
| **Formatting does not overwrite previous data.** Recovery tools can retrieve part of the USB drive's earlier contents. | Low | Overwriting every sector would multiply write time several times over; it is not appropriate as default behaviour. | If the drive held sensitive data, wipe it first with `shred` (Linux) or "Erase securely" in Disk Utility (macOS). |

---

## User responsibilities

Two things the code cannot guarantee on its own:

1. **Keep your operating system updated.** The application depends on `parted`,
   `rsync`, `wimlib` and other system utilities. Their security fixes arrive
   through system updates (`sudo apt upgrade`, `brew upgrade`).

2. **Verify the authenticity of the Windows image.** The application warns and
   computes the fingerprint, but only you can compare it against the value
   published by Microsoft. **Always download from the official site.**

---

## Reporting a vulnerability

Please open an issue at
<https://github.com/1985epma/epma-windows-usb-creator/issues>.

For sensitive findings, avoid publishing exploitation details before a fix is
available. Include the affected version (the SHA-256 of `win11_usb_creator.py`),
the platform, and reproduction steps.
