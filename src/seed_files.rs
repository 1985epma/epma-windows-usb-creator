//! Contents of the hardening seed drives: cloud-init (Ubuntu), kickstart (Fedora/RHEL), preseed (Debian) and the
//! Windows 11 seed (harden.cmd / audit.cmd / undo.cmd / harden.ps1 / README.txt). OWNER: A5.
//! Port of win11_usb_creator.py lines 7940-8461. Output is byte-identical to the Python (tests/golden/seed-*).
//!
//! The files of the "seed drive": a small second USB that is plugged in next to a Linux installer USB. Nothing here
//! selects a disk, creates an account or stores a secret: storage, accounts and the final summary stay interactive in
//! every installer. The hardening script is embedded as base64 inside the seed itself (so the seed works even when
//! the other files are not read) and is also written as a plain file for reading and for running by hand. Output is
//! deterministic: same input, same bytes.

use crate::harden_linux::linux_hardening_script;
use crate::harden_windows::{describe_hardening_windows_applied, windows_hardening_ps1, WINDOWS_HARDENING_NOT_CHANGED};
use crate::types::{Error, Files, Hardening, Result, SeedTarget};

pub const SEED_HARDEN_FILE: &str = "harden-linux.sh";
/// Written inside the installed system, in /var/log.
pub const SEED_LOG_NAME: &str = "epma-hardening.log";
pub const SEED_BASE64_WIDTH: usize = 76;
/// Debian's late_command is ONE command line handed to a shell, so every `echo` costs a few dozen bytes of overhead;
/// long base64 lines keep that overhead small. A single argument may not be longer than MAX_ARG_STRLEN (131072 bytes
/// on Linux): the generated command is refused above `SEED_DEBIAN_LATE_MAX`.
pub const SEED_DEBIAN_B64_WIDTH: usize = 4096;
pub const SEED_DEBIAN_LATE_MAX: usize = 100_000;
pub const SEED_README_WIDTH: usize = 78;
/// The installer screens that stay interactive for Ubuntu: "*" means EVERY section, so storage and identity (and all
/// the others) are asked on screen; the seed only adds late-commands.
pub const SEED_UBUNTU_INTERACTIVE: &[&str] = &["*"];
pub const SEED_PACKAGES_DEB: &[&str] = &["ufw", "auditd", "unattended-upgrades"];
pub const SEED_PACKAGES_RPM: &[&str] = &["firewalld", "audit", "dnf-automatic"];

pub const SEED_WINDOWS_LABEL: &str = "EPMA-SEED";
pub const SEED_WINDOWS_README_WIDTH: usize = 76;
/// The log of harden.ps1, as shown to the user.
pub const SEED_WINDOWS_LOG_SHOWN: &str = "C:\\Windows\\Temp\\epma-hardening.log";

/// One double-click launcher of the Windows seed drive.
pub struct WindowsLauncher {
    /// File name on the drive.
    pub name: &'static str,
    /// The `harden.ps1 -Mode` it runs.
    pub mode: &'static str,
    /// Asks "Continue? [y/N]" first.
    pub confirm: bool,
    /// Lines echoed before anything happens.
    pub banner: &'static [&'static str],
}

/// SEED_WINDOWS_LAUNCHERS (the banner lines that end in the log path start with `SEED_WINDOWS_LOG_SHOWN`).
pub const SEED_WINDOWS_LAUNCHERS: &[WindowsLauncher] = &[
    WindowsLauncher {
        name: "harden.cmd",
        mode: "Apply",
        confirm: true,
        banner: &[
            "EPMA USB CREATOR - hardening of this Windows PC. EXPERIMENTAL scripts.",
            "This applies a small set of recommended security settings with harden.ps1.",
            "Nothing is installed and nothing is downloaded. A log is written to",
            "C:\\Windows\\Temp\\epma-hardening.log. Run audit.cmd first to see a report.",
        ],
    },
    WindowsLauncher {
        name: "audit.cmd",
        mode: "Audit",
        confirm: false,
        banner: &[
            "EPMA USB CREATOR - report on this Windows PC. EXPERIMENTAL scripts.",
            "This only reports which settings are in effect. It changes nothing.",
            "Nothing is installed and nothing is downloaded. Administrator rights are",
            "still needed because some of the checks cannot be read without them.",
        ],
    },
    WindowsLauncher {
        name: "undo.cmd",
        mode: "Undo",
        confirm: true,
        banner: &[
            "EPMA USB CREATOR - undo the hardening of this Windows PC. EXPERIMENTAL scripts.",
            "This asks harden.ps1 to put back the settings it changed earlier.",
            "Nothing is installed and nothing is downloaded. A log is written to",
            "C:\\Windows\\Temp\\epma-hardening.log.",
        ],
    },
];

/// SEED_LABELS: FAT volume label of each seed drive (Ubuntu CIDATA, Fedora OEMDRV, Debian EPMA-SEED, Windows
/// EPMA-SEED).
pub fn seed_label(target: SeedTarget) -> &'static str {
    match target {
        SeedTarget::Ubuntu => "CIDATA",
        SeedTarget::Fedora => "OEMDRV",
        SeedTarget::Debian => "EPMA-SEED",
        SeedTarget::Windows => SEED_WINDOWS_LABEL,
    }
}

/// SEED_README_TITLES (Linux targets; the Windows README has its own title).
fn seed_readme_title(target: SeedTarget) -> &'static str {
    match target {
        SeedTarget::Ubuntu => "Ubuntu (autoinstall)",
        SeedTarget::Fedora => "Fedora / RHEL / Rocky / Alma (kickstart)",
        SeedTarget::Debian => "Debian (script + preseed)",
        SeedTarget::Windows => "Windows 11 (experimental scripts)",
    }
}

fn seed_check_args(profile: Hardening) -> Result<()> {
    // The target cannot be unknown (it is an enum); the Python "Unknown seed target" and "Unknown hardening profile"
    // errors have no equivalent here.
    if profile == Hardening::None {
        return Err(Error::value("The 'none' hardening profile has no seed files"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// base64 (standard alphabet, with padding): std only, the crate has no base64 dependency
// ---------------------------------------------------------------------------------------------------------------

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// `base64.b64encode(data).decode("ascii")`.
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], chunk.get(1).copied().unwrap_or(0), chunk.get(2).copied().unwrap_or(0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(char::from(B64_ALPHABET[(n >> 18) as usize & 63]));
        out.push(char::from(B64_ALPHABET[(n >> 12) as usize & 63]));
        out.push(if chunk.len() > 1 { char::from(B64_ALPHABET[(n >> 6) as usize & 63]) } else { '=' });
        out.push(if chunk.len() > 2 { char::from(B64_ALPHABET[n as usize & 63]) } else { '=' });
    }
    out
}

/// The base64 text of `data` cut into lines of `width` characters (plain ASCII: no '%', no quotes, no spaces).
fn seed_b64_lines(data: &[u8], width: usize) -> Vec<String> {
    let text = base64_encode(data);
    // The alphabet is ASCII, so cutting at byte offsets cuts at characters.
    text.as_bytes().chunks(width.max(1)).map(|c| String::from_utf8_lossy(c).into_owned()).collect()
}

fn seed_failure_echo(log: &str) -> String {
    format!(
        "echo \"EPMA hardening failed (exit status $?); the installation goes on. Run it again later with: sudo bash \
         /root/{SEED_HARDEN_FILE}\" >> {log}"
    )
}

/// `body.encode("ascii")`: the Python raises (a ValueError subclass) for anything else.
fn ascii_bytes(body: String) -> Result<Vec<u8>> {
    if body.is_ascii() {
        Ok(body.into_bytes())
    } else {
        Err(Error::value("The seed file is not plain ASCII"))
    }
}

/// `"\n".join(lines) + "\n"`.
fn join_lines(lines: &[String]) -> String {
    let mut text = lines.join("\n");
    text.push('\n');
    text
}

// ---------------------------------------------------------------------------------------------------------------
// Ubuntu / Fedora / Debian
// ---------------------------------------------------------------------------------------------------------------

fn seed_ubuntu_user_data(script: &[u8]) -> String {
    let log = format!("/target/var/log/{SEED_LOG_NAME}");
    let mut lines: Vec<String> = [
        "#cloud-config",
        "# EPMA hardening seed for the Ubuntu installer (autoinstall). Read README.txt first.",
        "# Every section is interactive ('*'): all installer screens are asked on screen as usual and",
        "# this file only adds the late-commands below. No disk layout, no account, no password and no",
        "# key is stored here, and no packages: the script installs what it needs on the first boot.",
        "autoinstall:",
        "  version: 1",
        "  interactive-sections:",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    lines.extend(SEED_UBUNTU_INTERACTIVE.iter().map(|name| format!("    - \"{name}\"")));
    lines.push("  late-commands:".into());
    lines.push("    - |".into());
    lines.push("      mkdir -p /target/root /target/var/log".into());
    lines.push(format!("      base64 -d > /target/root/{SEED_HARDEN_FILE} <<'EPMA_B64'"));
    lines.extend(seed_b64_lines(script, SEED_BASE64_WIDTH).into_iter().map(|chunk| format!("      {chunk}")));
    lines.push("      EPMA_B64".into());
    lines.push(format!("      chmod 700 /target/root/{SEED_HARDEN_FILE}"));
    lines.push("      true".into());
    lines.push("    - |".into());
    lines.push(format!(
        "      if curtin in-target --target=/target -- /bin/bash /root/{SEED_HARDEN_FILE} --yes --chroot; then"
    ));
    lines.push(format!("        echo \"EPMA hardening finished\" >> {log}"));
    lines.push("      else".into());
    lines.push(format!("        {}", seed_failure_echo(&log)));
    lines.push("      fi".into());
    lines.push("      true".into());
    join_lines(&lines)
}

fn seed_ubuntu_meta_data() -> String {
    "instance-id: epma-hardening-seed\nlocal-hostname: epma-ubuntu\n".to_string()
}

fn seed_fedora_ks(script: &[u8]) -> String {
    let log = format!("/var/log/{SEED_LOG_NAME}");
    let mut lines: Vec<String> = [
        "# EPMA hardening seed for Anaconda (kickstart). Read README.txt first.",
        "# This file only adds a few packages and runs the hardening script after the install.",
        "# Language, keyboard, disk, accounts and the summary are still asked on screen.",
        "",
        "%packages --ignoremissing",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    lines.extend(SEED_PACKAGES_RPM.iter().map(|s| s.to_string()));
    for line in [
        "%end",
        "",
        "# Runs inside the new system (the default). A failure here never stops the install.",
        "%post",
        "mkdir -p /root /var/log",
    ] {
        lines.push(line.into());
    }
    lines.push(format!("base64 -d > /root/{SEED_HARDEN_FILE} <<'EPMA_B64'"));
    lines.extend(seed_b64_lines(script, SEED_BASE64_WIDTH));
    lines.push("EPMA_B64".into());
    lines.push(format!("chmod 700 /root/{SEED_HARDEN_FILE}"));
    lines.push(format!("if /bin/bash /root/{SEED_HARDEN_FILE} --yes --chroot; then"));
    lines.push(format!("  echo \"EPMA hardening finished\" >> {log}"));
    lines.push("else".into());
    lines.push(format!("  {}", seed_failure_echo(&log)));
    lines.push("fi".into());
    lines.push("exit 0".into());
    lines.push("%end".into());
    join_lines(&lines)
}

fn seed_debian_preseed(script: &[u8]) -> Result<String> {
    let log = format!("/var/log/{SEED_LOG_NAME}");
    let b64 = "/target/root/harden-linux.b64";
    let inner = format!(
        "base64 -d /root/harden-linux.b64 > /root/{SEED_HARDEN_FILE} && chmod 700 /root/{SEED_HARDEN_FILE} \
         && rm -f /root/harden-linux.b64 && /bin/bash /root/{SEED_HARDEN_FILE} --yes --chroot \
         && echo EPMA-hardening-finished >> {log} || echo EPMA-hardening-failed-installation-goes-on >> {log}"
    );
    let mut steps: Vec<String> = vec!["mkdir -p /target/root".into(), format!(": > {b64}")];
    steps.extend(
        seed_b64_lines(script, SEED_DEBIAN_B64_WIDTH).into_iter().map(|chunk| format!("echo {chunk} >> {b64}")),
    );
    steps.push(format!("in-target /bin/sh -c '{inner}'"));
    steps.push("true".into());
    let size = steps.join("; ").len();
    if size > SEED_DEBIAN_LATE_MAX {
        return Err(Error::value(format!(
            "The Debian preseed late_command would be {size} bytes (the limit is {SEED_DEBIAN_LATE_MAX}; a single \
             command argument may not exceed 131072 bytes): the hardening script is too large"
        )));
    }
    let mut lines: Vec<String> = [
        "# EPMA hardening seed for the Debian installer (preseed). Read README.txt first.",
        "# Debian's installer does not find this drive by itself: see README.txt.",
        "# Only non-disk, language-neutral settings are here; disk, accounts and the rest are asked.",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    lines.push(format!("d-i pkgsel/include string {}", SEED_PACKAGES_DEB.join(" ")));
    lines.push("d-i pkgsel/update-policy select unattended-upgrades".into());
    lines.push("# The script is carried as base64 text and rebuilt inside the new system. Any failure".into());
    lines.push("# is logged and ignored, so the installation always finishes.".into());
    lines.push("d-i preseed/late_command string \\".into());
    if let Some((last, init)) = steps.split_last() {
        lines.extend(init.iter().map(|step| format!("    {step}; \\")));
        lines.push(format!("    {last}"));
    }
    Ok(join_lines(&lines))
}

// ---------------------------------------------------------------------------------------------------------------
// textwrap
// ---------------------------------------------------------------------------------------------------------------

/// `textwrap.wrap(text, width, initial_indent=..., subsequent_indent=..., break_on_hyphens=False,
/// break_long_words=False)`: the same greedy algorithm. The text is cut into alternating runs of whitespace and of
/// non-whitespace; a line takes chunks while they fit (`width` counts the indent), a word longer than a whole line goes
/// alone on its line (it is never broken), whitespace at a line's end is dropped and so is whitespace at the start of
/// every line but the first. Tabs are expanded to multiples of 8 and every whitespace character becomes a space first
/// (the texts here have none).
pub fn wrap_text(text: &str, width: usize, initial_indent: &str, subsequent_indent: &str) -> Vec<String> {
    let is_ws = |c: char| matches!(c, '\t' | '\n' | '\x0b' | '\x0c' | '\r' | ' ');
    // expand_tabs, then replace_whitespace
    let mut munged = String::with_capacity(text.len());
    let mut column = 0usize;
    for c in text.chars() {
        match c {
            '\t' => {
                let n = 8 - column % 8;
                munged.extend(std::iter::repeat_n(' ', n));
                column += n;
            }
            '\n' | '\r' => {
                munged.push(' ');
                column = 0;
            }
            c if is_ws(c) => {
                munged.push(' ');
                column += 1;
            }
            c => {
                munged.push(c);
                column += 1;
            }
        }
    }
    // _split: runs of whitespace and of non-whitespace
    let mut chunks: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut current_is_ws = false;
    for c in munged.chars() {
        let w = is_ws(c);
        if !current.is_empty() && w != current_is_ws {
            chunks.push(std::mem::take(&mut current));
        }
        current_is_ws = w;
        current.push(c);
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    // _wrap_chunks (the chunks are consumed from the front: `idx` is the Python `chunks[-1]` of the reversed list)
    let len = |s: &str| s.chars().count();
    let mut lines: Vec<String> = Vec::new();
    let mut idx = 0usize;
    while idx < chunks.len() {
        let mut cur_line: Vec<&str> = Vec::new();
        let mut cur_len = 0usize;
        let indent = if lines.is_empty() { initial_indent } else { subsequent_indent };
        let avail = width as i64 - len(indent) as i64;
        if !lines.is_empty() && chunks[idx].trim_matches(is_ws).is_empty() {
            idx += 1;
        }
        while idx < chunks.len() {
            let l = len(&chunks[idx]) as i64;
            if cur_len as i64 + l <= avail {
                cur_len += l as usize;
                cur_line.push(&chunks[idx]);
                idx += 1;
            } else {
                break;
            }
        }
        if idx < chunks.len() && len(&chunks[idx]) as i64 > avail && cur_line.is_empty() {
            // _handle_long_word with break_long_words=False: the long word stands alone on its line
            cur_line.push(&chunks[idx]);
            idx += 1;
        }
        if cur_line.last().is_some_and(|c| c.trim_matches(is_ws).is_empty()) {
            cur_line.pop();
        }
        if !cur_line.is_empty() {
            lines.push(format!("{indent}{}", cur_line.concat()));
        }
    }
    lines
}

/// The README builder shared by the Linux and Windows seeds (`para`, `blank`, `code`, `heading` of the Python).
struct Readme {
    out: Vec<String>,
    width: usize,
}

impl Readme {
    fn new(width: usize) -> Self {
        Readme { out: Vec::new(), width }
    }
    fn line(&mut self, text: &str) {
        self.out.push(text.to_string());
    }
    /// `para(text, bullet, indent)`.
    fn para_with(&mut self, text: &str, bullet: &str, indent: &str) {
        let first = format!("{indent}{bullet}");
        let rest = format!("{indent}{}", " ".repeat(bullet.chars().count()));
        self.out.extend(wrap_text(text, self.width, &first, &rest));
    }
    fn para(&mut self, text: &str) {
        self.para_with(text, "", "");
    }
    /// `para(text, "- ", "  ")`.
    fn item(&mut self, text: &str) {
        self.para_with(text, "- ", "  ");
    }
    fn blank(&mut self) {
        self.out.push(String::new());
    }
    fn code(&mut self, commands: &[&str]) {
        self.out.extend(commands.iter().map(|c| format!("    {c}")));
    }
    fn heading(&mut self, text: &str) {
        self.blank();
        self.out.push(text.to_ascii_uppercase());
    }
}

fn seed_readme(target: SeedTarget) -> String {
    let mut r = Readme::new(SEED_README_WIDTH);
    r.line(&format!("EPMA HARDENING SEED - {}", seed_readme_title(target)));
    r.line(&"=".repeat(60));
    r.heading("What this drive is");
    r.para(
        "A small helper drive made by EPMA USB CREATOR. It holds settings files that make a fresh \
         Linux install start from safer settings (a firewall, audit logging, automatic security \
         updates and similar). It is not an installer and it does not boot by itself.",
    );
    r.heading("Use it as a SECOND USB");
    r.para(
        "Keep your normal installer USB (the one you wrote the Linux ISO to) and plug this drive in \
         next to it, before you start the installer.",
    );
    r.heading("What it does NOT do");
    r.para(
        "Nothing here selects a disk, partitions, formats or erases anything, and nothing creates \
         an account or sets a password or key. You still choose the disk and create your own \
         account in the installer. Check each screen before you confirm it.",
    );
    r.heading("How to use it");
    match target {
        SeedTarget::Ubuntu => {
            r.para(
                "Meant for the Ubuntu Server live installer (autoinstall). Other Ubuntu flavours \
                 may ignore it. The drive is named CIDATA, which the installer looks for.",
            );
            r.blank();
            r.para_with("Plug in both USB drives and start the computer from the installer USB.", "1. ", "");
            r.para_with("At the GRUB boot menu, press e to edit the boot entry.", "2. ", "");
            r.para_with(
                "On the line that starts with linux, add the word autoinstall before the --- \
                 (leave the rest as it is).",
                "3. ",
                "",
            );
            r.para_with("Press F10 (or Ctrl+X) to boot.", "4. ", "");
            r.blank();
            r.para(
                "Without the word autoinstall the installer asks you to confirm before it uses these \
                 files. Every installer screen stays interactive (the seed marks all sections as \
                 interactive): it still asks for language, keyboard, network, disk, your account and \
                 time zone, as usual. The seed only adds a hardening step at the end.",
            );
            r.blank();
            r.para(
                "The seed does not install any package during the install. The settings that need \
                 no package are written then; the packages ufw, auditd and unattended-upgrades are \
                 installed by the hardening script on the first boot of the installed system, so \
                 that first boot needs an internet connection (it tries again at the next boot, up \
                 to 5 times, and then gives up).",
            );
            r.blank();
            r.para(&format!(
                "A log is kept in the installed system: /var/log/{SEED_LOG_NAME}. If the script \
                 fails, the installation still finishes."
            ));
        }
        SeedTarget::Fedora => {
            r.para(
                "For Fedora, RHEL, Rocky Linux and AlmaLinux (Anaconda). The drive is named OEMDRV, \
                 which Anaconda detects by itself and reads ks.cfg from.",
            );
            r.blank();
            r.para_with("Plug in both USB drives and start the computer from the installer USB.", "1. ", "");
            r.para_with(
                "Anaconda opens as usual. Choose the language, the install destination (disk), \
                 your root/user accounts and, if asked, the software selection.",
                "2. ",
                "",
            );
            r.para_with("Check the summary and start the installation yourself.", "3. ", "");
            r.blank();
            r.para(&format!(
                "The kickstart adds the packages firewalld, audit and dnf-automatic and runs the script \
                 inside the new system at the end. A log is kept in /var/log/{SEED_LOG_NAME}. \
                 If the script fails, the installation still finishes."
            ));
        }
        _ => {
            r.para("Debian's installer does NOT detect this drive by itself. Pick one of these:");
            r.blank();
            r.para(
                "(a) Recommended. Install Debian normally. When it is done and you are logged in, \
                 plug this drive in (a desktop usually mounts it under /media; otherwise mount it \
                 yourself), open a terminal in the drive's folder and run:",
            );
            r.code(&["sudo bash harden-linux.sh"]);
            r.para(
                "If sudo is not installed (Debian does not install it when you give root a password \
                 during the install), become root first and run it from there:",
            );
            r.code(&["su -", "bash /path/to/harden-linux.sh"]);
            r.blank();
            r.para(
                "(b) Advanced. preseed.cfg is an example you can hand to the Debian installer with \
                 boot parameters such as auto=true priority=critical file=... Read the official \
                 Debian installation guide chapter on preseeding first: how the file is found \
                 depends on your Debian version and on how you boot.",
            );
            r.blank();
            r.para(&format!(
                "preseed.cfg holds no disk, account or password settings. Its last step rebuilds \
                 the script inside the new system and runs it; if that fails, the install still \
                 finishes and the log is in /var/log/{SEED_LOG_NAME}."
            ));
        }
    }
    r.heading("What the script changes");
    r.para(
        "harden-linux.sh is a plain text file on this drive: read it before you use it. It prints \
         every change it makes. Typical changes:",
    );
    let firewall = if target == SeedTarget::Fedora {
        "the firewalld firewall is switched on; its default zone is left exactly as \
         Fedora/RHEL set it (the script does not make it stricter), and SSH is \
         allowed in that zone when the SSH server is in use"
    } else {
        "the ufw firewall blocks incoming connections by default, with SSH kept open \
         when the SSH server is in use (it is not switched on when Docker, libvirt or \
         LXD is found and you did not pass --yes)"
    };
    for item in [
        firewall,
        "audit logging of security-relevant events",
        "automatic security updates",
        "safer kernel and network settings (a setting that is already stricter is not \
         lowered)",
        "conservative SSH server settings. The script tries not to lock you out, but \
         it cannot promise your login keeps working: it refuses root logins over SSH \
         only when a normal user in the sudo (Debian/Ubuntu) or wheel (Fedora/RHEL) \
         group exists, and refuses password logins only when such a user has a key in \
         authorized_keys. Otherwise it leaves those logins as they are and prints a \
         [WARN] line. It then asks sshd what is really in effect, because another \
         file (for example 50-cloud-init.conf) can override it. Keep your first SSH \
         session open and try a second one before you close it",
    ] {
        r.para_with(item, "- ", "  ");
    }
    r.para(
        "Every file it edits is first copied once to a .epma-bak backup, running it twice \
         changes nothing more, and --dry-run shows what it would do without changing anything.",
    );
    r.heading("How to undo");
    r.para("On the installed system run:");
    r.code(&["sudo bash harden-linux.sh --undo"]);
    if target == SeedTarget::Debian {
        r.para(&format!(
            "(without sudo: become root with su - and run bash harden-linux.sh --undo. With the \
             preseed of option (b), a copy of the script is also kept in /root/{SEED_HARDEN_FILE})."
        ));
    } else {
        r.para(&format!("(a copy of the script is also kept in /root/{SEED_HARDEN_FILE} on the installed system)."));
    }
    r.heading("A note on the word 'hardened'");
    r.para(
        "These settings are inspired by common security baselines. They are a sensible starting \
         point, not a compliance claim, certification or guarantee.",
    );
    join_lines(&r.out)
}

/// The Linux seed files from the text of the hardening script: `(label, files)` for Ubuntu, Fedora or Debian.
/// Split from `hardening_files_seed` so the script can be injected (the Python tests patch
/// `linux_hardening_script`).
pub fn linux_seed_files_from(target: SeedTarget, script_text: &str) -> Result<(String, Files)> {
    if script_text.trim().is_empty() {
        return Err(Error::value("The hardening script is empty"));
    }
    let script = script_text.as_bytes();
    let texts: Vec<(&str, String)> = match target {
        SeedTarget::Ubuntu => {
            vec![("user-data", seed_ubuntu_user_data(script)), ("meta-data", seed_ubuntu_meta_data())]
        }
        SeedTarget::Fedora => vec![("ks.cfg", seed_fedora_ks(script))],
        SeedTarget::Debian => vec![("preseed.cfg", seed_debian_preseed(script)?)],
        SeedTarget::Windows => return Err(Error::value("The Windows seed has no Linux files")),
    };
    let mut files = Files::new();
    for (name, body) in texts {
        files.insert(name.to_string(), ascii_bytes(body)?);
    }
    files.insert(SEED_HARDEN_FILE.to_string(), script.to_vec());
    files.insert("README.txt".to_string(), ascii_bytes(seed_readme(target))?);
    Ok((seed_label(target).to_string(), files))
}

// ---------------------------------------------------------------------------------------------------------------
// The Windows 11 seed drive
// ---------------------------------------------------------------------------------------------------------------

/// The bytes of one double-click launcher (CRLF, plain ASCII, no BOM).
///
/// It re-launches itself as administrator when it is not (a UAC prompt), optionally asks `Continue? [y/N]`, runs
/// harden.ps1 from its own folder (`%~dp0`, quoted: paths with spaces work) in the given mode and waits for a key so
/// that the window stays open. It never deletes, formats or partitions anything.
///
/// System tools are called by full path (and the current folder is never searched for programs). The path of the
/// launcher itself reaches PowerShell through an environment variable, never inside a PowerShell string, so a folder
/// name with any quote character (a typographic apostrophe included) cannot break out of it. The confirmation is the
/// system `choice` tool: it answers 1 for y and 2 for n; an error (255) counts as n, Ctrl+C (0) falls through to the
/// cancel lines, and nothing typed is ever parsed by cmd.
pub fn windows_seed_launcher(name: &str, mode: &str, confirm: bool, banner: &[&str]) -> Vec<u8> {
    let system32 = "%SystemRoot%\\System32\\";
    let powershell = format!("{system32}WindowsPowerShell\\v1.0\\powershell.exe");
    let ps = format!("\"{powershell}\" -NoProfile -ExecutionPolicy Bypass -File \"%~dp0harden.ps1\" -Mode {mode}");
    let flag = if mode == "Audit" { "DIFF" } else { "WARN" };
    let mut lines: Vec<String> = vec![
        "@echo off".into(),
        "setlocal".into(),
        "set \"NoDefaultCurrentDirectoryInExePath=1\"".into(),
        format!("rem {name}: EPMA hardening seed for Windows 11 (EXPERIMENTAL scripts, see README.txt)."),
        format!("rem Runs harden.ps1 -Mode {mode} from this folder. Nothing is installed or downloaded."),
        format!("title EPMA hardening - {mode}"),
        "set \"EPMA_SELF=%~f0\"".into(),
        "echo.".into(),
    ];
    lines.extend(banner.iter().map(|text| format!("echo {text}")));
    lines.push("echo.".into());
    lines.push(format!("{system32}net.exe session >nul 2>&1"));
    lines.push("if not errorlevel 1 goto :admin".into());
    lines.push(format!("{system32}fltmc.exe >nul 2>&1"));
    lines.push("if not errorlevel 1 goto :admin".into());
    lines.push("if /i \"%~1\"==\"elevated\" goto :noadmin".into());
    lines.push("echo Administrator rights are needed. Windows will now show a prompt:".into());
    lines.push("echo choose Yes to continue. A new window opens for the work.".into());
    lines.push(format!(
        "\"{powershell}\" -NoProfile -ExecutionPolicy Bypass -Command \
         \"Start-Process -FilePath $env:EPMA_SELF -ArgumentList 'elevated' -Verb RunAs\""
    ));
    for line in [
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
    ] {
        lines.push(line.into());
    }
    if confirm {
        lines.push(format!("{system32}choice.exe /c yn /n /m \"Continue? [y/N] \""));
        for line in [
            "if errorlevel 2 goto :cancel",
            "if errorlevel 1 goto :run",
            ":cancel",
            "echo.",
            "echo Cancelled. Nothing was changed.",
            "pause",
            "exit /b 1",
            "",
            ":run",
        ] {
            lines.push(line.into());
        }
    }
    lines.push(ps);
    lines.push("set \"RC=%errorlevel%\"".into());
    lines.push("echo.".into());
    lines.push(format!("echo Finished with exit code %RC%. Read the lines above: a [{flag}] line means a"));
    lines.push("echo setting is not in effect. A restart may be needed for a few settings.".into());
    if mode == "Undo" {
        lines.push("echo Undo can finish with a non-zero exit code when one of its steps failed.".into());
    }
    lines.push("pause".into());
    lines.push("exit /b %RC%".into());
    let mut text = lines.join("\r\n");
    text.push_str("\r\n");
    text.into_bytes()
}

/// README.txt of the Windows seed drive: ASCII, CRLF (Notepad), lines of at most 76 characters. `applied` is
/// `describe_hardening_windows_applied(profile)` and `not_changed` is `WINDOWS_HARDENING_NOT_CHANGED` (injected so
/// the text can be produced and tested without the Windows hardening module).
pub fn windows_seed_readme_from(applied: &[String], not_changed: &[(&str, &str, &str)]) -> Vec<u8> {
    let mut r = Readme::new(SEED_WINDOWS_README_WIDTH);
    r.line("EPMA HARDENING SEED - Windows 11 (experimental scripts)");
    r.line(&"=".repeat(60));
    r.heading("What this drive is");
    r.para(
        "A small helper drive made by EPMA USB CREATOR. It holds a PowerShell script and three \
         double-click launchers that apply a small set of recommended security settings to \
         Windows 11. It is a SECOND small USB. It is NOT a Windows installer and it does not \
         boot by itself. Nothing is installed and nothing is downloaded.",
    );
    r.heading("How to use it: run it after Windows is installed");
    for (n, text) in [
        "Install Windows 11 as usual, then sign in with an administrator account.",
        "Plug this drive in and open it in File Explorer.",
        "Right-click audit.cmd and choose Open (or double-click it) FIRST. Windows asks for \
         permission (the User Account Control prompt): choose Yes. audit.cmd does not ask \
         you to confirm anything: it only shows a report of what is in effect and changes \
         nothing. In the report [OK] means in effect, [DIFF] means NOT in effect and [N/A] \
         means it does not apply to this PC.",
        "Then double-click harden.cmd. Windows asks for permission again: choose Yes. \
         harden.cmd then asks 'Continue? [y/N]': press y to apply the settings, n to cancel.",
        "Read the lines it prints. A [WARN] line means that a setting is NOT in effect. \
         Nothing was forced.",
        "To go back, double-click undo.cmd (it asks 'Continue? [y/N]' too). Read the limits \
         of undo.cmd below.",
    ]
    .iter()
    .enumerate()
    {
        r.para_with(text, &format!("{}. ", n + 1), "");
    }
    r.blank();
    r.para(&format!(
        "harden.cmd and undo.cmd write a log to {SEED_WINDOWS_LOG_SHOWN}. audit.cmd only \
         prints in its window. A restart may be needed for a few settings. Running harden.cmd \
         twice changes nothing more."
    ));
    r.heading("Limits of undo.cmd");
    for text in [
        "undo.cmd puts back the settings that harden.ps1 recorded when it changed them.",
        "It does not turn SMBv1 or PowerShell 2.0 on again (the log prints the command to do \
         it by hand), and it does not lower the Security log size.",
        "A setting that was already in the wanted state before harden.cmd ran is not \
         recorded, so undo.cmd leaves it as it is.",
        "undo.cmd can finish with a non-zero exit code when one of its steps failed: read the \
         lines it prints.",
    ] {
        r.item(text);
    }
    r.heading("What the script changes");
    for line in applied {
        r.item(line.split(" -- risk:").next().unwrap_or(""));
    }
    r.para_with(
        "Opt-in, never applied by default: harden.ps1 can also turn off NetBIOS over TCP/IP and \
         WPAD proxy auto-discovery (it can break very old networks). To apply them too, open \
         PowerShell as administrator, go to this drive (for example: E:) and run this \
         command (type it as one line):",
        "- ",
        "  ",
    );
    r.line("      powershell -ExecutionPolicy Bypass -File harden.ps1 -Mode Apply");
    r.line("        -DisableLegacyNetwork");
    r.heading("What it leaves alone");
    for (_sid, text, why) in not_changed {
        r.item(&format!("{text}. {why}"));
    }
    r.heading("Read the files before you run them");
    r.para(
        "harden.cmd, audit.cmd, undo.cmd and harden.ps1 are plain text files. Open them in \
         Notepad (right-click, Open with) and read them first. Each launcher asks for \
         administrator rights and runs harden.ps1 from this drive. harden.cmd and undo.cmd \
         also ask you to confirm; audit.cmd does not.",
    );
    r.heading("Honest caveats");
    for text in [
        "These settings are inspired by common security baselines. They are a sensible \
         starting point, not a compliance claim, certification or guarantee.",
        "The PowerShell script was never executed by its authors on a real Windows PC. Try it \
         on a spare PC or in a virtual machine before you use it on a PC you depend on.",
        "Another antivirus program or Windows Tamper Protection can stop the Windows Defender \
         settings from being changed. The script then prints a [WARN] line.",
        "Nothing here selects a disk, partitions or erases anything, and nothing creates an \
         account or sets a password.",
        "This drive is not protected or authenticated in any way: whatever is on it runs \
         with administrator rights when you use a launcher. Keep it with you.",
    ] {
        r.item(text);
    }
    let mut text = r.out.join("\r\n");
    text.push_str("\r\n");
    text.into_bytes()
}

/// `(label, files)` of the Windows seed drive from the bytes of harden.ps1 and the two lists the README quotes (see
/// `windows_seed_readme_from`). `hardening_files_seed` calls it with the real ones.
pub fn windows_seed_files_from(
    ps1: Vec<u8>,
    applied: &[String],
    not_changed: &[(&str, &str, &str)],
) -> Result<(String, Files)> {
    if ps1.iter().all(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)) {
        return Err(Error::value("The Windows hardening script is empty"));
    }
    let mut files = Files::new();
    for l in SEED_WINDOWS_LAUNCHERS {
        files.insert(l.name.to_string(), windows_seed_launcher(l.name, l.mode, l.confirm, l.banner));
    }
    files.insert("harden.ps1".to_string(), ps1);
    files.insert("README.txt".to_string(), windows_seed_readme_from(applied, not_changed));
    Ok((SEED_WINDOWS_LABEL.to_string(), files))
}

/// `_windows_seed_files(profile)`: the five files of the Windows seed drive.
fn windows_seed_files(profile: Hardening) -> Result<(String, Files)> {
    let ps1 = windows_hardening_ps1(profile)?;
    let applied = describe_hardening_windows_applied(profile);
    windows_seed_files_from(ps1, &applied, WINDOWS_HARDENING_NOT_CHANGED)
}

/// `(FAT32 volume label, {relative path: bytes})` of the seed drive for `target`.
///
/// `profile` is `Hardening::Baseline` (`Hardening::None` has no files and is `Error::Value`). The files never choose a
/// disk and never contain a password, hash or key; harden-linux.sh is exactly `linux_hardening_script(profile)`.
/// `SeedTarget::Windows` is the set of the Windows seed drive (harden.cmd, audit.cmd, undo.cmd, harden.ps1,
/// README.txt).
pub fn hardening_files_seed(target: SeedTarget, profile: Hardening) -> Result<(String, Files)> {
    seed_check_args(profile)?;
    if target == SeedTarget::Windows {
        return windows_seed_files(profile);
    }
    let text = linux_hardening_script(profile)?;
    linux_seed_files_from(target, text)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- textwrap (vectors computed with Python's textwrap.wrap(.., break_on_hyphens=False, break_long_words=False))
    fn wrapped(text: &str, width: usize, first: &str, rest: &str) -> Vec<String> {
        wrap_text(text, width, first, rest)
    }

    #[test]
    fn wrap_text_matches_python_textwrap() {
        assert_eq!(
            wrapped("The quick brown fox jumps over the lazy dog", 15, "- ", "  "),
            ["- The quick", "  brown fox", "  jumps over", "  the lazy dog"]
        );
        // a word longer than the line goes alone on its line and is never broken
        assert_eq!(wrapped("aaaaaaaaaaaaaaaaaaaaaaaa bb cc", 10, "", ""), ["aaaaaaaaaaaaaaaaaaaaaaaa", "bb cc"]);
        assert_eq!(wrapped(&"x".repeat(30), 10, "1. ", "   "), [format!("1. {}", "x".repeat(30))]);
        // runs of spaces inside a line are kept
        assert_eq!(
            wrapped("one  two   three four five six seven", 12, "> ", "  "),
            ["> one  two", "  three four", "  five six", "  seven"]
        );
        // leading whitespace survives on the first line only; trailing whitespace never
        assert_eq!(
            wrapped("  leading spaces then words that wrap around the line end", 20, "", "    "),
            ["  leading spaces", "    then words that", "    wrap around the", "    line end"]
        );
        assert_eq!(wrapped("trailing space here ", 11, "", ""), ["trailing", "space here"]);
        // hyphens are not break points
        assert_eq!(
            wrapped("a-b-c-d-e-f-g-h-i-j hyphenated-words-stay-together ok", 12, "", ""),
            ["a-b-c-d-e-f-g-h-i-j", "hyphenated-words-stay-together", "ok"]
        );
        assert!(wrapped("", 10, "", "").is_empty());
        assert_eq!(
            wrapped(&"word ".repeat(8), 10, "", "  "),
            ["word word", "  word", "  word", "  word", "  word", "  word", "  word"]
        );
        assert_eq!(wrapped("tab\tseparated\tcolumns here", 12, "", ""), ["tab", "separated", "columns here"]);
        assert_eq!(wrapped("a b", 3, "- ", "  "), ["- a", "  b"]);
    }

    #[test]
    fn base64_matches_the_standard_alphabet() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_encode(&[0xfb, 0xff, 0xfe]), "+//+");
        assert_eq!(seed_b64_lines(b"foobarfoobar", 8), ["Zm9vYmFy", "Zm9vYmFy"]);
        assert!(seed_b64_lines(b"", 76).is_empty());
    }

    // ---- goldens: byte-for-byte what the Python generators wrote (tests/golden/seed-*)
    type Golden = &'static [(&'static str, &'static [u8])];
    const UBUNTU: Golden = &[
        ("user-data", include_bytes!("../tests/golden/seed-ubuntu/user-data")),
        ("meta-data", include_bytes!("../tests/golden/seed-ubuntu/meta-data")),
        ("harden-linux.sh", include_bytes!("../tests/golden/seed-ubuntu/harden-linux.sh")),
        ("README.txt", include_bytes!("../tests/golden/seed-ubuntu/README.txt")),
    ];
    const FEDORA: Golden = &[
        ("ks.cfg", include_bytes!("../tests/golden/seed-fedora/ks.cfg")),
        ("harden-linux.sh", include_bytes!("../tests/golden/seed-fedora/harden-linux.sh")),
        ("README.txt", include_bytes!("../tests/golden/seed-fedora/README.txt")),
    ];
    const DEBIAN: Golden = &[
        ("preseed.cfg", include_bytes!("../tests/golden/seed-debian/preseed.cfg")),
        ("harden-linux.sh", include_bytes!("../tests/golden/seed-debian/harden-linux.sh")),
        ("README.txt", include_bytes!("../tests/golden/seed-debian/README.txt")),
    ];
    const WINDOWS: Golden = &[
        ("harden.cmd", include_bytes!("../tests/golden/seed-windows/harden.cmd")),
        ("audit.cmd", include_bytes!("../tests/golden/seed-windows/audit.cmd")),
        ("undo.cmd", include_bytes!("../tests/golden/seed-windows/undo.cmd")),
        ("harden.ps1", include_bytes!("../tests/golden/seed-windows/harden.ps1")),
        ("README.txt", include_bytes!("../tests/golden/seed-windows/README.txt")),
    ];
    const WINDOWS_PS1: &[u8] = include_bytes!("../tests/golden/windows/harden.ps1");
    const WINDOWS_DESCRIBE: &str = include_str!("../tests/golden/windows_describe.json");

    fn check(target: SeedTarget, golden: Golden, label: &str, got: (String, Files)) {
        let (got_label, files) = got;
        assert_eq!(got_label, label, "{target}");
        let names: Vec<&str> = files.keys().map(String::as_str).collect();
        let want: Vec<&str> = golden.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, want, "{target}: file names and their order");
        for (name, bytes) in golden {
            assert!(files[*name] == *bytes, "{target}/{name} differs from the golden");
        }
    }

    #[test]
    fn linux_seeds_are_the_golden_files() {
        let got = hardening_files_seed(SeedTarget::Ubuntu, Hardening::Baseline).unwrap();
        check(SeedTarget::Ubuntu, UBUNTU, "CIDATA", got);
        let got = hardening_files_seed(SeedTarget::Fedora, Hardening::Baseline).unwrap();
        check(SeedTarget::Fedora, FEDORA, "OEMDRV", got);
        let got = hardening_files_seed(SeedTarget::Debian, Hardening::Baseline).unwrap();
        check(SeedTarget::Debian, DEBIAN, "EPMA-SEED", got);
    }

    #[test]
    fn golden_labels_match_the_label_files() {
        for (target, label) in [
            (SeedTarget::Ubuntu, include_str!("../tests/golden/seed-ubuntu/LABEL")),
            (SeedTarget::Fedora, include_str!("../tests/golden/seed-fedora/LABEL")),
            (SeedTarget::Debian, include_str!("../tests/golden/seed-debian/LABEL")),
            (SeedTarget::Windows, include_str!("../tests/golden/seed-windows/LABEL")),
        ] {
            assert_eq!(seed_label(target), label);
        }
    }

    /// The rows of `WINDOWS_HARDENING_NOT_CHANGED` as the Python has them (A6's module owns the real constant).
    const NOT_CHANGED: &[(&str, &str, &str)] = &[
        (
            "bitlocker",
            "BitLocker is not turned on automatically",
            "It needs a TPM, a choice of where the recovery key goes and the owner's consent; a wrong default can lock someone out of their own data.",
        ),
        (
            "ntlm",
            "NTLM authentication levels are left as they are",
            "Stricter levels can break access to older file shares, printers and NAS devices without any warning.",
        ),
        (
            "accounts_disks",
            "Accounts, passwords, disks, language, licence and product key",
            "Windows Setup stays fully interactive; the hardening script never touches them.",
        ),
        (
            "device_guard",
            "Memory Integrity (HVCI), Credential Guard and Exploit Protection are only reported, never turned on",
            "They depend on the hardware, drivers and apps of each PC and can stop a PC from starting or a program from running; Audit mode shows their state so the owner can decide.",
        ),
    ];

    fn applied_lines() -> Vec<String> {
        let v: serde_json::Value = serde_json::from_str(WINDOWS_DESCRIBE).unwrap();
        v["applied"].as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect()
    }

    #[test]
    fn windows_seed_is_the_golden_files() {
        let got = windows_seed_files_from(WINDOWS_PS1.to_vec(), &applied_lines(), NOT_CHANGED).unwrap();
        check(SeedTarget::Windows, WINDOWS, "EPMA-SEED", got);
    }

    #[test]
    fn windows_launchers_are_the_golden_files() {
        for l in SEED_WINDOWS_LAUNCHERS {
            let golden = WINDOWS.iter().find(|(n, _)| *n == l.name).unwrap().1;
            assert!(windows_seed_launcher(l.name, l.mode, l.confirm, l.banner) == golden, "{}", l.name);
        }
    }

    #[test]
    fn launcher_banners_that_name_the_log_start_with_the_shown_path() {
        let shown: Vec<&str> = SEED_WINDOWS_LAUNCHERS
            .iter()
            .flat_map(|l| l.banner.iter().copied())
            .filter(|b| b.starts_with("C:"))
            .collect();
        assert_eq!(shown.len(), 2);
        assert!(shown.iter().all(|b| b.starts_with(SEED_WINDOWS_LOG_SHOWN)));
    }

    #[test]
    fn none_profile_has_no_seed_files() {
        for target in SeedTarget::ALL {
            let err = hardening_files_seed(target, Hardening::None).unwrap_err();
            assert!(matches!(err, Error::Value(_)));
            assert_eq!(err.to_string(), "The 'none' hardening profile has no seed files");
        }
    }

    #[test]
    fn empty_scripts_are_refused() {
        for bad in ["", "  \n", "\t\r\n"] {
            for target in [SeedTarget::Ubuntu, SeedTarget::Fedora, SeedTarget::Debian] {
                let err = linux_seed_files_from(target, bad).unwrap_err();
                assert_eq!(err.to_string(), "The hardening script is empty", "{target} {bad:?}");
            }
        }
        for bad in [&b""[..], b"  \r\n"] {
            let err = windows_seed_files_from(bad.to_vec(), &[], &[]).unwrap_err();
            assert_eq!(err.to_string(), "The Windows hardening script is empty");
        }
    }
}
