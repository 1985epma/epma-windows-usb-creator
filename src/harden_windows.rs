//! The Windows 11 hardening content: harden.ps1 (apply / audit / undo), SetupComplete.cmd, the settings tables and the
//! descriptions shown to the user. OWNER: A6. Port of win11_usb_creator.py lines 5944-7933. Output is byte-identical to
//! the Python (goldens in tests/golden/windows*/).
//!
//! Everything here is PURE: text in, bytes out. Nothing touches a drive and nothing is executed on this computer. The
//! files are plain ASCII so no encoding surprise can reach the target PC.
//!
//! Honest naming: these are "recommended settings inspired by common baselines", NOT a compliance profile.
//!
//! Layout of the data: the static PowerShell (helpers, the per-setting blocks that no table can express, the start
//! and the end of the script) lives in `assets/windows/*.ps1` and is embedded with `include_str!`; the blocks that are
//! only DWORD registry values or attack surface rule groups are generated here (`ps_reg_code`, `ps_asr_audit_code`),
//! and every table (settings, rule ids, audit subcategories, registry values...) is one Rust constant used by the
//! generator and by the `describe_*` functions alike.

use crate::types::{Error, Files, Hardening, Result};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

/// Embed a PowerShell asset of `assets/windows/`.
macro_rules! asset {
    ($path:literal) => {
        include_str!(concat!("../assets/windows/", $path))
    };
}

// The pieces of the path and of the state file are macros so that the composed constants below are built from ONE
// spelling of each (a `const` cannot `concat!` other consts).
macro_rules! scripts_dir {
    () => {
        "sources/$OEM$/$$/Setup/Scripts"
    };
}
macro_rules! state_dir {
    () => {
        "EPMA"
    };
}
macro_rules! state_file {
    () => {
        "hardening-state.json"
    };
}

/// Where SetupComplete.cmd and harden.ps1 write.
pub const WINDOWS_HARDENING_LOG: &str = "%windir%\\Temp\\epma-hardening.log";
/// `$$` is copied to %windir% by Windows Setup.
pub const WINDOWS_HARDENING_SCRIPTS_DIR: &str = scripts_dir!();
pub const WINDOWS_HARDENING_CMD: &str = concat!(scripts_dir!(), "/SetupComplete.cmd");
pub const WINDOWS_HARDENING_PS1: &str = concat!(scripts_dir!(), "/harden.ps1");
// hardening2 (WIN-SCRIPT): harden.ps1 has three modes and keeps the first-seen value of every setting it changes in a
// state file, so that -Mode Undo can put it back. The folder is created on the first change and limited to
// Administrators and SYSTEM by the script itself.
/// `-Mode` values; Apply is the default (what Setup runs).
pub const WINDOWS_HARDENING_MODES: [&str; 3] = ["Apply", "Audit", "Undo"];
pub const WINDOWS_HARDENING_STATE_DIR: &str = state_dir!();
pub const WINDOWS_HARDENING_STATE_FILE: &str = state_file!();
pub const WINDOWS_HARDENING_STATE: &str = concat!("%ProgramData%\\", state_dir!(), "\\", state_file!());
/// Settings that only an explicit -DisableLegacyNetwork applies (never SetupComplete.cmd, never by default).
pub const WINDOWS_HARDENING_OPTIN: [&str; 2] = ["netbios", "wpad"];

/// One row per setting: (id, short text, risk note). The id is also the marker in harden.ps1 ("# setting: <id>");
/// the script header and `describe_hardening_windows` are generated from these rows, and a test checks that every
/// row has a code block and every code block has a row. The baseline is kept SMALL: anything that commonly breaks
/// home or office use is left out (see `WINDOWS_HARDENING_NOT_CHANGED`).
pub const WINDOWS_HARDENING_SETTINGS: &[(&str, &str, &str)] = &[
    (
        "smb1",
        "Turn off SMBv1 (obsolete file-sharing protocol)",
        "Very old NAS boxes, scanners or Windows XP-era PCs that only speak SMBv1 can no longer \
        connect.",
    ),
    (
        "llmnr",
        "Turn off LLMNR name lookups",
        "Single-word names that only resolve through LLMNR stop resolving on networks without \
        proper DNS.",
    ),
    (
        "autorun",
        "Turn off AutoRun and AutoPlay on every drive type",
        "Inserted USB sticks and discs no longer start installers or show the AutoPlay prompt, \
        and phones and cameras no longer show the import-photos prompt; open them from File \
        Explorer.",
    ),
    (
        "firewall",
        "Windows Firewall on for all network profiles, inbound blocked unless a rule allows it",
        "A program that must accept incoming connections (game server, file sharing, remote \
        tools) needs an allow rule. The script runs once at the end of Setup and does not \
        retry; the log says [WARN] if the firewall settings are not in effect.",
    ),
    (
        "defender_cloud",
        "Defender: block potentially unwanted apps and turn cloud protection on",
        "Some bundled freeware may be flagged, and cloud protection sends file metadata to \
        Microsoft. The script runs once at the end of Setup and does not retry; Tamper \
        Protection, another antivirus or a Defender that is not ready yet can stop the change, \
        and the log then says [WARN].",
    ),
    (
        "asr_lsass",
        "Defender attack surface rule in Block mode: no credential stealing from LSASS",
        "Rarely, security or backup tools that read LSASS memory are blocked and Defender shows \
        a notification. The script runs once at the end of Setup and does not retry; the log \
        says [WARN] if the rule is not in effect.",
    ),
    (
        "asr_audit",
        "Defender attack surface rules in Audit mode (log only): email executable content, \
        Office child processes, obfuscated scripts, script-launched downloads",
        "Audit mode only writes events and blocks nothing. Review the Defender event log before \
        switching any rule to Block. The script runs once at the end of Setup and does not \
        retry; the log says [WARN] for a rule that is not in effect.",
    ),
    (
        "asr_audit_extra",
        "Defender attack surface rules in Audit mode (log only), more: abuse of exploited \
        vulnerable signed drivers, process creation from PsExec and WMI commands, untrusted \
        processes that run from USB drives",
        "Audit mode only writes events and blocks nothing; running programs from a USB stick or \
        with remote-management tools adds events. Review the Defender event log before \
        switching any rule to Block. The script runs once at the end of Setup and does not \
        retry; the log says [WARN] for a rule that is not in effect.",
    ),
    (
        "wdigest",
        "Do not keep plain-text WDigest credentials in memory",
        "Only legacy digest authentication against very old web servers is affected.",
    ),
    (
        "ps_logging",
        "PowerShell script block logging",
        "Adds events to the PowerShell log; secrets typed inside a script would be logged as well.",
    ),
    (
        "ps2",
        "Disable the PowerShell 2.0 optional feature",
        "Very old scripts or tools that insist on running with -Version 2 stop working.",
    ),
    (
        "remote_assist",
        "Turn off Remote Assistance invitations",
        "Old-style Remote Assistance invitations stop working; Quick Assist and Remote Desktop \
        are not changed.",
    ),
    (
        "audit",
        "Advanced audit policy: sign-ins, account lockouts, account and group changes, \
        audit-policy changes, process creation; Security log size raised to 128 MiB",
        "The Security event log fills much faster (process creation and sign-ins are frequent \
        events), so its maximum size is raised to 128 MiB (never lowered). Retention is still \
        limited: on a busy PC the oldest events can be overwritten within days, so export the \
        log if you need to keep it.",
    ),
    (
        "uac",
        "Keep User Account Control switched on",
        "Only acts when UAC was switched off; takes effect after the next restart.",
    ),
    (
        "netbios",
        "Opt-in (-DisableLegacyNetwork, never applied by default): turn off NetBIOS over TCP/IP \
        on all network adapters",
        "Looking up or browsing machines by their NetBIOS name stops working on the adapters \
        that exist now (very old file shares, printers or NAS boxes reached by a short name). \
        It takes effect when the adapter reconnects or after a restart; adapters added later \
        keep their default.",
    ),
    (
        "wpad",
        "Opt-in (-DisableLegacyNetwork, never applied by default): turn off WPAD proxy \
        auto-discovery for WinHTTP",
        "A network that hands out its proxy only through WPAD (some offices and schools) no \
        longer gives it to Windows services and apps that use WinHTTP, so they can lose \
        internet access until a proxy is set by hand. The WinHTTP auto-proxy service itself is \
        left running.",
    ),
];

/// Deliberately NOT done, with the reason: (id, text, why). Shown in the script header and available to the
/// README / help text.
pub const WINDOWS_HARDENING_NOT_CHANGED: &[(&str, &str, &str)] = &[
    (
        "bitlocker",
        "BitLocker is not turned on automatically",
        "It needs a TPM, a choice of where the recovery key goes and the owner's consent; a \
        wrong default can lock someone out of their own data.",
    ),
    (
        "ntlm",
        "NTLM authentication levels are left as they are",
        "Stricter levels can break access to older file shares, printers and NAS devices without \
        any warning.",
    ),
    (
        "accounts_disks",
        "Accounts, passwords, disks, language, licence and product key",
        "Windows Setup stays fully interactive; the hardening script never touches them.",
    ),
    (
        "device_guard",
        "Memory Integrity (HVCI), Credential Guard and Exploit Protection are only reported, \
        never turned on",
        "They depend on the hardware, drivers and apps of each PC and can stop a PC from \
        starting or a program from running; Audit mode shows their state so the owner can \
        decide.",
    ),
];

/// `_windows_hardening_check(profile)`: true when there is something to add (anything but `Hardening::None`). The
/// Python also refused an unknown profile name; the enum makes that impossible.
fn windows_hardening_check(profile: Hardening) -> bool {
    profile != Hardening::None
}

/// `describe_hardening_windows(profile)`: human-readable lines (English, ASCII) saying what the Windows hardening
/// changes and what it risks. One line per setting: "<text> -- risk: <note>". Empty for `Hardening::None`.
pub fn describe_hardening_windows(profile: Hardening) -> Vec<String> {
    if !windows_hardening_check(profile) {
        return Vec::new();
    }
    WINDOWS_HARDENING_SETTINGS.iter().map(|(_sid, text, risk)| format!("{text} -- risk: {risk}")).collect()
}

/// `describe_hardening_windows_applied(profile)`: the lines of `describe_hardening_windows` for what the scripts apply
/// BY DEFAULT: the opt-in settings (`-DisableLegacyNetwork`, never used by SetupComplete.cmd or the launchers) are
/// left out.
pub fn describe_hardening_windows_applied(profile: Hardening) -> Vec<String> {
    if !windows_hardening_check(profile) {
        return Vec::new();
    }
    WINDOWS_HARDENING_SETTINGS
        .iter()
        .filter(|(sid, _text, _risk)| !WINDOWS_HARDENING_OPTIN.contains(sid))
        .map(|(_sid, text, risk)| format!("{text} -- risk: {risk}"))
        .collect()
}

/// `_windows_setupcomplete_cmd(profile, ps1)`: SetupComplete.cmd (ASCII, CRLF). The SHA-256 of harden.ps1
/// (`windows_hardening_ps1(profile)`, or the bytes given as `ps1`) is embedded and checked with certutil before the
/// script runs, so a harden.ps1 that does not match this file is never run. That is all the check does: whoever can
/// change both files (or the drive that holds them) is not stopped by it.
pub(crate) fn windows_setupcomplete_cmd(profile: Hardening, ps1: Option<&[u8]>) -> Result<Vec<u8>> {
    let generated;
    let ps1 = match ps1 {
        Some(bytes) => bytes,
        None => {
            generated = windows_hardening_ps1(profile)?;
            &generated[..]
        }
    };
    // `bytes.strip()` in Python: ASCII whitespace including the vertical tab.
    if ps1.iter().all(|b| b.is_ascii_whitespace() || *b == 0x0b) {
        return Err(Error::value("The Windows hardening script is empty"));
    }
    let digest: String = Sha256::digest(ps1).iter().map(|b| format!("{b:02x}")).collect();
    // SetupComplete.cmd runs once as SYSTEM at the very end of Setup (before the first sign-in), from
    // %windir%\Setup\Scripts. It must never make Setup fail, so every path ends in `exit /b 0`. No parenthesised
    // blocks on purpose (%errorlevel% inside one is expanded too early); the only parentheses are the `for /f` command.
    // `certutil -hashfile` prints a header line, the hash (older Windows versions put a space between the bytes) and a
    // status line: line 2 is read, the spaces are dropped and the comparison ignores case.
    let lines: Vec<String> = vec![
        "@echo off".into(),
        "rem EPMA USB CREATOR - optional hardened setup. Checks harden.ps1, runs it once, logs, never fails the setup."
            .into(),
        format!("set \"EPMA_LOG={WINDOWS_HARDENING_LOG}\""),
        format!("set \"EPMA_WANT={digest}\""),
        "set \"EPMA_GOT=\"".into(),
        "echo [%date% %time%] SetupComplete.cmd: starting >> \"%EPMA_LOG%\"".into(),
        "if not exist \"%~dp0harden.ps1\" goto missing".into(),
        "for /f \"skip=1 delims=\" %%H in ('%SystemRoot%\\System32\\certutil.exe -hashfile \"%~dp0harden.ps1\" SHA256 2^>nul') \
         do if not defined EPMA_GOT set \"EPMA_GOT=%%H\""
            .into(),
        "if not defined EPMA_GOT goto nohash".into(),
        "set \"EPMA_GOT=%EPMA_GOT: =%\"".into(),
        "if /i not \"%EPMA_GOT%\"==\"%EPMA_WANT%\" goto mismatch".into(),
        "echo [%date% %time%] SetupComplete.cmd: harden.ps1 SHA-256 matches >> \"%EPMA_LOG%\"".into(),
        "%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -ExecutionPolicy Bypass -File \
         \"%~dp0harden.ps1\" >> \"%EPMA_LOG%\" 2>&1"
            .into(),
        "echo [%date% %time%] SetupComplete.cmd: harden.ps1 exit code %errorlevel% (ignored) >> \"%EPMA_LOG%\"".into(),
        "goto done".into(),
        ":missing".into(),
        "echo [SKIP] harden.ps1 not found next to SetupComplete.cmd >> \"%EPMA_LOG%\"".into(),
        "goto done".into(),
        ":nohash".into(),
        "echo [SKIP] could not compute the SHA-256 of harden.ps1 (certutil failed): harden.ps1 was NOT run >> \
         \"%EPMA_LOG%\""
            .into(),
        "goto done".into(),
        ":mismatch".into(),
        "echo [SKIP] harden.ps1 does not match the SHA-256 recorded in SetupComplete.cmd: harden.ps1 was NOT run >> \
         \"%EPMA_LOG%\""
            .into(),
        "echo [SKIP] expected %EPMA_WANT% but found %EPMA_GOT% >> \"%EPMA_LOG%\"".into(),
        ":done".into(),
        "exit /b 0".into(),
    ];
    let mut text = lines.join("\r\n");
    text.push_str("\r\n");
    Ok(text.into_bytes())
}

// ===== hardening2: windows script (harden.ps1 with -Mode Apply|Audit|Undo) =====
// The script has three modes (-Mode Apply|Audit|Undo). Every setting has ONE code block per mode, kept in three
// tables with the same keys in the same order: WINDOWS_PS_CODE (Apply), WINDOWS_PS_AUDIT (Audit, read-only) and
// WINDOWS_PS_UNDO (Undo, puts back what Apply recorded). Each block runs inside its own try/catch and logs one line
// (or, for a few multi-part settings, one line per part): Apply and Undo use [OK]/[SKIP]/[WARN]/[FAIL] (Undo:
// [OK]/[SKIP]/[WARN]), Audit uses [OK] in effect / [DIFF] not in effect / [N/A]. `@WHAT@` is replaced by the
// setting's text from WINDOWS_HARDENING_SETTINGS. Only PowerShell 5.1 syntax; no network access, no downloads.
//
// NOTHING in this file was ever executed: pwsh is not available where it was written, so the PowerShell is checked
// structurally by the tests and nothing else. Test it on a throw-away Windows 11 first (Audit mode is a safe way to
// start: it changes nothing).

/// Pairs (what Apply calls to record + change, what Undo calls to put it back). A test checks that every setting
/// whose Apply block uses the first name has the second name in its Undo block.
pub const WINDOWS_HARDENING_STATE_PAIRS: &[(&str, &str)] = &[
    ("Set-RegDword", "Restore-RegValue"),
    ("Set-AsrRule", "Restore-AsrRule"),
    ("Set-AuditSubcategory", "Restore-AuditSubcategory"),
    ("Save-FirewallState", "Restore-FirewallState"),
    ("Save-DefenderValue", "Restore-DefenderValue"),
    ("Save-FeatureState", "Restore-FeatureState"),
    ("Save-EventLogState", "Restore-EventLogState"),
];

// Attack surface reduction rules by GUID (Microsoft documentation names in the comments). Only rules whose GUID is
// certain are listed; the three of the second group are only ever set to Audit mode.
/// Block credential stealing from LSASS (Block mode).
pub const WINDOWS_ASR_LSASS: &str = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2";
pub const WINDOWS_ASR_AUDIT_RULES: &[&str] = &[
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", // block executable content from email client and webmail
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a", // block all Office applications from creating child processes
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc", // block execution of potentially obfuscated scripts
    "d3e037e1-3eb8-44c8-a917-57927947596d", // block JavaScript or VBScript from launching downloaded executable content
];
pub const WINDOWS_ASR_AUDIT_EXTRA_RULES: &[&str] = &[
    "56a863a9-875e-4185-98a7-b882c64b5ce5", // block abuse of exploited vulnerable signed drivers
    "d1e49aac-8f56-4280-b9ba-993a6d77406c", // block process creations originating from PSExec and WMI commands
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", // block untrusted and unsigned processes that run from USB
];

/// Advanced audit policy subcategories, addressed by GUID because their names are translated on non-English
/// Windows. The GUIDs are not checked against a live system here: if auditpol rejects one, a FAIL line names it.
/// List the valid ones with: `auditpol /list /subcategory:* /v`
/// (guid, name, success wanted, failure wanted): Logon, Account Lockout, User Account Management, Security Group
/// Management, Audit Policy Change (success and failure); Process Creation (success only, no command-line capture).
pub const WINDOWS_AUDIT_SUBCATEGORIES: &[(&str, &str, bool, bool)] = &[
    ("{0CCE9215-69AE-11D9-BED3-505054503030}", "Logon", true, true),
    ("{0CCE9217-69AE-11D9-BED3-505054503030}", "Account Lockout", true, true),
    ("{0CCE9235-69AE-11D9-BED3-505054503030}", "User Account Management", true, true),
    ("{0CCE9237-69AE-11D9-BED3-505054503030}", "Security Group Management", true, true),
    ("{0CCE922F-69AE-11D9-BED3-505054503030}", "Audit Policy Change", true, true),
    ("{0CCE922B-69AE-11D9-BED3-505054503030}", "Process Creation", true, false),
];

// Registry keys of the settings that are only DWORD values. The same spelling feeds the generated blocks and
// WINDOWS_REG_VALUES (the static blocks of assets/windows/ carry their own copy; a test compares both).
const KEY_LANMAN_SERVER: &str = r"HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
const KEY_DNS_CLIENT: &str = r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";
const KEY_EXPLORER_POLICIES: &str = r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
const KEY_WDIGEST: &str = r"HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest";
const KEY_SCRIPT_BLOCK_LOGGING: &str = r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging";
const KEY_REMOTE_ASSISTANCE: &str = r"HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance";
const KEY_SYSTEM_POLICIES: &str = r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
const KEY_WINHTTP: &str = r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp";

/// The ONLY registry values the script writes or puts back: (key, value name, lowest, highest DWORD accepted when
/// Undo puts an earlier value back). The state file is a source of VALUES only: Undo looks every setting up in this
/// table (rendered into the script as `$script:KnownReg`) and ignores any path or name written in the file. The
/// per-adapter NetBIOS values are the one family that is matched by pattern instead (`WINDOWS_NETBT_KEY_REGEX`, value
/// name NetbiosOptions, 0 to 2). A test checks that every Set-RegDword / Restore-RegValue call is in here.
pub const WINDOWS_REG_VALUES: &[(&str, &str, i32, i32)] = &[
    (KEY_LANMAN_SERVER, "SMB1", 0, 1),
    (KEY_DNS_CLIENT, "EnableMulticast", 0, 1),
    (KEY_EXPLORER_POLICIES, "NoDriveTypeAutoRun", -1, 255),
    (KEY_EXPLORER_POLICIES, "NoAutorun", 0, 1),
    (KEY_WDIGEST, "UseLogonCredential", 0, 1),
    (KEY_SCRIPT_BLOCK_LOGGING, "EnableScriptBlockLogging", 0, 1),
    (KEY_REMOTE_ASSISTANCE, "fAllowToGetHelp", 0, 1),
    (KEY_REMOTE_ASSISTANCE, "fAllowFullControl", 0, 1),
    (KEY_SYSTEM_POLICIES, "EnableLUA", 0, 1),
    (KEY_WINHTTP, "DisableWpad", 0, 1),
];
pub const WINDOWS_NETBT_KEY_REGEX: &str =
    r"^HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\Tcpip_\{[0-9A-Fa-f-]{36}\}$";
pub const WINDOWS_OPTIONAL_FEATURES: &[&str] =
    &["SMB1Protocol", "MicrosoftWindowsPowerShellV2Root", "MicrosoftWindowsPowerShellV2"];
pub const WINDOWS_DEFENDER_PREFERENCES: &[&str] = &["PUAProtection", "MAPSReporting"];

/// `_ps_known_tables()`: the built-in tables that Undo trusts instead of the state file, as text for the script
/// helpers: (placeholder, text) in the order the placeholders are substituted.
pub(crate) fn ps_known_tables() -> Vec<(&'static str, String)> {
    let reg = format!(
        "@{{\n{}\n}}",
        WINDOWS_REG_VALUES
            .iter()
            .map(|(p, n, lo, hi)| format!("    '{p}|{n}' = @({lo}, {hi})"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    let asr = std::iter::once(WINDOWS_ASR_LSASS)
        .chain(WINDOWS_ASR_AUDIT_RULES.iter().copied())
        .chain(WINDOWS_ASR_AUDIT_EXTRA_RULES.iter().copied())
        .map(|g| format!("    '{g}'"))
        .collect::<Vec<_>>()
        .join(",\n");
    let audit = WINDOWS_AUDIT_SUBCATEGORIES.iter().map(|(g, ..)| format!("    '{g}'")).collect::<Vec<_>>().join(",\n");
    let quoted = |items: &[&str]| items.iter().map(|f| format!("'{f}'")).collect::<Vec<_>>().join(", ");
    vec![
        ("@KNOWN_REG@", reg),
        ("@KNOWN_ASR@", format!("@(\n{asr}\n)")),
        ("@KNOWN_AUDIT@", format!("@(\n{audit}\n)")),
        ("@KNOWN_FEATURES@", format!("@({})", quoted(WINDOWS_OPTIONAL_FEATURES))),
        ("@KNOWN_MP@", format!("@({})", quoted(WINDOWS_DEFENDER_PREFERENCES))),
        ("@NETBT_REGEX@", WINDOWS_NETBT_KEY_REGEX.to_string()),
    ]
}

fn ps_bool(value: bool) -> &'static str {
    if value {
        "$true"
    } else {
        "$false"
    }
}

/// The (Apply, Audit, Undo) PowerShell of one setting (`(apply, audit, undo)` tuples of the Python generators).
pub(crate) struct PsBlocks {
    pub apply: String,
    pub audit: String,
    pub undo: String,
}

/// `_ps_reg_code(rows, optin, absent_ok)`: (apply, audit, undo) PowerShell for a setting that is only DWORD registry
/// values.
///
/// rows = (path, name, wanted int). `optin`: Apply does nothing without -DisableLegacyNetwork and Audit does not
/// count a missing setting. `absent_ok`: a value that does not exist counts as in effect in Audit (the Windows
/// default already is the wanted state).
fn ps_reg_code(rows: &[(&str, &str, i32)], optin: bool, absent_ok: bool) -> PsBlocks {
    let mut apply_l: Vec<String> = vec!["try {".into()];
    let mut names: Vec<String> = Vec::new();
    for (i, (path, name, value)) in rows.iter().enumerate() {
        let n = i + 1;
        apply_l.push(format!("    $c{n} = Set-RegDword -Path '{path}' -Name '{name}' -Value {value}"));
        names.push(format!("$c{n}"));
    }
    apply_l.push(format!("    Write-Result 'OK' '@WHAT@' (Get-ChangeText ({}))", names.join(" -or ")));
    apply_l.extend(
        ["} catch {", "    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message", "}"].iter().map(|s| s.to_string()),
    );

    let mut audit_l: Vec<String> = vec!["try {".into(), "    $good = @()".into(), "    $bad = @()".into()];
    for (path, name, value) in rows {
        audit_l.push(format!("    $cur = Get-RegDword -Path '{path}' -Name '{name}'"));
        if absent_ok {
            audit_l.push(format!(
                "    if ($null -eq $cur) {{ $good += '{name} is not set (the Windows default is already {value})' }}"
            ));
            audit_l.push(format!("    elseif ([int]$cur -eq {value}) {{ $good += '{name} is {value}' }}"));
        } else {
            audit_l.push(format!(
                "    if (($null -ne $cur) -and ([int]$cur -eq {value})) {{ $good += '{name} is {value}' }}"
            ));
        }
        audit_l.push(format!("    else {{ $bad += '{name} is ' + (Format-Value $cur) + ', wanted {value}' }}"));
    }
    let flag = if optin { " -OptIn $true" } else { "" };
    audit_l.extend(
        ["    if ($bad.Count -eq 0) {", "        Write-Audit 'OK' '@WHAT@' ($good -join '; ')", "    } else {"]
            .iter()
            .map(|s| s.to_string()),
    );
    audit_l.push(format!("        Write-Audit 'DIFF' '@WHAT@' ($bad -join '; '){flag}"));
    audit_l.extend(
        ["    }", "} catch {", "    Write-Audit 'NA' '@WHAT@' ('could not be checked: ' + $_.Exception.Message)", "}"]
            .iter()
            .map(|s| s.to_string()),
    );

    let mut undo_l: Vec<String> = vec!["try {".into(), "    $r = @()".into()];
    for (path, name, _value) in rows {
        undo_l.push(format!("    $r += Restore-RegValue -Path '{path}' -Name '{name}'"));
    }
    undo_l.extend(
        [
            "    Write-UndoSummary '@WHAT@' $r",
            "} catch {",
            "    Write-Result 'WARN' '@WHAT@ not put back' $_.Exception.Message",
            "}",
        ]
        .iter()
        .map(|s| s.to_string()),
    );

    if optin {
        // The body of the try block (the set lines and the OK line) moves one level in, inside the opt-in gate.
        let inner: Vec<String> = apply_l[1..apply_l.len() - 3].iter().map(|ln| format!("    {ln}")).collect();
        let mut gated: Vec<String> = vec![
            "try {".into(),
            "    if (-not $DisableLegacyNetwork) {".into(),
            "        Write-Result 'SKIP' '@WHAT@' 'opt-in, not requested (run with -DisableLegacyNetwork)'".into(),
            "    } else {".into(),
        ];
        gated.extend(inner);
        gated.extend(
            ["    }", "} catch {", "    Write-Result 'FAIL' '@WHAT@' $_.Exception.Message", "}"]
                .iter()
                .map(|s| s.to_string()),
        );
        apply_l = gated;
    }
    let join = |lines: &[String]| lines.join("\n") + "\n";
    PsBlocks { apply: join(&apply_l), audit: join(&audit_l), undo: join(&undo_l) }
}

/// `_ps_asr_audit_code(rules)`: (apply, audit, undo) for a group of attack surface rules that are only ever set to
/// Audit mode. The three blocks are assets with the rule ids at `@ASR_IDS@`.
fn ps_asr_audit_code(rules: &[&str]) -> PsBlocks {
    let ids = rules.iter().map(|r| format!("            '{r}'")).collect::<Vec<_>>().join(",\n");
    let ids_u = rules.iter().map(|r| format!("        '{r}'")).collect::<Vec<_>>().join(",\n");
    PsBlocks {
        apply: asset!("asr_group_apply.ps1").replace("@ASR_IDS@", &ids),
        audit: asset!("asr_group_audit.ps1").replace("@ASR_IDS@", &ids),
        undo: asset!("asr_group_undo.ps1").replace("@ASR_IDS@", &ids_u),
    }
}

/// `_ps_audit_items(indent)`: the audit subcategories as PowerShell array rows.
fn ps_audit_items(indent: usize) -> String {
    let pad = " ".repeat(indent);
    WINDOWS_AUDIT_SUBCATEGORIES
        .iter()
        .map(|(g, n, s, f)| format!("{pad}@('{g}', '{n}', {}, {})", ps_bool(*s), ps_bool(*f)))
        .collect::<Vec<_>>()
        .join(",\n")
}

static REG_LLMNR: LazyLock<PsBlocks> =
    LazyLock::new(|| ps_reg_code(&[(KEY_DNS_CLIENT, "EnableMulticast", 0)], false, false));
static REG_AUTORUN: LazyLock<PsBlocks> = LazyLock::new(|| {
    ps_reg_code(
        &[(KEY_EXPLORER_POLICIES, "NoDriveTypeAutoRun", 255), (KEY_EXPLORER_POLICIES, "NoAutorun", 1)],
        false,
        false,
    )
});
static REG_WDIGEST: LazyLock<PsBlocks> =
    LazyLock::new(|| ps_reg_code(&[(KEY_WDIGEST, "UseLogonCredential", 0)], false, true));
static REG_PSLOG: LazyLock<PsBlocks> =
    LazyLock::new(|| ps_reg_code(&[(KEY_SCRIPT_BLOCK_LOGGING, "EnableScriptBlockLogging", 1)], false, false));
static REG_REMOTE: LazyLock<PsBlocks> = LazyLock::new(|| {
    ps_reg_code(
        &[(KEY_REMOTE_ASSISTANCE, "fAllowToGetHelp", 0), (KEY_REMOTE_ASSISTANCE, "fAllowFullControl", 0)],
        false,
        false,
    )
});
// Only the WinHTTP DisableWpad value. The "WinHTTP Web Proxy Auto-Discovery" service (WinHttpAutoProxySvc) is left
// alone on purpose: stopping or disabling it breaks proxy handling for apps that need it. The per-user Internet
// Explorer "detect settings" switch lives under HKCU and belongs to each user, so a machine-wide script skips it.
static REG_WPAD: LazyLock<PsBlocks> = LazyLock::new(|| ps_reg_code(&[(KEY_WINHTTP, "DisableWpad", 1)], true, false));
static ASR_EXTRA: LazyLock<PsBlocks> = LazyLock::new(|| ps_asr_audit_code(WINDOWS_ASR_AUDIT_EXTRA_RULES));
static ASR_BASE: LazyLock<PsBlocks> = LazyLock::new(|| ps_asr_audit_code(WINDOWS_ASR_AUDIT_RULES));

/// The comma-separated GUIDs of the audit subcategories, as the Undo block lists them.
fn ps_audit_guids() -> String {
    WINDOWS_AUDIT_SUBCATEGORIES.iter().map(|(g, ..)| format!("        '{g}'")).collect::<Vec<_>>().join(",\n")
}

/// A table of PowerShell blocks: (setting id, code) in the order of `WINDOWS_HARDENING_SETTINGS`.
pub(crate) type PsTable = Vec<(&'static str, String)>;

/// `_WINDOWS_PS_CODE`: the Apply block of every setting.
pub(crate) static WINDOWS_PS_CODE: LazyLock<PsTable> = LazyLock::new(|| {
    vec![
        ("smb1", asset!("apply/smb1.ps1").to_string()),
        ("llmnr", REG_LLMNR.apply.clone()),
        ("autorun", REG_AUTORUN.apply.clone()),
        ("firewall", asset!("apply/firewall.ps1").to_string()),
        ("defender_cloud", asset!("apply/defender_cloud.ps1").to_string()),
        ("asr_lsass", asset!("apply/asr_lsass.ps1").replace("@LSASS@", WINDOWS_ASR_LSASS)),
        ("asr_audit", ASR_BASE.apply.clone()),
        ("asr_audit_extra", ASR_EXTRA.apply.clone()),
        ("wdigest", REG_WDIGEST.apply.clone()),
        ("ps_logging", REG_PSLOG.apply.clone()),
        ("ps2", asset!("apply/ps2.ps1").to_string()),
        ("remote_assist", REG_REMOTE.apply.clone()),
        ("audit", asset!("apply/audit.ps1").replace("@AUDIT_ITEMS@", &ps_audit_items(8))),
        ("uac", asset!("apply/uac.ps1").to_string()),
        ("netbios", asset!("apply/netbios.ps1").to_string()),
        ("wpad", REG_WPAD.apply.clone()),
    ]
});

/// `_WINDOWS_PS_AUDIT`: the Audit block (read-only) of every setting.
pub(crate) static WINDOWS_PS_AUDIT: LazyLock<PsTable> = LazyLock::new(|| {
    vec![
        ("smb1", asset!("audit/smb1.ps1").to_string()),
        ("llmnr", REG_LLMNR.audit.clone()),
        ("autorun", REG_AUTORUN.audit.clone()),
        ("firewall", asset!("audit/firewall.ps1").to_string()),
        ("defender_cloud", asset!("audit/defender_cloud.ps1").to_string()),
        ("asr_lsass", asset!("audit/asr_lsass.ps1").replace("@LSASS@", WINDOWS_ASR_LSASS)),
        ("asr_audit", ASR_BASE.audit.clone()),
        ("asr_audit_extra", ASR_EXTRA.audit.clone()),
        ("wdigest", REG_WDIGEST.audit.clone()),
        ("ps_logging", REG_PSLOG.audit.clone()),
        ("ps2", asset!("audit/ps2.ps1").to_string()),
        ("remote_assist", REG_REMOTE.audit.clone()),
        ("audit", asset!("audit/audit.ps1").replace("@AUDIT_ITEMS@", &ps_audit_items(8))),
        ("uac", asset!("audit/uac.ps1").to_string()),
        ("netbios", asset!("audit/netbios.ps1").to_string()),
        ("wpad", REG_WPAD.audit.clone()),
    ]
});

/// `_WINDOWS_PS_UNDO`: the Undo block of every setting.
pub(crate) static WINDOWS_PS_UNDO: LazyLock<PsTable> = LazyLock::new(|| {
    vec![
        ("smb1", asset!("undo/smb1.ps1").to_string()),
        ("llmnr", REG_LLMNR.undo.clone()),
        ("autorun", REG_AUTORUN.undo.clone()),
        ("firewall", asset!("undo/firewall.ps1").to_string()),
        ("defender_cloud", asset!("undo/defender_cloud.ps1").to_string()),
        ("asr_lsass", asset!("undo/asr_lsass.ps1").replace("@LSASS@", WINDOWS_ASR_LSASS)),
        ("asr_audit", ASR_BASE.undo.clone()),
        ("asr_audit_extra", ASR_EXTRA.undo.clone()),
        ("wdigest", REG_WDIGEST.undo.clone()),
        ("ps_logging", REG_PSLOG.undo.clone()),
        ("ps2", asset!("undo/ps2.ps1").to_string()),
        ("remote_assist", REG_REMOTE.undo.clone()),
        ("audit", asset!("undo/audit.ps1").replace("@AUDIT_GUIDS@", &ps_audit_guids())),
        ("uac", asset!("undo/uac.ps1").to_string()),
        ("netbios", asset!("undo/netbios.ps1").to_string()),
        ("wpad", REG_WPAD.undo.clone()),
    ]
});

/// `_WINDOWS_PS_HELPERS`: the functions of the script (with the `@STATE_DIR@`, `@STATE_FILE@` and `@KNOWN_*@`
/// placeholders, see `ps_known_tables`).
pub(crate) const WINDOWS_PS_HELPERS: &str = asset!("helpers.ps1");

// The script starts with its parameters. Everything is safe by default: no argument means "Apply", exactly what
// SetupComplete.cmd has always run; -DisableLegacyNetwork is an opt-in switch; the log path defaults to the file
// SetupComplete.cmd already appends to.
pub(crate) const WINDOWS_PS_PARAMS: &str = asset!("params.ps1");

/// Who is running, the log file decision, the state file. Runs after the helpers and before the first setting.
pub(crate) const WINDOWS_PS_START: &str = asset!("start.ps1");

/// Audit mode only: read-only facts that this script never changes. They are NOT counted in the summary. None of
/// this could be run where it was written (no Windows, no pwsh): every query is wrapped in its own try/catch and says
/// what it could not read.
pub(crate) const WINDOWS_PS_AUDIT_INFO: &str = asset!("audit_info.ps1");

/// `_WINDOWS_PS_END["Apply"]`.
pub(crate) const WINDOWS_PS_END_APPLY: &str = asset!("end_apply.ps1");
/// `_WINDOWS_PS_END["Audit"]`.
pub(crate) const WINDOWS_PS_END_AUDIT: &str = asset!("end_audit.ps1");
/// `_WINDOWS_PS_END["Undo"]`.
pub(crate) const WINDOWS_PS_END_UNDO: &str = asset!("end_undo.ps1");

/// The header of the script (comments); `@SETTINGS_COMMENTS@`, `@NOT_CHANGED_COMMENTS@`, `@STATE@`, `@STATE_FOLDER@`
/// and `@LOG@` are filled in by `windows_harden_ps1`.
const WINDOWS_PS_HEAD: &str = asset!("head.ps1");

/// `_windows_ps_comment_lines(rows)`: two comment lines per row (id and text, then the risk note).
fn windows_ps_comment_lines(rows: &[(&str, &str, &str)]) -> Vec<String> {
    let mut out = Vec::with_capacity(rows.len() * 2);
    for (sid, text, note) in rows {
        out.push(format!("#   {sid}: {text}"));
        out.push(format!("#       risk/why: {note}"));
    }
    out
}

/// `_windows_ps_indent(code)`: strip the surrounding newlines and indent every non-blank line by four spaces.
fn windows_ps_indent(code: &str) -> String {
    code.trim_matches('\n')
        .split('\n')
        .map(|ln| if ln.trim().is_empty() { ln.to_string() } else { format!("    {ln}") })
        .collect::<Vec<_>>()
        .join("\n")
}

/// `_windows_harden_ps1()`: the exact bytes of harden.ps1 (UTF-8 BOM, CRLF, pure ASCII).
pub(crate) fn windows_harden_ps1() -> Result<Vec<u8>> {
    let ids: Vec<&str> = WINDOWS_HARDENING_SETTINGS.iter().map(|s| s.0).collect();
    let keys = |table: &PsTable| table.iter().map(|(k, _)| *k).collect::<Vec<_>>();
    if !(ids == keys(&WINDOWS_PS_CODE) && ids == keys(&WINDOWS_PS_AUDIT) && ids == keys(&WINDOWS_PS_UNDO)) {
        return Err(Error::runtime("PowerShell code blocks and hardening settings do not match"));
    }
    let head = WINDOWS_PS_HEAD
        .replace("@SETTINGS_COMMENTS@", &windows_ps_comment_lines(WINDOWS_HARDENING_SETTINGS).join("\n"))
        .replace("@NOT_CHANGED_COMMENTS@", &windows_ps_comment_lines(WINDOWS_HARDENING_NOT_CHANGED).join("\n"))
        .replace("@STATE@", WINDOWS_HARDENING_STATE)
        .replace("@STATE_FOLDER@", concat!("%ProgramData%\\", state_dir!()))
        .replace("@LOG@", WINDOWS_HARDENING_LOG);
    let mut body = String::new();
    // The three tables have the same keys in the same order as the settings (checked above), so they zip.
    let rows = WINDOWS_HARDENING_SETTINGS
        .iter()
        .zip(WINDOWS_PS_CODE.iter())
        .zip(WINDOWS_PS_AUDIT.iter())
        .zip(WINDOWS_PS_UNDO.iter());
    for ((((sid, text, _risk), (_, apply)), (_, audit)), (_, undo)) in rows {
        let what = text.replace('\'', "''");
        let part = |code: &str| windows_ps_indent(&code.replace("@WHAT@", &what));
        let code = format!(
            "if ($Mode -eq 'Apply') {{\n{}\n}} elseif ($Mode -eq 'Audit') {{\n{}\n}} else {{\n{}\n}}",
            part(apply),
            part(audit),
            part(undo)
        );
        body.push_str(&format!("\n# setting: {sid}\n{code}\n"));
    }
    let mut helpers = WINDOWS_PS_HELPERS
        .replace("@STATE_DIR@", WINDOWS_HARDENING_STATE_DIR)
        .replace("@STATE_FILE@", WINDOWS_HARDENING_STATE_FILE);
    for (placeholder, text) in ps_known_tables() {
        helpers = helpers.replace(placeholder, &text);
    }
    let tail = format!(
        "\nif ($Mode -eq 'Audit') {{\n{}\n{}\n}} elseif ($Mode -eq 'Undo') {{\n{}\n}} else {{\n{}\n}}\nexit 0\n",
        windows_ps_indent(WINDOWS_PS_AUDIT_INFO),
        windows_ps_indent(WINDOWS_PS_END_AUDIT),
        windows_ps_indent(WINDOWS_PS_END_UNDO),
        windows_ps_indent(WINDOWS_PS_END_APPLY)
    );
    let text = [head.as_str(), WINDOWS_PS_PARAMS, &helpers, WINDOWS_PS_START, &body, &tail].concat();
    if !text.is_ascii() {
        return Err(Error::runtime("harden.ps1 must be pure ASCII"));
    }
    // The assets are LF files. A checkout that converted them to CRLF (git `core.autocrlf` on Windows) must not turn
    // the output into CR CR LF, so every line end is normalised before it is made CRLF.
    let text = text.replace("\r\n", "\n");
    // BOM: PowerShell 5.1 reads ANSI without it.
    let mut out = vec![0xef, 0xbb, 0xbf];
    out.extend_from_slice(text.replace('\n', "\r\n").as_bytes());
    Ok(out)
}

/// `windows_hardening_ps1(profile)`: the exact bytes of harden.ps1 (UTF-8 BOM, CRLF, pure ASCII) that
/// `hardening_files_windows` ships. Other parts of the program (the Windows seed drive) call this instead of private
/// names. Empty bytes for `Hardening::None` (nothing to add, like `hardening_files_windows`).
pub fn windows_hardening_ps1(profile: Hardening) -> Result<Vec<u8>> {
    if !windows_hardening_check(profile) {
        return Ok(Vec::new());
    }
    windows_harden_ps1()
}
// ===== end hardening2: windows script =====

/// `hardening_files_windows(profile)`: the files the Windows 11 install media gets for the hardened setup:
/// `{relative posix path: bytes}`.
///
/// Exactly two files, both under sources/$OEM$/$$/Setup/Scripts (Windows Setup copies `$$` to %windir%, so no answer
/// file is needed and Setup stays fully interactive): SetupComplete.cmd and harden.ps1 (applied once at the end of
/// Setup, logged to %windir%\Temp\epma-hardening.log). SetupComplete.cmd runs harden.ps1 with no arguments (mode
/// Apply); the same harden.ps1 (see `windows_hardening_ps1`) also has the Audit and Undo modes and the opt-in
/// -DisableLegacyNetwork switch for an administrator on an installed Windows 11. Empty for `Hardening::None`.
pub fn hardening_files_windows(profile: Hardening) -> Result<Files> {
    let mut files = Files::new();
    if !windows_hardening_check(profile) {
        return Ok(files);
    }
    // One generation feeds both files, so the SHA-256 in SetupComplete.cmd is that of the harden.ps1 that is shipped.
    let ps1 = windows_harden_ps1()?;
    files.insert(WINDOWS_HARDENING_CMD.to_string(), windows_setupcomplete_cmd(profile, Some(&ps1))?);
    files.insert(WINDOWS_HARDENING_PS1.to_string(), ps1);
    Ok(files)
}
// ===== end hardening: windows content =====

#[cfg(test)]
mod tests;
