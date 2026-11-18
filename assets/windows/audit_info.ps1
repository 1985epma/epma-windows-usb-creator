
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
