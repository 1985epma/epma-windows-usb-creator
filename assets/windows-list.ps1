
$sysLetter = ([string]$env:SystemDrive).TrimEnd(':')
$out = @()
foreach ($d in @(Get-Disk)) {
  $holdsSystem = [bool]($d.IsBoot -or $d.IsSystem)
  $vols = @()
  foreach ($p in @(Get-Partition -DiskNumber $d.Number -ErrorAction SilentlyContinue)) {
    $letter = ''
    if ($p.DriveLetter) { $letter = [string]$p.DriveLetter }
    if ($letter -ne '' -and $letter -eq $sysLetter) { $holdsSystem = $true }
    $v = $null
    if ($letter -ne '') { try { $v = Get-Volume -DriveLetter $letter -ErrorAction Stop } catch { $v = $null } }
    $label = ''; $fs = ''; $free = -1
    if ($v) { $label = [string]$v.FileSystemLabel; $fs = [string]$v.FileSystem; $free = [int64]$v.SizeRemaining }
    $vols += [pscustomobject]@{ Letter = $letter; Label = $label; FileSystem = $fs; Size = [int64]$p.Size; Free = $free }
  }
  $out += [pscustomobject]@{
    Number = [int]$d.Number; Model = [string]$d.FriendlyName; Serial = ([string]$d.SerialNumber).Trim()
    UniqueId = [string]$d.UniqueId; BusType = [string]$d.BusType; Size = [int64]$d.Size
    SectorSize = [int]$d.LogicalSectorSize; HoldsSystem = $holdsSystem; Volumes = @($vols)
  }
}
ConvertTo-Json -InputObject @($out) -Depth 4 -Compress
