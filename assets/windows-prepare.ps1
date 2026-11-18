
param([int]$Number, [string]$Label, [long]$MaxBytes)
$disk = Get-Disk -Number $Number
if ($disk.BusType -ne 'USB') { throw "Disk $Number is not a USB drive." }
if ($disk.IsBoot -or $disk.IsSystem) { throw "Disk $Number holds the running Windows." }
$svc = Get-Service -Name ShellHWDetection -ErrorAction SilentlyContinue
$stopped = $false
if ($svc -and $svc.Status -eq 'Running') { Stop-Service -Name ShellHWDetection -Force -ErrorAction SilentlyContinue; $stopped = $true }
try {
  if ($disk.IsOffline) { Set-Disk -Number $Number -IsOffline $false }
  if ($disk.IsReadOnly) { Set-Disk -Number $Number -IsReadOnly $false }
  if ($disk.PartitionStyle -ne 'RAW') { Clear-Disk -Number $Number -RemoveData -RemoveOEM -Confirm:$false }
  Initialize-Disk -Number $Number -PartitionStyle GPT
  if ($MaxBytes -gt 0 -and $disk.Size -gt ($MaxBytes + 4MB)) {
    $part = New-Partition -DiskNumber $Number -Size $MaxBytes -AssignDriveLetter
  } else {
    $part = New-Partition -DiskNumber $Number -UseMaximumSize -AssignDriveLetter
  }
  $null = Format-Volume -Partition $part -FileSystem FAT32 -NewFileSystemLabel $Label -Confirm:$false -Force
  $part = Get-Partition -DiskNumber $Number -PartitionNumber $part.PartitionNumber
  Write-Output ('EPMA_VOLUME ' + $part.DriveLetter + ' ' + $part.PartitionNumber)
} finally {
  if ($stopped) { Start-Service -Name ShellHWDetection -ErrorAction SilentlyContinue }
}
