
param([int]$Number)
$disk = Get-Disk -Number $Number
if ($disk.BusType -ne 'USB') { throw "Disk $Number is not a USB drive." }
if ($disk.IsBoot -or $disk.IsSystem) { throw "Disk $Number holds the running Windows." }
if ($disk.IsOffline) { Set-Disk -Number $Number -IsOffline $false }
if ($disk.IsReadOnly) { Set-Disk -Number $Number -IsReadOnly $false }
if ($disk.PartitionStyle -ne 'RAW') { Clear-Disk -Number $Number -RemoveData -RemoveOEM -Confirm:$false }
Write-Output 'EPMA_RAW_READY'
