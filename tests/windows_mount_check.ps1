# windows_mount_check.ps1 - mount the test VHDs read-only with Windows' own
# FAT32 and exFAT drivers, compare every file's SHA-256 (and, for exFAT, its
# UTC modified time) with expected.json, and run chkdsk on each volume.
#
# USAGE:  .\tests\windows_mount_check.ps1 -Dir <dir written by make_vhd.py>
# Needs an elevated shell (GitHub's windows-latest runner is one).

param([Parameter(Mandatory = $true)][string]$Dir)
$ErrorActionPreference = "Stop"
$expected = Get-Content -Raw -Encoding UTF8 (Join-Path $Dir "expected.json") | ConvertFrom-Json
$failed = 0

foreach ($fs in @("fat32", "exfat")) {
    $vhd = (Resolve-Path (Join-Path $Dir "$fs.vhd")).Path
    Mount-DiskImage -ImagePath $vhd -Access ReadOnly | Out-Null
    try {
        Start-Sleep -Seconds 3
        $disk = Get-DiskImage -ImagePath $vhd | Get-Disk
        $part = Get-Partition -DiskNumber $disk.Number | Where-Object DriveLetter | Select-Object -First 1
        if (-not $part) { throw "$fs : Windows assigned no drive letter (volume not recognized)" }
        $vol = Get-Volume -DriveLetter $part.DriveLetter
        Write-Host "$fs : mounted as $($part.DriveLetter): filesystem $($vol.FileSystem), label $($vol.FileSystemLabel)"
        $root = "$($part.DriveLetter):\"
        foreach ($p in $expected.$fs.PSObject.Properties) {
            $path = Join-Path $root ($p.Name -replace "/", "\")
            if (-not (Test-Path -LiteralPath $path)) { Write-Host "MISSING $fs $($p.Name)"; $failed++; continue }
            $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower()
            if ($hash -ne $p.Value[0]) { Write-Host "HASH MISMATCH $fs $($p.Name)"; $failed++ }
            if ($fs -eq "exfat") {
                $epoch = [int][double]::Parse((Get-Date (Get-Item -LiteralPath $path).LastWriteTimeUtc -UFormat %s))
                if ([math]::Abs($epoch - [int]$p.Value[1]) -gt 2) { Write-Host "TIME MISMATCH $fs $($p.Name): $epoch"; $failed++ }
            }
        }
        $count = (Get-ChildItem -LiteralPath $root -Recurse -File -Force | Measure-Object).Count
        Write-Host "$fs : $count files visible to Windows"
        & chkdsk.exe "$($part.DriveLetter):" | Out-Host
        if ($LASTEXITCODE -ne 0) { Write-Host "CHKDSK reported problems on $fs (exit $LASTEXITCODE)"; $failed++ }
    }
    finally {
        Dismount-DiskImage -ImagePath $vhd | Out-Null
    }
}
if ($failed) { Write-Error "$failed check(s) failed"; exit 1 }
Write-Host "Windows drivers read both volumes; hashes, times and chkdsk agree"
