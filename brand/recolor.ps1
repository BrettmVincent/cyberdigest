# Recolour the brand cyan in the logo/icon PNGs (shield + "Digest") to the brand blue.
# Pixels in the cyan/teal hue band (165°–200°, saturation >= 0.25) take the target colour scaled by
# their own brightness (keeps anti-aliasing and shading); alpha is untouched. White "Cyber" text and
# the blue dot (hue ~210°) fall outside the band and are left as they are.
#   Light-theme logo + favicon: #005baa.  Dark-theme logo + touch icon: #4a95e2 (same hue, readable on black).
# Windows PowerShell / pwsh with System.Drawing. Run from the repo root:  pwsh -File brand/recolor.ps1
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$dir = Join-Path $PSScriptRoot '..\web\public\brand'
$jobs = @(
    @{ File = 'logo-light-full.png'; Target = '#005baa' },
    @{ File = 'logo-light.png'; Target = '#005baa' },
    @{ File = 'logo-dark-full.png'; Target = '#4a95e2' },
    @{ File = 'logo-dark.png'; Target = '#4a95e2' },
    @{ File = 'icon-64.png'; Target = '#005baa' },
    @{ File = 'icon-180.png'; Target = '#4a95e2' }
)

function Get-Hsv([int]$r, [int]$g, [int]$b) {
    $max = [Math]::Max($r, [Math]::Max($g, $b)); $min = [Math]::Min($r, [Math]::Min($g, $b)); $d = $max - $min
    $h = 0.0
    if ($d -gt 0) {
        if ($max -eq $r) { $h = 60 * ((($g - $b) / $d) % 6) }
        elseif ($max -eq $g) { $h = 60 * ((($b - $r) / $d) + 2) }
        else { $h = 60 * ((($r - $g) / $d) + 4) }
        if ($h -lt 0) { $h += 360 }
    }
    $s = if ($max -gt 0) { $d / $max } else { 0 }
    return @($h, $s, ($max / 255.0))
}

foreach ($j in $jobs) {
    $path = Join-Path $dir $j.File
    $src = [System.Drawing.Bitmap]::FromFile($path)
    $bmp = New-Object System.Drawing.Bitmap $src
    $src.Dispose()
    $t = [System.Drawing.ColorTranslator]::FromHtml($j.Target)
    $rect = New-Object System.Drawing.Rectangle 0, 0, $bmp.Width, $bmp.Height
    $data = $bmp.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::ReadWrite, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $n = $data.Stride * $bmp.Height
    $px = New-Object byte[] $n
    [System.Runtime.InteropServices.Marshal]::Copy($data.Scan0, $px, 0, $n)
    # Pass 1: reference brightness = 95th percentile of the band's V values.
    $vals = New-Object System.Collections.Generic.List[double]
    for ($i = 0; $i -lt $n; $i += 4) {
        if ($px[$i + 3] -eq 0) { continue }
        $hsv = Get-Hsv $px[$i + 2] $px[$i + 1] $px[$i]
        if ($hsv[0] -ge 165 -and $hsv[0] -le 200 -and $hsv[1] -ge 0.25) { $vals.Add($hsv[2]) }
    }
    if ($vals.Count -eq 0) { Write-Host "$($j.File): no cyan pixels (already recoloured?) - skipped"; $bmp.UnlockBits($data); $bmp.Dispose(); continue }
    $sorted = $vals | Sort-Object
    $vref = [double]$sorted[[int][Math]::Floor(($sorted.Count - 1) * 0.95)]
    # Pass 2: recolour.
    $changed = 0
    for ($i = 0; $i -lt $n; $i += 4) {
        if ($px[$i + 3] -eq 0) { continue }
        $hsv = Get-Hsv $px[$i + 2] $px[$i + 1] $px[$i]
        if (-not ($hsv[0] -ge 165 -and $hsv[0] -le 200 -and $hsv[1] -ge 0.25)) { continue }
        $f = [Math]::Min(1.0, $hsv[2] / $vref)
        $px[$i + 2] = [byte][Math]::Round($t.R * $f)
        $px[$i + 1] = [byte][Math]::Round($t.G * $f)
        $px[$i] = [byte][Math]::Round($t.B * $f)
        $changed++
    }
    [System.Runtime.InteropServices.Marshal]::Copy($px, 0, $data.Scan0, $n)
    $bmp.UnlockBits($data)
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host ("{0}: {1} px -> {2}" -f $j.File, $changed, $j.Target)
}
