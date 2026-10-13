[CmdletBinding()]
param(
    [string]$ApkPath,
    [string]$Device = '127.0.0.1:7555',
    [string]$Package = 'com.moonjoy.letsfarm',
    [string]$Output = '',
    [switch]$PullFromDevice
)

$ErrorActionPreference = 'Stop'

function Get-RelativePath([string]$Base, [string]$Path) {
    $Path.Substring($Base.Length).TrimStart('\', '/')
}

function Get-PrintableStrings([byte[]]$Bytes, [int]$MinLength = 6) {
    $text = [Text.Encoding]::UTF8.GetString($Bytes)
    $text -split "[^\x20-\x7E]+" | Where-Object { $_.Length -ge $MinLength } | Sort-Object -Unique
}

function Add-UniqueLine([Collections.Generic.List[string]]$List, [string]$Value) {
    if ($Value -and -not $List.Contains($Value)) { $List.Add($Value) }
}

if (-not $ApkPath -or $PullFromDevice) {
    if (-not $Output) { $Output = Join-Path $PSScriptRoot '..\out\static' }
    New-Item -ItemType Directory -Force -Path $Output | Out-Null
    $ApkPath = Join-Path $Output ($Package + '.apk')
    $apkRemote = @(adb -s $Device shell pm path $Package) |
        ForEach-Object { $_.ToString().Trim() -replace '^package:', '' } |
        Where-Object { $_ } |
        Select-Object -First 1
    if (-not $apkRemote) { throw "Package '$Package' was not found on device '$Device'." }
    adb -s $Device pull $apkRemote $ApkPath
    if ($LASTEXITCODE -ne 0) { throw "Failed to pull APK from $Device." }
}

if (-not (Test-Path -LiteralPath $ApkPath -PathType Leaf)) {
    throw "APK not found: $ApkPath"
}

if (-not $Output) {
    $base = [IO.Path]::GetFileNameWithoutExtension($ApkPath)
    $Output = Join-Path (Split-Path -Parent $ApkPath) ($base + '-static')
}
New-Item -ItemType Directory -Force -Path $Output | Out-Null
$Extract = Join-Path $Output 'extracted'
New-Item -ItemType Directory -Force -Path $Extract | Out-Null

Add-Type -AssemblyName System.IO.Compression.FileSystem
$apkFull = [IO.Path]::GetFullPath($ApkPath)
$apkHash = (Get-FileHash -LiteralPath $apkFull -Algorithm SHA256).Hash
$zip = [IO.Compression.ZipFile]::OpenRead($apkFull)
$entries = @($zip.Entries)

$libraries = [Collections.Generic.List[object]]::new()
$metadata = [Collections.Generic.List[object]]::new()
$managed = [Collections.Generic.List[string]]::new()
$dex = [Collections.Generic.List[string]]::new()
$symbols = [Collections.Generic.List[string]]::new()
$bundles = [Collections.Generic.List[string]]::new()
$textCandidates = [Collections.Generic.List[string]]::new()
$abis = [Collections.Generic.List[string]]::new()

foreach ($entry in $entries) {
    $name = $entry.FullName
    if ($entry.Length -eq 0) { continue }
    if ($name -match '^lib/([^/]+)/libil2cpp\.so$') {
        Add-UniqueLine $abis $Matches[1]
        $libraries.Add([pscustomobject]@{ path = $name; size = $entry.Length })
    }
    if ($name -match '^lib/([^/]+)/.*\.so$') { Add-UniqueLine $abis $Matches[1] }
    if ($name -match 'global-metadata\.dat$') {
        $metadata.Add([pscustomobject]@{ path = $name; size = $entry.Length })
    }
    if ($name -match '(?i)(^|/)Managed/.*\.dll$|(^|/)\.dll$') { Add-UniqueLine $managed $name }
    if ($name -match '(?i)(^|/).+\.dex$') { Add-UniqueLine $dex $name }
    if ($name -match '(?i)(\.pdb$|\.dbg$|symbols\.zip$)') { Add-UniqueLine $symbols $name }
    if ($name -match '(?i)(\.bundle$|\.unity3d$|assetbundle)') { Add-UniqueLine $bundles $name }
    if ($name -match '(?i)(\.json$|\.xml$|\.properties$|\.ini$|\.cfg$|\.txt$|\.bytes$)') {
        Add-UniqueLine $textCandidates $name
    }
}

$stringHits = [Collections.Generic.List[string]]::new()
$extractNames = [Collections.Generic.HashSet[string]]::new()
foreach ($item in $libraries) { [void]$extractNames.Add($item.path) }
foreach ($item in $metadata) { [void]$extractNames.Add($item.path) }
foreach ($item in $managed) { [void]$extractNames.Add($item) }
foreach ($item in $textCandidates) { [void]$extractNames.Add($item) }

foreach ($entry in $entries) {
    if ($entry.FullName -notin $extractNames) { continue }
    $relative = $entry.FullName -replace '/', '\\'
    $destination = Join-Path $Extract $relative
    $parent = Split-Path -Parent $destination
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    $stream = $entry.Open()
    $file = [IO.File]::Open($destination, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.CopyTo($file) } finally { $file.Dispose(); $stream.Dispose() }
}

$interesting = @(
    'api[_-]?key', 'secret', 'token', 'password', 'private[_-]?key',
    'client[_-]?secret', 'authorization', 'license', 'obfuz', 'metadata'
)

foreach ($entry in $entries) {
    if ($entry.FullName -notin $textCandidates) { continue }
    if ($entry.FullName -match '(^|/)META-INF/|LICENSE') { continue }
    if ($entry.Length -gt 2MB) { continue }
    $stream = $entry.Open()
    $memory = [IO.MemoryStream]::new()
    try {
        $stream.CopyTo($memory)
        $bytes = $memory.ToArray()
        foreach ($line in (Get-PrintableStrings $bytes)) {
            if ($interesting | Where-Object { $line -match $_ }) {
                Add-UniqueLine $stringHits ($entry.FullName + ': ' + $line.Substring(0, [Math]::Min($line.Length, 240)))
            }
        }
    } finally {
        $memory.Dispose()
        $stream.Dispose()
    }
}

$report = [ordered]@{
    generated = (Get-Date).ToString('o')
    apk = $apkFull
    sha256 = $apkHash
    size = (Get-Item -LiteralPath $apkFull).Length
    entryCount = $entries.Count
    il2cpp = [ordered]@{
        detected = ($libraries.Count -gt 0)
        libraries = @($libraries)
        metadata = @($metadata)
        abi = @($abis | Sort-Object)
        managedDllCount = $managed.Count
        managedDlls = @($managed | Sort-Object)
    }
    dexCount = $dex.Count
    dex = @($dex | Sort-Object)
    debugSymbolCount = $symbols.Count
    debugSymbols = @($symbols | Sort-Object)
    assetBundleCount = $bundles.Count
    assetBundles = @($bundles | Sort-Object)
    possibleSensitiveStrings = @($stringHits | Sort-Object)
}

$jsonPath = Join-Path $Output 'static-report.json'
$txtPath = Join-Path $Output 'static-summary.txt'
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

$summary = [Collections.Generic.List[string]]::new()
$summary.Add('APK static analysis')
$summary.Add(('APK: ' + $apkFull))
$summary.Add(('SHA256: ' + $apkHash))
$summary.Add(('Size: ' + $report.size + ' bytes'))
$summary.Add(('Entries: ' + $entries.Count))
$summary.Add('')
$summary.Add(('IL2CPP detected: ' + $report.il2cpp.detected))
$summary.Add(('ABI: ' + [string]::Join(', ', @($report.il2cpp.abi))))
$summary.Add(('libil2cpp.so: ' + $libraries.Count))
$summary.Add(('global-metadata.dat: ' + $metadata.Count))
$summary.Add(('Managed DLLs: ' + $managed.Count))
$summary.Add(('DEX files: ' + $dex.Count))
$summary.Add(('Debug symbols: ' + $symbols.Count))
$summary.Add(('Asset bundles: ' + $bundles.Count))
$summary.Add(('Possible sensitive string hits: ' + $stringHits.Count))
if ($stringHits.Count) {
    $summary.Add('')
    $summary.Add('Possible sensitive string hits:')
    $stringHits | Sort-Object | ForEach-Object { $summary.Add('  ' + $_) }
}
$summary | Set-Content -LiteralPath $txtPath -Encoding UTF8

$zip.Dispose()
$summary | ForEach-Object { Write-Output $_ }
Write-Output ''
Write-Output ('JSON report: ' + $jsonPath)
Write-Output ('Summary: ' + $txtPath)
