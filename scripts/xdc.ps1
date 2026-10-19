# lixi-reverse · xdc.ps1 — 不依赖 Python 的第一响应（Windows 原生）
# 用法: powershell -NoProfile -ExecutionPolicy Bypass -File xdc.ps1 <目标> [-Need "绕过卡密"]
# 作用: 头判型 + 大小 + SHA256 + （ZIP/APK）条目分组 + 分层判定 + 下一步命令
# 纪律: 只读。深度分析仍走 python scripts\autoexec.py（本脚本是"没有 Python 时也能先看一眼"）

param(
    [Parameter(Mandatory = $true, Position = 0)][string]$Target,
    [string]$Need = ''
)
$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}

if (-not (Test-Path $Target)) { Write-Host "[X] 目标不存在: $Target" -ForegroundColor Red; exit 2 }
$f = Get-Item $Target
$bytes = New-Object byte[] 16
$fs = [IO.File]::OpenRead($f.FullName); [void]$fs.Read($bytes, 0, 16); $fs.Close()
$hex = ($bytes | ForEach-Object { $_.ToString('x2') }) -join ' '

function Get-Kind([byte[]]$b) {
    if ($b[0] -eq 0x7f -and $b[1] -eq 0x45 -and $b[2] -eq 0x4c -and $b[3] -eq 0x46) { return 'ELF' }
    if ($b[0] -eq 0x50 -and $b[1] -eq 0x4b) { return 'ZIP/APK/JAR' }
    if ($b[0] -eq 0x64 -and $b[1] -eq 0x65 -and $b[2] -eq 0x78) { return 'DEX' }
    if ($b[0] -eq 0x1f -and $b[1] -eq 0x8b) { return 'gzip' }
    if ($b[0] -eq 0xfd -and $b[1] -eq 0x37) { return 'xz' }
    if ($b[0] -eq 0x42 -and $b[1] -eq 0x5a -and $b[2] -eq 0x68) { return 'bzip2' }
    if ($b[0] -eq 0x4d -and $b[1] -eq 0x5a) { return 'PE(Windows)' }
    if ($b[0] -eq 0x25 -and $b[1] -eq 0x50) { return 'PDF' }
    return '未知/文本/其它'
}

$kind = Get-Kind $bytes
$sha = (Get-FileHash $f.FullName -Algorithm SHA256).Hash.ToLower()
$mb = [math]::Round($f.Length / 1MB, 2)

Write-Host "== lixi-reverse · 第一响应（PowerShell 版）"
Write-Host "   目标: $($f.FullName)"
Write-Host ("   大小: {0} B ({1} MB)   SHA256: {2}" -f $f.Length, $mb, $sha.Substring(0,16))
Write-Host "   头16: $hex"
Write-Host "   形态: $kind"

# ELF 细看
if ($kind -eq 'ELF') {
    $fs = [IO.File]::OpenRead($f.FullName)
    $h = New-Object byte[] 64; [void]$fs.Read($h, 0, 64); $fs.Close()
    $cls = if ($h[4] -eq 2) { 'ELF64' } else { 'ELF32' }
    $le = $h[5] -eq 1
    $eType = if ($le) { [BitConverter]::ToUInt16($h, 16) } else { ([BitConverter]::ToUInt16($h, 16) -shr 8) -bor (([BitConverter]::ToUInt16($h, 16) -band 0xFF) -shl 8) }
    $machine = if ($le) { [BitConverter]::ToUInt16($h, 18) } else { 0 }
    $emap = @{ 183 = 'AARCH64'; 62 = 'X86_64'; 40 = 'ARM' }
    $tm = @{ 1 = 'REL(内核模块)'; 2 = 'EXEC'; 3 = 'DYN(PIE/so)'; 4 = 'CORE' }
    Write-Host ("   ELF: {0} {1} type={2} machine={3}" -f $cls, $(if($le){'LE'}else{'BE'}), $tm[$eType], $emap[$machine])
    Write-Host "   >> 下一步: python scripts\elfprobe.py `"$($f.FullName)`"     # 熵/自解密四指纹/filesz=0/大块高熵数据段"
    Write-Host "             python scripts\container.py `"$($f.FullName)`"    # 追加容器 / 节表 / 垃圾字"
    Write-Host "             python scripts\rkprobe.py `"$($f.FullName)`"       # 运行时打桩点（thunk/PLT/喂狗）"
    Write-Host "             python scripts\jniprobe.py `"$($f.FullName)`"      # JNI 动态注册还原"
}
# ZIP/APK 条目
if ($kind -eq 'ZIP/APK/JAR') {
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $z = [IO.Compression.ZipFile]::OpenRead($f.FullName)
        $dex = @($z.Entries | Where-Object { $_.Name -match '^classes\d*\.dex$' })
        $so = @($z.Entries | Where-Object { $_.FullName -match '\.so$' })
        $lua = @($z.Entries | Where-Object { $_.FullName -match '\.lua$' })
        $assets = @($z.Entries | Where-Object { $_.FullName -match '^(assets|res)/' })
        Write-Host ("   条目: {0}  dex: {1}  so: {2}  lua: {3}  assets/res: {4}" -f $z.Entries.Count, $dex.Count, $so.Count, $lua.Count, $assets.Count)
        foreach ($d in $dex) { Write-Host ("     {0,-18} {1,12:N0} B" -f $d.FullName, $d.Length) }
        $tiny = @($dex | Where-Object { $_.Length -lt 20000 })
        if ($tiny.Count -gt 0) { Write-Host ("   [!] 极小 dex（可能是解码器）: " + (($tiny | ForEach-Object { $_.Name }) -join ', ')) -ForegroundColor Yellow }
        $stored = @($so | Where-Object { $_.CompressedLength -eq $_.Length })
        if ($stored.Count -gt 0) { Write-Host ("   [!] STORED 的 so（重打包必须页对齐）: " + (($stored | ForEach-Object { $_.Name }) -join ', ')) -ForegroundColor Yellow }
        if ($lua.Count -ge 5) { Write-Host "   [!] 成规模 .lua ⇒ 可能是脚本壳（闸门在脚本里，不在 dex）" -ForegroundColor Yellow }
        $z.Dispose()
    } catch { Write-Host "   [!] 读 zip 失败: $_" }
    Write-Host "   >> 下一步: python scripts\autoexec.py `"$($f.FullName)`" --need `"$Need`""
    Write-Host "             python scripts\luaq.py `"$($f.FullName)`"          # 是不是脚本层"
}
if ($kind -eq 'gzip') { Write-Host "   >> 下一步: python scripts\payload.py `"$($f.FullName)`" --dump out   # 剥载体链" }
if ($kind -eq 'PE(Windows)') { Write-Host "   >> 这是 Windows PE，不是安卓目标；本技能不覆盖（走 win-flow）" }

if ($Need) { Write-Host "   需求: $Need" }
Write-Host ""
Write-Host "   深度分析（需要 Python）: python scripts\autoexec.py `"$($f.FullName)`" --need `"$Need`""
