﻿# 李喜 skill 一键安装器（幂等；可 -DryRun 演练）
# 用法：
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\一键安装.ps1 -DryRun
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\一键安装.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\一键安装.ps1 -Target "D:\某处\skills"
param(
    [string]$Target = '',
    [switch]$DryRun,
    [switch]$SkipTest
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}
$SkillName = 'lixi-reverse'
$PkgRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Src = Join-Path $PkgRoot $SkillName

function Say($m) { Write-Host $m }
function Ok($m) { Write-Host "  [OK] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "  [!] $m" -ForegroundColor Yellow }
function Die($m) { Write-Host "  [X] $m" -ForegroundColor Red; exit 1 }

Say "== 李喜 skill 安装器 =="
if (-not (Test-Path (Join-Path $Src 'SKILL.md'))) { Die "包不完整：缺 $Src\SKILL.md" }
Ok "技能包: $Src"

# ---------- 1. 找 skills 根 ----------
function Find-SkillRoots {
    $cands = @()
    # ① 显式参数
    if ($Target) { $cands += $Target; return $cands }
    # ② DSH profile 里的 customSkillDirs
    $profDirs = @()
    if ($env:DSH_PROFILE_DIR) { $profDirs += $env:DSH_PROFILE_DIR }
    if ($env:DSH_HOME) {
        $p = Join-Path $env:DSH_HOME 'profiles'
        if (Test-Path $p) { $profDirs += (Get-ChildItem $p -Directory | ForEach-Object { $_.FullName }) }
    }
    if (-not $env:DSH_HOME -and $env:USERPROFILE) {
        $p = Join-Path $env:USERPROFILE '.dsh\profiles'
        if (Test-Path $p) { $profDirs += (Get-ChildItem $p -Directory | ForEach-Object { $_.FullName }) }
    }
    foreach ($d in $profDirs) {
        $y = Join-Path $d 'cordis.patch.yml'
        if (-not (Test-Path $y)) { continue }
        $txt = Get-Content $y -Raw -Encoding UTF8
        # 抓 customSkillDirs: 之后的若干 "  - '路径'" 行
        $m = [regex]::Match($txt, 'customSkillDirs:\s*\r?\n((?:\s*-\s*.+\r?\n)+)')
        if ($m.Success) {
            foreach ($line in ($m.Groups[1].Value -split "`r?`n")) {
                $mm = [regex]::Match($line, '-\s*[''"]?([^''"]+?)[''"]?\s*$')
                if ($mm.Success) {
                    $p2 = $mm.Groups[1].Value.Trim()
                    if (Test-Path $p2) { $cands += $p2 }
                }
            }
        }
    }
    return ($cands | Select-Object -Unique)
}

$roots = @(Find-SkillRoots)
if (-not $roots -or $roots.Count -eq 0) {
    Die @"
没找到可用的 skills 根。请显式指定：
   -Target "<DSH 配置里 customSkillDirs 指向的目录>"
提示：那个目录下应当已经有其它技能（如 xiaotao-win-flow\SKILL.md）。
"@
}
Say "`n探测到的 skills 根:"
$roots | ForEach-Object { Say "   - $_" }
$root = $roots[0]
if ($roots.Count -gt 1) { Warn "有多个候选，默认用第一个；要换请加 -Target" }

$dst = Join-Path $root $SkillName
Say "`n安装目标: $dst"
if ($DryRun) { Warn "-DryRun：只演练，不落盘"; }

# ---------- 2. 复制 ----------
if (-not $DryRun) {
    if (Test-Path $dst) {
        Warn "目标已存在，覆盖技能目录（不动其它技能）"
        Remove-Item $dst -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $dst | Out-Null
    # 复制（排除 __pycache__）
    $files = Get-ChildItem $Src -Recurse -File | Where-Object { $_.FullName -notmatch '__pycache__' }
    foreach ($f in $files) {
        $rel = $f.FullName.Substring($Src.Length + 1)
        $to = Join-Path $dst $rel
        $dir = Split-Path -Parent $to
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        Copy-Item $f.FullName $to -Force
    }
    Ok "已复制 $($files.Count) 个文件"
} else {
    $files = Get-ChildItem $Src -Recurse -File | Where-Object { $_.FullName -notmatch '__pycache__' }
    Ok "将复制 $($files.Count) 个文件（演练）"
}

# ---------- 3. 自检 ----------
if (-not $SkipTest -and -not $DryRun) {
    Say "`n自检（selftest.py）…"
    $py = (Get-Command python -ErrorAction SilentlyContinue)
    if (-not $py) { $py = (Get-Command py -ErrorAction SilentlyContinue) }
    if (-not $py) {
        Warn "没找到 python，跳过自检。装好后请手动跑: python `"$dst\scripts\selftest.py`""
    } else {
        & $py.Source (Join-Path $dst 'scripts\selftest.py')
        if ($LASTEXITCODE -ne 0) { Warn "自检未全绿（缺 capstone 属正常降级）；其余输出见上" }
        else { Ok "自检全绿" }
    }
}

# ---------- 4. 下一步 ----------
Say @"

== 装好了，下一步 ==
1) 重启 DeepSeek Harness（或等 skill-filesystem 的 watch 自动发现）
2) 会话里说一句「李喜」——技能列表里应出现 $SkillName
3) 冒烟测试：
   python "$dst\scripts\autoexec.py" "<任意 APK/ELF/.sh>" --need "判型"
4) 若技能列表里看不到：确认 DSH 的 customSkillDirs 包含 $root
   （要加就编辑 <DSH_PROFILE_DIR>\cordis.patch.yml 的 skill-filesystem 段，加一行 '- $root'，重启）

卸载：Remove-Item "$dst" -Recurse -Force
"@
