#!/usr/bin/env pwsh
# Direct Windows build script for pixiewps-extend using Clang-CL (MSVC driver)

$CLANG = "C:\Program Files\LLVM\bin\clang-cl.exe"
$OUTDIR = ".\build"
$OBJDIR = ".\build\obj"

New-Item -ItemType Directory -Force -Path $OUTDIR | Out-Null
New-Item -ItemType Directory -Force -Path $OBJDIR | Out-Null

Write-Host "pixiewps-extend Windows Build (clang-cl)" -ForegroundColor Cyan

$SOURCES = @(
    "src/pixiewps.c",
    "src/pixiewps_modules.c",
    "src/wifi_scanner.c"
)

$TFM_SOURCES = Get-ChildItem "src/crypto/tfm/*.c" | ForEach-Object { $_.FullName }
$TC_SOURCES = @("src/crypto/tc/aes.c", "src/crypto/tc/aes_cbc.c")
$OTHER_SOURCES = @("src/crypto/hmac_sha256.c", "src/crypto/crypto_internal-modexp.c", "src/random/glibc_random_yura.c")

$ALL_SOURCES = @($SOURCES) + $TFM_SOURCES + $TC_SOURCES + $OTHER_SOURCES

$CFLAGS = @("/O2", "/W3", "/TC", "/D_POSIX_C_SOURCE=200809L", "/Isrc", "/Isrc/crypto/tc", "/Isrc/crypto/tfm")

Write-Host "Compiling $($ALL_SOURCES.Count) sources..." -ForegroundColor Cyan
$i = 0
$errors = 0

foreach ($src in $ALL_SOURCES) {
    $i++
    $basename = Split-Path -Leaf $src
    $obj = Join-Path $OBJDIR ($basename -replace "\.c`$", ".obj")
    Write-Host "[$i/$($ALL_SOURCES.Count)] $basename" -NoNewline
    
    $cmd = @("/c", $src, "/Fo$obj") + $CFLAGS
    & $CLANG @cmd 2>&1 | Out-Null
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host " OK" -ForegroundColor Green
    } else {
        Write-Host " FAIL" -ForegroundColor Red
        & $CLANG @cmd 2>&1 | Select-Object -First 5
        $errors++
    }
}

if ($errors -gt 0) {
    Write-Host "`nERROR: $errors compilation failures" -ForegroundColor Red
    exit 1
}

Write-Host "`nLinking..." -ForegroundColor Cyan
$OBJS = Get-ChildItem "$OBJDIR/*.obj"
$OUTPUT = "$OUTDIR\pixiewps.exe"

& $CLANG $OBJS /Fe$OUTPUT /link /SUBSYSTEM:CONSOLE 2>&1 | Out-Null

if ($LASTEXITCODE -eq 0) {
    Write-Host "SUCCESS! Binary: $OUTPUT" -ForegroundColor Green
    Write-Host "Size: $((Get-Item $OUTPUT).Length) bytes" -ForegroundColor Green
} else {
    Write-Host "Link FAILED" -ForegroundColor Red
    & $CLANG $OBJS /Fe$OUTPUT /link /SUBSYSTEM:CONSOLE 2>&1 | Select-Object -First 10
    exit 1
}
