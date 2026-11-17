# send.ps1 -- send a payload to remote_lua_loader.
#
# The payload's `print` comes back over the same 9026 socket, so this is the
# live view of a run. Nothing is written to disk unless you ask for it with
# -Log <path>.

param(
    [Parameter(Mandatory = $true)][string]$Ip,
    [int]$Port = 9026,
    [string]$Lua = (Join-Path (Split-Path $PSScriptRoot -Parent) "afterglow.lua"),
    [string]$SendLua = "E:\PS JB Exploit\remote_lua_loader-n0llptr\payloads\send_lua.py",
    [ValidateSet("on", "off", "keep")][string]$SignalHandler = "keep",
    [string]$Python = "python",
    [string]$Log = ""
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $Lua)) { throw "payload not found: $Lua" }
if (-not (Test-Path $SendLua)) { throw "send_lua.py not found: $SendLua (pass -SendLua <path>)" }

# the mode, read off the payload, so the banner tells the truth
$head = (Get-Content -LiteralPath $Lua -TotalCount 120) -join "`n"
$m = [regex]::Match($head, '(?m)^\s*mode\s*=\s*"([a-z]+)"')
$mode = if ($m.Success) { $m.Groups[1].Value } else { "unknown" }

Write-Host "payload : $Lua"
Write-Host "target  : ${Ip}:$Port"
Write-Host "mode    : $mode"
if ($Log) { Write-Host "log     : $Log" }
Write-Host ""

$argv = @("-u", $SendLua, "$Ip", "$Port")
if ($SignalHandler -eq "on") {
    $argv += "--enable-signal-handler"
} elseif ($SignalHandler -eq "off") {
    $argv += "--disable-signal-handler"
} else {
    $argv += $Lua
}

if ($Log) {
    & $Python @argv 2>&1 | Tee-Object -FilePath $Log
} else {
    & $Python @argv 2>&1
}
