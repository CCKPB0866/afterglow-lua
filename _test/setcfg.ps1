<#
  setcfg.ps1 -- toggle any afterglow.lua config switch without touching the file
                by hand.

  show what is set now:
      .\_test\setcfg.ps1

  change one switch:
      .\_test\setcfg.ps1 debug true
      .\_test\setcfg.ps1 mode probe
      .\_test\setcfg.ps1 sprays 200
      .\_test\setcfg.ps1 leak_rax_only on        (on/off -> true/false)

  everything is written back to afterglow.lua as `    name = value,` and the
  file is re-encoded UTF-8 without BOM (the loader needs it that way).
#>

param(
    [string]$Name,
    [string]$Value,
    [string]$File = (Join-Path $PSScriptRoot "..\afterglow.lua")
)

$File = [System.IO.Path]::GetFullPath($File)
if (-not (Test-Path $File)) { Write-Error "no such file: $File"; exit 1 }

$text  = [System.IO.File]::ReadAllText($File)
$lines = $text -split "`r?`n"

if (-not $Name) {
    "current settings in $File`n"
    $n = 0
    foreach ($line in $lines) {
        $n++
        if ($line -match '^\s{4}([a-z_][a-z0-9_]*)\s*=\s*(.+?),?\s*(--.*)?$') {
            "{0,4}  {1,-18} {2}" -f $n, $matches[1], $matches[2]
        }
    }
    exit 0
}

switch ($Value.ToLower()) {
    "on"  { $Value = "true" }
    "off" { $Value = "false" }
}
# a quoted setting stays quoted: `mode run` must not turn into `mode = run`
$quoteIt = $Value -notmatch '^["''{\[]' -and $Value -notmatch '^(true|false|nil|[-0-9])'
if ($quoteIt -and $Name -notmatch '^(debug|verbose|measure_cores|idle_|leak_|probe_|one_read_|use_jmp_|apply_|notify)') {
    $Value = '"' + $Value + '"'
}

$pattern = '^(\s{4})' + [regex]::Escape($Name) + '(\s*=\s*)([^,\r\n]+)(,?)(.*)$'
$hit = $false
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match $pattern) {
        $old = $matches[3]
        $lines[$i] = $matches[1] + $Name + $matches[2] + $Value + $matches[4] + $matches[5]
        "{0}: {1}  {2}  ->  {3}" -f ($i + 1), $Name, $old.Trim(), $Value
        $hit = $true
        break
    }
}

if (-not $hit) { Write-Error "no switch named '$Name' (run without arguments to list them)"; exit 1 }

[System.IO.File]::WriteAllText($File, ($lines -join "`n"), (New-Object System.Text.UTF8Encoding($false)))
"written"
