# send_bin.ps1 -- push a raw binary payload to a listening Lua payload.
#
#   .\_test\send_bin.ps1 -Ip 192.168.5.33 -File ..\payload\goldhen.bin
#
# Used with afterglow's mode = "listen": the Lua payload sits on port 9020 and
# hands whatever arrives to the ring 0 loader.

param(
    [Parameter(Mandatory = $true)][string]$Ip,
    [Parameter(Mandatory = $true)][string]$File,
    [int]$Port = 9020,
    [int]$Wait = 5
)

$ErrorActionPreference = "Stop"
if (-not [System.IO.Path]::IsPathRooted($File)) { $File = Join-Path (Get-Location) $File }
$File = [System.IO.Path]::GetFullPath($File)
if (-not (Test-Path $File)) { throw "payload not found: $File" }

$bytes = [System.IO.File]::ReadAllBytes($File)
"target : ${Ip}:${Port}"
"payload: $File ($($bytes.Length) bytes)"

$client = New-Object System.Net.Sockets.TcpClient
$client.NoDelay = $true
$client.Connect($Ip, $Port)
$stream = $client.GetStream()

$chunk = 32KB
$sent = 0
while ($sent -lt $bytes.Length) {
    $n = [Math]::Min($chunk, $bytes.Length - $sent)
    $stream.Write($bytes, $sent, $n)
    $sent += $n
    if ($sent % (256KB) -eq 0 -or $sent -eq $bytes.Length) {
        "  sent $sent / $($bytes.Length)"
    }
}
$stream.Flush()

# half-close so the Lua side sees end of stream and stops reading
try { $client.Client.Shutdown([System.Net.Sockets.SocketShutdown]::Send) } catch { }

"waiting $Wait s for the console..."
Start-Sleep -Seconds $Wait

# drain anything the Lua side prints back before it closes
try {
    $stream.ReadTimeout = 500
    $buf = New-Object byte[] 4096
    while ($true) {
        $r = $stream.Read($buf, 0, $buf.Length)
        if ($r -le 0) { break }
        [System.Text.Encoding]::ASCII.GetString($buf, 0, $r)
    }
} catch { }

$client.Close()
"done"
