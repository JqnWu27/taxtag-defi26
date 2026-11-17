# Peak-memory measurement helper: runs a command and polls its (and its
# children's) working set until exit, reporting the peak in MB.
# Usage: powershell -File measure_mem.ps1 <label> <exe> <args...>
param([string]$Label, [string]$Exe, [Parameter(ValueFromRemainingArguments=$true)][string[]]$Rest)
if ($Rest -and $Rest.Count -gt 0) {
    # Start-Process joins the arguments with spaces, so an argument that
    # contains a space (a path, for example) must be quoted here.
    $quoted = $Rest | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }
    $p = Start-Process -FilePath $Exe -ArgumentList $quoted -PassThru -NoNewWindow
} else {
    $p = Start-Process -FilePath $Exe -PassThru -NoNewWindow
}
if (-not $p) { Write-Error "failed to start $Exe"; exit 1 }
$peak = 0
while (-not $p.HasExited) {
    try {
        $p.Refresh()
        $m = $p.PeakWorkingSet64
        if ($m -gt $peak) { $peak = $m }
    } catch {}
    Start-Sleep -Milliseconds 200
}
"{0} peak MB: {1}" -f $Label, [math]::Round($peak/1MB)
