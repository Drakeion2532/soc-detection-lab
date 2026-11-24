<#
.SYNOPSIS
    Harmless simulations of five common attacker techniques, for testing detections in this lab.

.DESCRIPTION
    Every step does something an attacker would do, but with a benign payload (whoami, notepad),
    and is undone afterwards. Nothing leaves the machine and nothing is downloaded.
    Every object it creates is named "SOCLab..." so it is easy to find and remove.

    Run ONLY on a machine you own, in an elevated PowerShell (Run as Administrator), with Sysmon and
    the Wazuh agent installed. Windows Defender may flag the encoded-command step: that is a detection
    working, not a problem.

.PARAMETER Technique
    Run one technique (T1059.001, T1053.005, T1136.001, T1547.001, T1033) or All (default).

.PARAMETER CleanupOnly
    Remove anything a previous, interrupted run left behind, then exit.

.EXAMPLE
    .\Invoke-LabSimulations.ps1
    .\Invoke-LabSimulations.ps1 -Technique T1547.001
    .\Invoke-LabSimulations.ps1 -CleanupOnly
#>
[CmdletBinding()]
param(
    [ValidateSet('All', 'T1059.001', 'T1053.005', 'T1136.001', 'T1547.001', 'T1033')]
    [string]$Technique = 'All',
    [switch]$CleanupOnly
)

$ErrorActionPreference = 'Stop'
$TaskName = 'SOCLabTask'
$UserName = 'SOCLabUser'
$RunKey   = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$RunValue = 'SOCLabRun'
$LogFile  = Join-Path $PSScriptRoot 'simulation-log.csv'

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-LabLog([string]$Id, [string]$Step) {
    # The timestamps let you line each simulation up with the alerts in Wazuh.
    $row = [pscustomobject]@{ utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); technique = $Id; step = $Step; host = $env:COMPUTERNAME }
    $row | Export-Csv -Path $LogFile -Append -NoTypeInformation
    Write-Host ("[{0}] {1,-10} {2}" -f $row.utc, $Id, $Step)
}

function Invoke-Cleanup {
    # native-command errors are expected when nothing is left to remove
    try { cmd.exe /c "schtasks /Delete /TN $TaskName /F >nul 2>&1" } catch { }
    if (Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue) { Remove-LocalUser -Name $UserName }
    Remove-ItemProperty -Path $RunKey -Name $RunValue -ErrorAction SilentlyContinue
    Write-Host 'Cleanup done: no SOCLab task, user or Run value remains.'
}

function Sim-T1059_001 {
    # PowerShell with an encoded command; the payload only runs whoami.
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('whoami'))
    Write-LabLog 'T1059.001' 'powershell -enc (payload: whoami)'
    powershell.exe -NoProfile -enc $enc | Out-Null
}

function Sim-T1053_005 {
    # A scheduled task that would open Notepad once a day; deleted straight away.
    Write-LabLog 'T1053.005' "schtasks /create $TaskName (notepad), then delete"
    schtasks.exe /Create /TN $TaskName /TR 'notepad.exe' /SC DAILY /ST 23:59 /F | Out-Null
    Start-Sleep -Seconds 5
    schtasks.exe /Delete /TN $TaskName /F | Out-Null
}

function Sim-T1136_001 {
    # A disabled local account with a random password; removed after a few seconds.
    $pw = (-join ((48..57) + (65..90) + (97..122) | Get-Random -Count 20 | ForEach-Object { [char]$_ })) + '!a1'
    Write-LabLog 'T1136.001' "net user $UserName /add, then delete"
    net.exe user $UserName $pw /add /active:no | Out-Null
    Start-Sleep -Seconds 5
    net.exe user $UserName /delete | Out-Null
}

function Sim-T1547_001 {
    # A Run key value pointing at Notepad (current user only); removed after a few seconds.
    Write-LabLog 'T1547.001' "Run key value $RunValue -> notepad.exe, then remove"
    Set-ItemProperty -Path $RunKey -Name $RunValue -Value "$env:WINDIR\System32\notepad.exe"
    Start-Sleep -Seconds 5
    Remove-ItemProperty -Path $RunKey -Name $RunValue
}

function Sim-T1033 {
    # The "where am I" burst: four read-only discovery commands from one parent process.
    Write-LabLog 'T1033' 'whoami /all, hostname, systeminfo, ipconfig /all'
    cmd.exe /c 'whoami /all >nul & hostname >nul & systeminfo >nul & ipconfig /all >nul'
}

if (-not (Test-Admin)) { throw 'Run this from an elevated PowerShell (Run as Administrator).' }
if ($CleanupOnly) { Invoke-Cleanup; return }

$all = [ordered]@{
    'T1059.001' = ${function:Sim-T1059_001}
    'T1053.005' = ${function:Sim-T1053_005}
    'T1136.001' = ${function:Sim-T1136_001}
    'T1547.001' = ${function:Sim-T1547_001}
    'T1033'     = ${function:Sim-T1033}
}
try {
    foreach ($id in $all.Keys) {
        if ($Technique -in @('All', $id)) { & $all[$id]; Start-Sleep -Seconds 10 }
    }
}
finally {
    Invoke-Cleanup
}
Write-Host "Done. Timestamps saved to $LogFile. Now find the matching alerts in Wazuh (rule IDs 100101-100106)."
