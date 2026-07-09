param(
    [string]$TaskName = "UniFi Radius Remediation",
    [string]$Distro = "Ubuntu",
    [string]$WslProjectPath = "/opt/radius"
)

$scriptPath = Join-Path $PSScriptRoot "register-radius-wsl-task.ps1"
& $scriptPath -TaskName $TaskName -Distro $Distro -WslProjectPath $WslProjectPath
