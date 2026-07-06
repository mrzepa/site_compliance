param(
    [string]$TaskName = "UniFi Radius Remediation",
    [string]$Distro = "Ubuntu",
    [string]$WslProjectPath = "/opt/radius"
)

$command = "cd '$WslProjectPath' && export PYTHONPATH=`$PWD && .venv/bin/python -m app.scheduler"
$action = New-ScheduledTaskAction -Execute "wsl.exe" -Argument "-d $Distro -- bash -lc `"$command`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Description "Runs the UniFi Radius remediation scheduler through WSL."
