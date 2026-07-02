<#
Example IIS reverse proxy setup for Grafana.

Prerequisites:
- IIS installed
- URL Rewrite installed
- Application Request Routing (ARR) installed
- A certificate already installed in LocalMachine\My

Run from an elevated PowerShell prompt. Replace the variables below first.
#>

$SiteName = "Radius Grafana"
$HostName = "radius.example.com"
$GrafanaTarget = "http://127.0.0.1:3000"
$CertificateThumbprint = "REPLACE_WITH_CERT_THUMBPRINT"
$PhysicalPath = "C:\inetpub\radius-grafana"

Import-Module WebAdministration

if (-not (Test-Path $PhysicalPath)) {
    New-Item -ItemType Directory -Path $PhysicalPath | Out-Null
}

if (-not (Test-Path "IIS:\Sites\$SiteName")) {
    New-Website -Name $SiteName -PhysicalPath $PhysicalPath -Port 80 -HostHeader $HostName | Out-Null
}

if (-not (Get-WebBinding -Name $SiteName -Protocol https -ErrorAction SilentlyContinue)) {
    New-WebBinding -Name $SiteName -Protocol https -Port 443 -HostHeader $HostName -SslFlags 1
}

$Binding = Get-WebBinding -Name $SiteName -Protocol https
$Binding.AddSslCertificate($CertificateThumbprint, "My")

# Enable ARR proxy support.
Set-WebConfigurationProperty `
    -PSPath "MACHINE/WEBROOT/APPHOST" `
    -Filter "system.webServer/proxy" `
    -Name "enabled" `
    -Value "True"

$WebConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <rewrite>
      <rules>
        <rule name="Redirect HTTP to HTTPS" enabled="true" stopProcessing="true">
          <match url="(.*)" />
          <conditions>
            <add input="{HTTPS}" pattern="off" ignoreCase="true" />
          </conditions>
          <action type="Redirect" url="https://{HTTP_HOST}/{R:1}" redirectType="Permanent" />
        </rule>
        <rule name="Grafana Reverse Proxy" stopProcessing="true">
          <match url="(.*)" />
          <action type="Rewrite" url="$GrafanaTarget/{R:1}" />
          <serverVariables>
            <set name="HTTP_X_FORWARDED_PROTO" value="https" />
            <set name="HTTP_X_FORWARDED_HOST" value="{HTTP_HOST}" />
          </serverVariables>
        </rule>
      </rules>
    </rewrite>
  </system.webServer>
</configuration>
"@

Set-Content -Path (Join-Path $PhysicalPath "web.config") -Value $WebConfig -Encoding UTF8

Write-Host "IIS reverse proxy created for https://$HostName -> $GrafanaTarget"
Write-Host "Confirm URL Rewrite and ARR are installed, then browse to https://$HostName"
