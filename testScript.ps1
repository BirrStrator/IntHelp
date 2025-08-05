# Ensure script is run as Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "You must run this script as an Administrator!"
    exit 1
}

function RUserDesktop {
    # This function refreshes the desktop for the currently logged-in interactive user.
    # It works even when the script is run as SYSTEM (e.g., via Intune) by creating a temporary
    # scheduled task that runs the refresh command in the user's session.
    try {
        # Find the explorer.exe process to identify the user. Requires elevation.
        $explorerProcess = Get-Process -Name explorer -IncludeUserName -ErrorAction SilentlyContinue
        if (-not $explorerProcess) {
            Write-Warning "No active user session found. A desktop refresh cannot be performed."
            return
        }
        # In case of multiple sessions (e.g., RDP), target the first one found.
        $userName = $explorerProcess[0].UserName

        $taskName = "Temp-DesktopRefresh-$(Get-Random -Maximum 99999)"
        $taskAction = New-ScheduledTaskAction -Execute "rundll32.exe" -Argument "user32.dll,UpdatePerUserSystemParameters"
        $taskPrincipal = New-ScheduledTaskPrincipal -UserID $userName -LogonType Interactive
        $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 1)

        Write-Output "Attempting to refresh desktop for user '$userName'..."
        Register-ScheduledTask -TaskName $taskName -Action $taskAction -Principal $taskPrincipal -Settings $taskSettings -Force -ErrorAction Stop | Out-Null
        Start-ScheduledTask -TaskName $taskName
        
        # Give the task a moment to complete before removing it.
        Start-Sleep -Seconds 3
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        
        Write-Output "Desktop refresh command sent."
    } catch {
        Write-Warning "Could not automatically refresh the desktop. A logoff or restart may be required to see icon changes. Error: $_"
    }
}
# Alle Verknüpfungen mit dem Namen "DATEVasp" auf allen Benutzer-Desktops auf "hidden" setzen
Write-Output "Hiding existing 'DATEVasp starten.lnk' and 'DATEVasp starten.url' shortcuts on all desktops..."
$desktopPaths = @(
    "$env:PUBLIC\Desktop"
)

# Alle Benutzerprofile durchsuchen
Get-ChildItem "$env:SystemDrive\Users" -Directory | ForEach-Object {
    $userDesktop = Join-Path -Path $_.FullName -ChildPath "Desktop"
    if (Test-Path $userDesktop) {
        $desktopPaths += $userDesktop
    }
}

foreach ($desktop in $desktopPaths) {
    # Find all .lnk and .url files with the specified name to hide them.
    Get-ChildItem -Path $desktop -Filter 'DATEVasp starten.*' -Force -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.lnk', '.url' } | ForEach-Object {
        # Setze das Hidden-Attribut
        $_.Attributes = $_.Attributes -bor [System.IO.FileAttributes]::Hidden
    }
}
# Icon für die Internetverknüpfung festlegen
$localIconPath = "C:\Program Files (x86)\DATEV\PROGRAMM\ASPZugangspaket\Resources\Datev-Cloud.ico"
$iconDownloadUrl = "https://github.com/BirrStrator/IntHelp/raw/main/DATEV-Cloud.ico"

if (-Not (Test-Path $localIconPath)) {
    Write-Output "Custom icon not found. Attempting to download..."
    $iconDir = Split-Path $localIconPath -Parent
    if (-Not (Test-Path $iconDir)) {
        New-Item -Path $iconDir -ItemType Directory -Force | Out-Null
    }
    try {
        Invoke-WebRequest -Uri $iconDownloadUrl -OutFile $localIconPath -UseBasicParsing -ErrorAction Stop
        Write-Output "Icon downloaded successfully to $localIconPath"
    } catch {
        Write-Error "Failed to download icon: $_"
        # Continue without the custom icon
        $localIconPath = $null
    }
}

# Internetverknüpfung auf dem Public Desktop erstellen
$publicDesktop = "$env:PUBLIC\Desktop"
$linkPath = Join-Path $publicDesktop "DATEVasp starten.url"

if (Test-Path $linkPath) {
    Write-Output "Shortcut '$($linkPath)' already exists. Ensuring it is visible."
    # Ensure the shortcut is not hidden, in case the cleanup loop above hid it.
    (Get-Item $linkPath).Attributes = (Get-Item $linkPath).Attributes -band (-bnot [System.IO.FileAttributes]::Hidden)
} else {
    Write-Output "Creating 'DATEVasp starten.url' shortcut on Public Desktop..."
    $linkContent = @"
[InternetShortcut]
URL=https://start.asp.datev-cs.de
"@
    if ($localIconPath -and (Test-Path $localIconPath)) {
        $linkContent += "`r`nIconFile=$localIconPath`r`nIconIndex=0"
    }
    # Create the .url file directly. Using WScript.Shell is not necessary for .url files.
    Set-Content -Path $linkPath -Value $linkContent -Encoding ASCII -Force
}

Write-Output "Refreshing desktop to apply changes..."
RUserDesktop

Write-Output "Script finished."
