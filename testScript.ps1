# Ensure script is run as Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "You must run this script as an Administrator!"
    exit 1
}

# Alle Verknüpfungen mit dem Namen "DATEVasp" auf allen Benutzer-Desktops auf "hidden" setzen
Write-Output "Hiding existing 'DATEVasp starten.lnk' and 'DATEVasp starten.url' shortcuts on all user desktops..."
$desktopPaths = @()

# Alle Benutzerprofile durchsuchen
 # Exclude the 'Public' user profile from the cleanup loop
Get-ChildItem "$env:SystemDrive\Users" -Directory | Where-Object { $_.Name -ne 'Public' } | ForEach-Object {
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

# Set permissions on the Public Desktop to ensure all users can access items placed there.
Write-Output "Setting 'Modify' permissions for 'Authenticated Users' on the Public Desktop folder..."
try {
    $publicDesktopPath = "$env:PUBLIC\Desktop"
    if (Test-Path $publicDesktopPath) {
        $acl = Get-Acl -Path $publicDesktopPath
        # Using the well-known SID for "Authenticated Users" (S-1-5-11) is language-independent and more robust.
        $sid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")
        $permissions = "Modify" # Includes read, write, execute, and delete.
        $inheritance = "ContainerInherit, ObjectInherit"
        $propagation = "None"
        $type = "Allow"
        
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, $permissions, $inheritance, $propagation, $type)
        $acl.SetAccessRule($rule)
        Set-Acl -Path $publicDesktopPath -AclObject $acl -ErrorAction Stop
    }
} catch {
    Write-Error "Failed to set permissions on Public Desktop: $_"
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

Write-Output "Script finished."
