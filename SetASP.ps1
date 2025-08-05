# Ensure script is run as Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "You must run this script as an Administrator!"
    exit 1
}

# Set registry key for current machine (applies to all users, including future ones)
$regPath   = "HKLM:\SOFTWARE\WOW6432NODE\DATEV-CS\ASPZugangspaket"
$propName  = "NextReady"

try {
    if (-not (Test-Path $regPath)) {
        # Create key and set value to 1
        New-Item -Path $regPath -Force | Out-Null
        New-ItemProperty -Path $regPath -Name $propName -Value 1 -PropertyType DWORD -Force | Out-Null
    } else {
        $currentValue = (Get-ItemProperty -Path $regPath -Name $propName -ErrorAction SilentlyContinue).$propName
        if ($null -eq $currentValue) {
            New-ItemProperty -Path $regPath -Name $propName -Value 1 -PropertyType DWORD -Force | Out-Null
        } elseif ($currentValue -eq 0) {
            Set-ItemProperty -Path $regPath -Name $propName -Value 1
        }
    }
} catch {
    Write-Error "Failed to create registry key or set property: $_"
    exit 1
}
# Hide "DATEVasp starten" shortcut on user desktops
$shortcutName = "DATEVasp starten.url"
$userDesktop  = [Environment]::GetFolderPath("Desktop")
$shortcutPath = Join-Path $userDesktop $shortcutName

if (Test-Path $shortcutPath) {
    # Prüfen, ob es eine Internetverknüpfung (.url) oder eine normale Verknüpfung (.lnk) ist
    $extension = [IO.Path]::GetExtension($shortcutPath)
    if ($extension -ieq ".url") {
        Write-Output "Die Verknüpfung 'DATEVasp starten' existiert auf dem Userdesktop und ist eine Internetverknüpfung (.url)."
    } elseif ($extension -ieq ".lnk") {
        Write-Output "Die Verknüpfung 'DATEVasp starten' existiert auf dem Userdesktop und ist eine normale Verknüpfung (.lnk)."
    } else {
        Write-Output "Die Verknüpfung 'DATEVasp starten' existiert auf dem Userdesktop, Typ: $extension"
    }
} else {
    Write-Output "Die Verknüpfung 'DATEVasp starten' existiert NICHT auf dem Userdesktop."
}

# Nur normale Verknüpfung (.lnk) ausblenden, keine Internetverknüpfung (.url)
if (Test-Path $shortcutPath) {
    $extension = [IO.Path]::GetExtension($shortcutPath)
    if ($extension -ieq ".lnk") {
        Set-ItemProperty -Path $shortcutPath -Name Attributes -Value ([IO.FileAttributes]::Hidden)
    }
}

# Create shortcut on public desktop to Microsoft Edge with URL
$publicDesktop = "$env:PUBLIC\Desktop"
$edgePath      = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
if (-not (Test-Path $edgePath)) {
    $edgePath = "${env:ProgramFiles}\Microsoft\Edge\Application\msedge.exe"
}
$publicShortcut = Join-Path $publicDesktop "DATEVasp starten.lnk"

$WshShell = New-Object -ComObject WScript.Shell
$shortcut = $WshShell.CreateShortcut($publicShortcut)
$shortcut.TargetPath   = $edgePath
$shortcut.Arguments    = "https://start.asp.datev-cs.de"
$shortcut.IconLocation = "$edgePath,0"

# Set custom icon for the public desktop shortcut if available, otherwise download it
$customIcon = "C:\Program Files (x86)\DATEV\PROGRAMM\ASPZugangspaket\Resources\Datev-Cloud.ico"
$customIconDir = Split-Path $customIcon -Parent

if (-not (Test-Path $customIcon)) {
    if (-not (Test-Path $customIconDir)) {
        New-Item -Path $customIconDir -ItemType Directory -Force | Out-Null
    }
    $iconUrl = "https://github.com/BirrStrator/IntHelp/raw/main/DATEV-Cloud.ico"
    Invoke-WebRequest -Uri $iconUrl -OutFile $customIcon
}

if (Test-Path $customIcon) {
    $shortcut.IconLocation = $customIcon
}
$shortcut.Save()

