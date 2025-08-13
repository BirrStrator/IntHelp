# Sicherstellen, dass das Skript als Administrator ausgeführt wird
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Sie muessen dieses Skript als Administrator ausfuehren!"
    exit 1
}

# --- ROBUSTE DEINSTALLATION DES DATEVASP ZUGANGSPAKETS ---
Write-Output "Versuche, das DATEVasp Zugangspaket zu deinstallieren..."
$appName = "DATEVasp Zugangspaket"
$uninstallString = $null

# Pfade zur Registry, wo Deinstallations-Informationen gespeichert sind
$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

foreach ($path in $regPaths) {
    # Suche nach dem Programm in der Registry
    $regKey = Get-ChildItem -Path $path | ForEach-Object { Get-ItemProperty -Path $_.PSPath } | Where-Object { $_.DisplayName -like "*$appName*" }
    
    if ($regKey) {
        $uninstallString = $regKey.UninstallString
        break # Beende die Schleife, wenn der Eintrag gefunden wurde
    }
}

if ($uninstallString) {
    Write-Output "Deinstallationsbefehl gefunden: $uninstallString"
    
    # Argumente für eine stille Deinstallation vorbereiten
    $uninstallArgs = ""
    if ($uninstallString -like "msiexec.exe*") {
        # MSI-Paket: Stille Deinstallation erzwingen
        $productCode = ($uninstallString -split " ")[1].Replace("/I", "").Replace("/X", "")
        $uninstallString = "msiexec.exe"
        $uninstallArgs = "/x $productCode /qn /norestart"
    } else {
        # EXE-Paket: Verwende die spezifischen stillen Schalter
        # Extrahiere den reinen Pfad zur Exe, falls er in Anführungszeichen steht
        if ($uninstallString.StartsWith('"')) {
            $uninstallString = $uninstallString.Split('"')[1]
        }
        $uninstallArgs = "/uninstall /quiet" # Spezifische Schalter laut Anforderung
    }

    try {
        Write-Output "Starte Deinstallation mit Befehl: `"$uninstallString`" und Argumenten: `"$uninstallArgs`""
        Start-Process -FilePath $uninstallString -ArgumentList $uninstallArgs -Wait -ErrorAction Stop
        Write-Output "Deinstallation erfolgreich gestartet. Der Prozess laeuft im Hintergrund."
    } catch {
        Write-Error "Fehler bei der Ausfuehrung des Deinstallationsbefehls: $($_)"
    }

} else {
    Write-Output "Das Paket '$appName' wurde nicht in der Registry gefunden. Ueberspringe Deinstallation."
}


# Alle Verknüpfungen mit dem Namen "DATEVasp" auf allen Benutzer-Desktops auf "hidden" setzen
Write-Output "Verstecke existierende 'DATEVasp starten.lnk' und 'DATEVasp starten.url' Verknuepfungen auf allen Benutzer-Desktops..."
$desktopPaths = @()

# Alle Benutzerprofile durchsuchen
# Das 'Public'-Benutzerprofil von der Bereinigungsschleife ausschließen
Get-ChildItem "$env:SystemDrive\Users" -Directory | Where-Object { $_.Name -ne 'Public' } | ForEach-Object {
    $userDesktop = Join-Path -Path $_.FullName -ChildPath "Desktop"
    if (Test-Path $userDesktop) {
        $desktopPaths += $userDesktop
    }
}

foreach ($desktop in $desktopPaths) {
    # Alle .lnk- und .url-Dateien mit dem angegebenen Namen finden, um sie zu verstecken.
    Get-ChildItem -Path $desktop -Filter 'DATEVasp starten.*' -Force -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.lnk', '.url' } | ForEach-Object {
        # Setze das Hidden-Attribut
        $_.Attributes = $_.Attributes -bor [System.IO.FileAttributes]::Hidden
    }
}

# Registry-Schlüssel für die aktuelle Maschine setzen (gilt für alle Benutzer, auch zukünftige)
$regPath  = "HKLM:\SOFTWARE\WOW6432Node\DATEV-CS\ASPZugangspaket"
$propName = "NextReady"

try {
    if (-not (Test-Path $regPath)) {
        # Schlüssel erstellen und Wert auf 1 setzen
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
    Write-Error "Fehler beim Erstellen des Registry-Schluessels oder Setzen der Eigenschaft: $($_)"
    exit 1
}

# Notwendige Zertifikate herunterladen und installieren
Write-Output "Installiere notwendige Zertifikate..."
$certificatesToInstall = @(
    @{
        Url = "https://cacerts.digicert.com/ThawteTLSRSACAG1.crt"
        Store = "CA" # Zwischenzertifizierungsstellen
    },
    @{
        Url = "https://cacerts.digicert.com/DigiCertGlobalRootG2.crt"
        Store = "Root" # Vertrauenswuerdige Stammzertifizierungsstellen
    }
)

foreach ($certInfo in $certificatesToInstall) {
    $certUrl = $certInfo.Url
    $certStorePath = "Cert:\LocalMachine\$($certInfo.Store)"
    $fileName = [System.IO.Path]::GetFileName($certUrl)
    $tempFilePath = Join-Path $env:TEMP $fileName

    try {
        Write-Output "Verarbeite Zertifikat von $certUrl"

        # Herunterladen
        Invoke-WebRequest -Uri $certUrl -OutFile $tempFilePath -UseBasicParsing -ErrorAction Stop
        
        # Installieren
        Import-Certificate -FilePath $tempFilePath -CertStoreLocation $certStorePath -ErrorAction Stop
        Write-Output "Zertifikat erfolgreich im Store '$($certInfo.Store)' installiert."

    } catch {
        Write-Error "Fehler bei der Installation des Zertifikats von $certUrl : $($_)"
    } finally {
        # Temporäre Datei bereinigen
        if (Test-Path $tempFilePath) {
            Remove-Item $tempFilePath -Force
        }
    }
}


# Icon für die Internetverknüpfung festlegen
$localIconPath = "C:\Program Files (x86)\DATEV\PROGRAMM\ASPZugangspaket\Resources\Datev-Cloud.ico"
$iconDownloadUrl = "https://github.com/BirrStrator/IntHelp/raw/main/DATEV-Cloud.ico"

if (-Not (Test-Path $localIconPath)) {
    Write-Output "Benutzerdefiniertes Icon nicht gefunden. Es wird versucht, es herunterzuladen..."
    $iconDir = Split-Path $localIconPath -Parent
    if (-Not (Test-Path $iconDir)) {
        New-Item -Path $iconDir -ItemType Directory -Force | Out-Null
    }
    try {
        Invoke-WebRequest -Uri $iconDownloadUrl -OutFile $localIconPath -UseBasicParsing -ErrorAction Stop
        Write-Output "Icon erfolgreich nach $localIconPath heruntergeladen"
    } catch {
        Write-Error "Fehler beim Herunterladen des Icons: $($_)"
        # Ohne benutzerdefiniertes Icon fortfahren
        $localIconPath = $null
    }
}

# Berechtigungen für den öffentlichen Desktop festlegen, um sicherzustellen, dass alle Benutzer auf die dort platzierten Elemente zugreifen können.
Write-Output "Setze 'Aendern'-Berechtigungen fuer 'Authentifizierte Benutzer' auf dem oeffentlichen Desktop-Ordner..."
try {
    $publicDesktopPath = "$env:PUBLIC\Desktop"
    if (Test-Path $publicDesktopPath) {
        $acl = Get-Acl -Path $publicDesktopPath
        # Die Verwendung der bekannten SID für "Authentifizierte Benutzer" (S-1-5-11) ist sprachunabhängig und robuster.
        $sid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")
        $permissions = "Modify" # Beinhaltet Lesen, Schreiben, Ausführen und Löschen.
        $inheritance = "ContainerInherit, ObjectInherit"
        $propagation = "None"
        $type = "Allow"
        
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, $permissions, $inheritance, $propagation, $type)
        $acl.SetAccessRule($rule)
        Set-Acl -Path $publicDesktopPath -AclObject $acl -ErrorAction Stop
    }
} catch {
    Write-Error "Fehler beim Setzen der Berechtigungen auf dem oeffentlichen Desktop: $($_)"
}

# === ERSTE VERKNÜPFUNG ERSTELLEN ===
$publicDesktop = "$env:PUBLIC\Desktop"
$linkPath1 = Join-Path $publicDesktop "DATEVasp starten.url"

if (Test-Path $linkPath1) {
    Write-Output "Verknuepfung '$($linkPath1)' existiert bereits. Stelle sicher, dass sie sichtbar ist."
    # Sicherstellen, dass die Verknüpfung nicht versteckt ist, falls die obige Bereinigungsschleife sie versteckt hat.
    (Get-Item $linkPath1).Attributes = (Get-Item $linkPath1).Attributes -band (-bnot [System.IO.FileAttributes]::Hidden) -band (-bnot [System.IO.FileAttributes]::System)
} else {
    Write-Output "Erstelle 'DATEVasp starten.url' Verknuepfung auf dem oeffentlichen Desktop..."
    
    $linkContent = @"
[InternetShortcut]
URL=https://start.asp.datev-cs.de
"@

    if ($localIconPath -and (Test-Path $localIconPath)) {
        $iconContent = "`r`nIconFile=$localIconPath`r`nIconIndex=0"
        $linkContent = $linkContent + $iconContent
    }

    Set-Content -Path $linkPath1 -Value $linkContent -Encoding ASCII -Force
}


# === ZWEITE VERKNÜPFUNG ERSTELLEN (NUR WENN NICHT VORHANDEN) ===
$linkPath2 = Join-Path $publicDesktop "DATEVasp Mobiler Arbeitsplatz starten.url"

if (-not (Test-Path $linkPath2)) {
    Write-Output "Erstelle 'DATEVasp Mobiler Arbeitsplatz starten.url' Verknuepfung auf dem oeffentlichen Desktop..."
    
    $linkContent = @"
[InternetShortcut]
URL=https://map.datevasp.de
"@

    if ($localIconPath -and (Test-Path $localIconPath)) {
        $iconContent = "`r`nIconFile=$localIconPath`r`nIconIndex=0"
        $linkContent = $linkContent + $iconContent
    }

    Set-Content -Path $linkPath2 -Value $linkContent -Encoding ASCII -Force
} else {
    Write-Output "Verknuepfung '$($linkPath2)' existiert bereits. Keine Aktion erforderlich."
}

Write-Output "Skript beendet."
