# Alle Verknüpfungen mit dem Namen "DATEVasp" auf allen Benutzer-Desktops auf "hidden" setzen
$desktopPaths = @(
    "$env:PUBLIC\Desktop"
)

# Alle Benutzerprofile durchsuchen
Get-ChildItem 'C:\Users' -Directory | ForEach-Object {
    $userDesktop = "$($_.FullName)\Desktop"
    if (Test-Path $userDesktop) {
        $desktopPaths += $userDesktop
    }
}

foreach ($desktop in $desktopPaths) {
    Get-ChildItem -Path $desktop -Filter 'DATEVasp*.lnk' -Force -ErrorAction SilentlyContinue | ForEach-Object {
        # Setze das Hidden-Attribut
        $_.Attributes = $_.Attributes -bor [System.IO.FileAttributes]::Hidden
    }
}
# Icon für die Internetverknüpfung festlegen
$iconPath1 = "C:\Program Files (x86)\DATEV\PROGRAMM\ASPZugangspaket\Resources\Datev-Cloud.ico"
$iconDownloadUrl = "https://github.com/BirrStrator/IntHelp/raw/main/DATEV-Cloud.ico"

if (-Not (Test-Path $iconPath1)) {
    $iconDir = Split-Path $iconPath1
    if (-Not (Test-Path $iconDir)) {
        New-Item -Path $iconDir -ItemType Directory -Force | Out-Null
    }
    Invoke-WebRequest -Uri $iconDownloadUrl -OutFile $iconPath1 -UseBasicParsing
}
$iconPath = $iconPath1

# IconLocation zur .url-Datei hinzufügen
Add-Content -Path $linkPath -Value "IconFile=$iconPath`r`nIconIndex=0"
# Internetverknüpfung auf dem Public Desktop erstellen
$publicDesktop = "$env:PUBLIC\Desktop"
$linkPath = Join-Path $publicDesktop "DATEV Online.url"
$linkContent = @"
[InternetShortcut]
URL=https://start.asp.datev-cs.de
"@
Set-Content -Path $linkPath -Value $linkContent -Encoding ASCII
