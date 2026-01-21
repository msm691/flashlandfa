@echo off
setlocal EnableDelayedExpansion
color 0B
title SCANNER FORENSIC - MADE BY FLGZ

net session >nul 2>&1
if %errorLevel% neq 0 (
    color 4F
    echo [!] ERREUR : Lancez ce script en ADMINISTRATEUR.
    pause
    exit
)

set "LOGFILE=%USERPROFILE%\Desktop\scanlog.txt"
if exist "%LOGFILE%" del "%LOGFILE%"

echo GENERATION DU RAPPORT V13... PATIENTEZ...

echo ############################################################################## > "%LOGFILE%"
echo #              RAPPORT FORENSIC - V13 (USB CORRIGE)                          # >> "%LOGFILE%"
echo ############################################################################## >> "%LOGFILE%"
echo. >> "%LOGFILE%"
echo  DATE   : %DATE% %TIME% >> "%LOGFILE%"
echo  CIBLE  : %USERNAME% sur %COMPUTERNAME% >> "%LOGFILE%"
echo. >> "%LOGFILE%"

echo [+] Analyse Defender...
echo ------------------------------------------------------------------------------ >> "%LOGFILE%"
echo [ 1 ] EXCLUSIONS WINDOWS DEFENDER >> "%LOGFILE%"
echo ------------------------------------------------------------------------------ >> "%LOGFILE%"
powershell -Command "$x = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath -ErrorAction SilentlyContinue; if ($x) { $x | Out-String -Width 4096 } else { Write-Output 'Aucune exclusion detectee.' }" >> "%LOGFILE%"
echo. >> "%LOGFILE%"

echo [+] Analyse Drivers...
echo ------------------------------------------------------------------------------ >> "%LOGFILE%"
echo [ 2 ] HISTORIQUE INSTALLATION SERVICES (Event 7045) >> "%LOGFILE%"
echo ------------------------------------------------------------------------------ >> "%LOGFILE%"
powershell -Command "$e = Get-WinEvent -FilterHashtable @{LogName='System';ID=7045} -ErrorAction SilentlyContinue | Select-Object -First 20 TimeCreated, @{n='ServiceName';e={$_.Properties[0].Value}}, @{n='ImagePath';e={$_.Properties[1].Value}}; if ($e) { $e | Format-Table -AutoSize | Out-String -Width 4096 } else { Write-Output 'Aucun historique recent.' }" >> "%LOGFILE%"
echo. >> "%LOGFILE%"

echo [+] Recherche Dossiers...
echo ------------------------------------------------------------------------------ >> "%LOGFILE%"
echo [ 3 ] RECHERCHE CIBLEE (Dossiers Suspects) >> "%LOGFILE%"
echo ------------------------------------------------------------------------------ >> "%LOGFILE%"
if exist "%appdata%\Eulen" echo [!] DETECTE : AppData\Roaming\Eulen >> "%LOGFILE%"
if exist "%appdata%\Skript" echo [!] DETECTE : AppData\Roaming\Skript >> "%LOGFILE%"
if exist "%appdata%\RedEngine" echo [!] DETECTE : AppData\Roaming\RedEngine >> "%LOGFILE%"
if exist "C:\RedEngine" echo [!] DETECTE : C:\RedEngine >> "%LOGFILE%"
if exist "%appdata%\CitizenFX" echo [-] Dossier CitizenFX (Present) >> "%LOGFILE%"
echo Scan dossiers termine. >> "%LOGFILE%"
echo. >> "%LOGFILE%"

echo [+] Analyse Pare-Feu...
echo ------------------------------------------------------------------------------ >> "%LOGFILE%"
echo [ 4 ] REGLES PARE-FEU (Blocage Sortant) >> "%LOGFILE%"
echo ------------------------------------------------------------------------------ >> "%LOGFILE%"
powershell -Command "$f = Get-NetFirewallRule | Where-Object { $_.Action -eq 'Block' -and $_.Direction -eq 'Outbound' -and ($_.DisplayName -match 'FiveM' -or $_.DisplayName -match 'GTA' -or $_.DisplayName -match 'Block') } | Select-Object DisplayName, Description; if ($f) { $f | Format-Table -AutoSize | Out-String -Width 4096 } else { Write-Output 'Rien de suspect.' }" >> "%LOGFILE%"
echo. >> "%LOGFILE%"

echo [+] Analyse PowerShell...
echo ------------------------------------------------------------------------------ >> "%LOGFILE%"
echo [ 5 ] HISTORIQUE POWERSHELL >> "%LOGFILE%"
echo ------------------------------------------------------------------------------ >> "%LOGFILE%"
powershell -Command "$h = Get-Content (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue | Select-Object -Last 20; if ($h) { $h | Out-String -Width 4096 } else { Write-Output 'Historique vide.' }" >> "%LOGFILE%"
echo. >> "%LOGFILE%"

echo [+] Analyse Crash Dumps...
echo ------------------------------------------------------------------------------ >> "%LOGFILE%"
echo [ 6 ] RAPPORTS DE CRASH >> "%LOGFILE%"
echo ------------------------------------------------------------------------------ >> "%LOGFILE%"
powershell -Command "$w = Get-ChildItem -Path 'C:\ProgramData\Microsoft\Windows\WER\ReportArchive' -Recurse -Filter 'AppCrash_*' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 10 LastWriteTime, Name; if ($w) { $w | Format-Table -AutoSize | Out-String -Width 4096 } else { Write-Output 'Aucun crash recent.' }" >> "%LOGFILE%"
echo. >> "%LOGFILE%"

echo [+] Analyse Services Actifs...
echo ------------------------------------------------------------------------------ >> "%LOGFILE%"
echo [ 7 ] SERVICES ACTIFS NON-MICROSOFT >> "%LOGFILE%"
echo ------------------------------------------------------------------------------ >> "%LOGFILE%"
powershell -Command "$s = Get-WmiObject Win32_Service | Where-Object { $_.DisplayName -notmatch 'Microsoft|Windows|Intel|NVIDIA|AMD|Realtek|Google|Steam|Rockstar|Sons|Sound|Mozilla|Edge|Corsair|Logitech|Razer|Bonjour' -and $_.State -eq 'Running' } | Select-Object DisplayName, Name, PathName; if ($s) { $s | Format-Table -AutoSize | Out-String -Width 4096 } else { Write-Output 'Rien de suspect actif.' }" >> "%LOGFILE%"
echo. >> "%LOGFILE%"

echo [+] Analyse MuiCache...
echo ------------------------------------------------------------------------------ >> "%LOGFILE%"
echo [ 8 ] MUICACHE (Noms Executables) >> "%LOGFILE%"
echo ------------------------------------------------------------------------------ >> "%LOGFILE%"
powershell -Command "$m = Get-ItemProperty 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache' -ErrorAction SilentlyContinue | Select-Object -Property * | ForEach-Object { $_.PSObject.Properties | Where-Object { $_.Name -ne 'PSPath' -and $_.Name -ne 'PSParentPath' -and $_.Name -ne 'PSChildName' } } | Where-Object { $_.Name -match '.exe' -and $_.Name -notmatch 'System32|Program Files' } | Select-Object Name, Value; if ($m) { $m | Format-Table -AutoSize | Out-String -Width 4096 } else { Write-Output 'Clean.' }" >> "%LOGFILE%"
echo. >> "%LOGFILE%"

echo [+] Analyse Reseau...
echo ------------------------------------------------------------------------------ >> "%LOGFILE%"
echo [ 9 ] CONNEXIONS ACTIVES >> "%LOGFILE%"
echo ------------------------------------------------------------------------------ >> "%LOGFILE%"
netstat -ano | findstr "ESTABLISHED" | findstr /V "127.0.0.1 192.168" >> "%LOGFILE%"
echo. >> "%LOGFILE%"

echo [+] Analyse USB...
echo ------------------------------------------------------------------------------ >> "%LOGFILE%"
echo [ 10 ] HISTORIQUE CLES USB (Sans Erreur) >> "%LOGFILE%"
echo ------------------------------------------------------------------------------ >> "%LOGFILE%"
echo Note : Si cette liste est vide mais que la section 'REGISTRE' existe, >> "%LOGFILE%"
echo c'est que le joueur a nettoye manuellement son historique. >> "%LOGFILE%"
echo. >> "%LOGFILE%"

powershell -Command "$Path = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*' ; if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR') { Get-ItemProperty $Path -ErrorAction SilentlyContinue | Select-Object @{N='Nom';E={$_.FriendlyName}}, @{N='Serie';E={$_.PSChildName}} | Where-Object {$_.Nom -ne $null} | Format-Table -AutoSize | Out-String -Width 4096 } else { Write-Output '[!] ALERTE : REGISTRE USBSTOR SUPPRIME (CLEANER DETECTE)' }" >> "%LOGFILE%"
echo. >> "%LOGFILE%"

echo [+] Analyse FiveM...
echo ------------------------------------------------------------------------------ >> "%LOGFILE%"
echo [ 11 ] HOSTS ET INTEGRITE FIVEM >> "%LOGFILE%"
echo ------------------------------------------------------------------------------ >> "%LOGFILE%"
type C:\Windows\System32\drivers\etc\hosts | findstr /v "^#" >> "%LOGFILE%"
echo. >> "%LOGFILE%"
set "FIVEM_DATA=%localappdata%\FiveM\FiveM.app"
if exist "%FIVEM_DATA%" (
    if exist "%FIVEM_DATA%\d3d11.dll" echo [!] CRITIQUE : d3d11.dll detecte (Injection) >> "%LOGFILE%"
    if exist "%FIVEM_DATA%\dxgi.dll" echo [!] CRITIQUE : dxgi.dll detecte (Injection) >> "%LOGFILE%"
    if exist "%FIVEM_DATA%\dinput8.dll" echo [!] CRITIQUE : dinput8.dll detecte (Loader ASI) >> "%LOGFILE%"
    echo Plugins : >> "%LOGFILE%"
    dir "%FIVEM_DATA%\plugins" /b >> "%LOGFILE%" 2>nul
) else (
    echo [-] Dossier FiveM introuvable. >> "%LOGFILE%"
)
echo. >> "%LOGFILE%"

echo [+] Analyse Logs Execution...
echo ------------------------------------------------------------------------------ >> "%LOGFILE%"
echo [ 12 ] PREFETCH (48H) >> "%LOGFILE%"
echo ------------------------------------------------------------------------------ >> "%LOGFILE%"
powershell -Command "$p = Get-ChildItem -Path 'C:\Windows\Prefetch' -Filter '*.pf' -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-48) } | Sort-Object LastWriteTime -Descending | Select-Object -First 20 LastWriteTime, Name; if ($p) { $p | Format-Table -AutoSize | Out-String -Width 4096 } else { Write-Output 'Aucun prefetch recent.' }" >> "%LOGFILE%"

echo ------------------------------------------------------------------------------ >> "%LOGFILE%"
echo [ 13 ] BAM REGISTRE (Chemins Suspects) >> "%LOGFILE%"
echo ------------------------------------------------------------------------------ >> "%LOGFILE%"
powershell -Command "$b = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\*' | Select-Object -Property * | ForEach-Object { $_.PSObject.Properties | Where-Object { $_.Name -ne 'PSPath' -and $_.Name -ne 'PSParentPath' -and $_.Name -ne 'PSChildName' } | Select-Object Name } | Where-Object { $_.Name -match 'Temp|Downloads|Desktop' -or $_.Name -match 'E:|F:|G:' }; if ($b) { $b | Format-Table -AutoSize | Out-String -Width 4096 } else { Write-Output 'BAM clean.' }" >> "%LOGFILE%"
echo. >> "%LOGFILE%"

echo [+] Analyse Fichiers...
echo ------------------------------------------------------------------------------ >> "%LOGFILE%"
echo [ 14 ] DOWNLOADS ET TEMP >> "%LOGFILE%"
echo ------------------------------------------------------------------------------ >> "%LOGFILE%"
echo -> Downloads (24h) : >> "%LOGFILE%"
powershell -Command "Get-ChildItem -Path $env:USERPROFILE\Downloads -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-1) } | Select-Object LastWriteTime, Name, Length | Format-Table -AutoSize | Out-String -Width 4096" >> "%LOGFILE%"

echo ------------------------------------------------------------------------------ >> "%LOGFILE%"
echo [ 15 ] CACHE DNS >> "%LOGFILE%"
echo ------------------------------------------------------------------------------ >> "%LOGFILE%"
ipconfig /displaydns | findstr /I "cheat auth key fivem mega.nz discordapp eulen skript redengine blur susano .exe exe script tool" >> "%LOGFILE%"

cls
color 0A
echo ########################################################
echo #             SCAN V13 TERMINE (FIX FINAL)             #
echo ########################################################
echo.
echo RAPPORT : Sur le BUREAU (scanlog.txt)
echo.
pause