## Linux privilege Escalation

* Automated enumeration scripts

```
// https://github.com/diego-treitos/linux-smart-enumeration.git
./lse.sh > output.txt

// https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
linpeas -a > /dev/shm/linpeas.txt
```

* Enumerate General information

```
  # Part of too many groups? Find out all the files you've access to
  for i in $(groups); do echo "=======$i======"; find / -group $i 2>/dev/null | grep -v "proc" >> allfiles; done

  # Look what the user was up to
  less .bash_history
  less mysql_history
```

* Enumerating Users

```
id
whoami
cat /etc/passwd
```

* Get System information

```
cat /etc/issue
cat /etc/*-release
uname -a
```

* Check bash History

```
cat ~/.bash_history
```

* Enumerating Running Processes and Services

```
ps axuww
#ww for wider output
```

* Enumerating Networking Information

```
ip a
/sbin/route
netstat -anp
ss -anp
```

* Enumerating Firewall Status and Rules

```
Root privileges are required to list firewall rules with iptables
Can search for firewall dump configuration as user
		-Command: iptables-save
```

* Enumerating Scheduled Tasks

```
ls -lah /etc/cron*
cat /etc/crontab
grep "CRON" /var/log/cron.log
```

* Enumerating Installed Applications

```
Debian
    dpkg -l
Redhat
    rpm
```

* Enumerating Readable/Writable Files and Directories

```
RUN SUID3NUM to look for SUID bits with colors in python script
find / -writable -type d 2>/dev/null
find / -writable -type f 2>/dev/null
```

* Enumerating Unmounted Disks

```
/bin/lsblk
cat /etc/fstab
mount
```

* Enumerating Kernel Modules

```
// list modules
lsmod

// get details
/sbin/modinfo libata
```

* Enumerating Binaries That AutoElevate

```
find / -perm -u=s -type f 2>/dev/null
```

* Enumerate UID Spoofing

```
Find a file that might have creds but locked for a user that has UUID of '1014' who has rwx permissions on file
Add local user to machine through adduser command 
Change added user to UUID to '1014' and switch to that user and access the file
Command to change specified UUID of new user to '1014'
Command: sudo sed -i -e 's/1001/1014/g' /etc/passwd
```

* Password Policy

```
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```

* Linux PrivEsc Guide

```
// https://noobsec.net/
// https://book.hacktricks.xyz/linux-unix/privilege-escalation
```