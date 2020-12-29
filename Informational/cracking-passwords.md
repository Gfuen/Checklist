## Passwords

```
use rockyou.txt in /usr/share/wordlists for bruteforcing
DONT FORGET TO USE USER AS PASSWORD when bruteforcing OR TO USE NULL AS PASSWORD
if not use custom wordlist
-January
-February
-...
-Autumn
-...
Add year to entries
-Command: for i in $(cat custom_wordlist.txt); do echo $i; echo ${i}2019; echo ${i}2020; done
Add a bang if needed
-Command: for i in $(cat test1.txt); do echo $i; echo ${i}\!; done > test3.txt  
```

## Hashes

```
Use following website to crack unsalted hashes
    // https://crackstation.net/
Check hash format for reference when trying to crack
    // https://hashcat.net/wiki/doku.php?id=example_hashes

hash-identifier [hash]
john hashes.txt
hashcat -m 500 -a 0 -o output.txt –remove hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 1000 dump.txt -o output.txt --remove -a 3 ?u?l?l?d?d?d?d
    Brute force crack for NTLM hashes with an uppercase, lowercase, lowercase, and 4 digit mask
List of hash types and examples for hashcat https://hashcat.net/wiki/doku.php?id=example_hashes 
// https://hashkiller.co.uk has a good repo of already cracked MD5 and NTLM hashes
```