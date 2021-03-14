## What happens when your type in "google.com" into a browser

1. Browser checks cache for response
2. Browsers asks OS for servers IP address
3. OS makes a DNS lookup and replies the ip address to the browser
4. Browser opens a TCP connection to server
5. Browser sends the HTTP request through TCP connection
6. Browser receives HTTP response and may close the TCP connection 
7. Browser Checks Response code (2XX or 3XX or 4XX?)
8. If cacheable response is stored in cache
9. Browser decodes response
10. Browser determines what to do with response
11. Browser renders response or offers download for unrecognized types


## What is DNS

DNS - Converts human readable domain names into IP addresses

## Difference between Autoritative DNS server and a Recursive DNS resolver

Recursive DNS resolver - beginning of DNS query

Authoritative Nameserver - end of DNS query

## How DNS works

DNS Recursor - server designed to receive queries from client machines through applications such as web browsers. Then is responsible for making additional requests to satisfy DNS query

Root Nameserver - root server is first step in translating human readable host names into IP addresses. Thought of like an index in a library that points to different racks of books

TLD Nameserver - Top level domain server can be thought of as a specific rack of books in a library. This nameserver is the next step in the search for a specific IP address and it hosts the last portion of a hostname (in example.com, the TLD server is "com")

Authoritative Nameserver - Final nameserver can be thought of as a dictionary on a rack of books in which a specific name can be translated into its definition. The authoritative nameserver is the last stop in the nameserver query. If the authoritative nameserver has access to the requested record it will return the IP address for the requested hostname back to the DNS Recursor that made the initial request

## DNS Lookup

1. User types into 'example.com' into web browser and the query travles to DNS recursive resolver
2. The resolver then queries a DNS root nameserver
3. The root server then responds to the resolver with the address of a Top Level Domain (TLD) DNS server (such as .com or .net) which stores the information for its domain. When searching for example.com our request is pointed toward the .com TLD.
4. The DNS resolver then makes a quest to the .com TLD
5. The TLD server then responds with the ip address of the domains nameserver, example.com
6. Lastly, the recursive resolver sends a query to the domains nameserver
7. The IP address for example.com is then returned to the resolver from the nameserver
8. Then DNS resolver then responds to the web browser with the IP address of the domain requested initially

## DNS Port

53

## How to change DNS settings 

```
Linux
```

Go to /etc/resolv.conf.d and under the base file
Then put DNS Nameserver under list
Sudo resolveconf -u to update DNS settings

```
Windows
```

Go to Control Panel
Go to Network 
Go to Change adapter settings
Right click the properties option
Select and check the IPv4 options and click the properties option under that
Type in Preferred DNS Server IP address under General tab
Click OK