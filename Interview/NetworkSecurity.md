## What port does ping work over

Ping does not work over a port. ICMP is a layer 3 protocol and does not user TCP or UDP.

## Do you prefer filtered ports or closed ports on your firewall?

small company back-end intranet - focus on close ports (REJECT) because those servers are not usually targeted by DDos attacks and external applications that requires to consume services hosted in the servers can quickly report failures instead to hang the connections


website - website can be targeted by DDoS attack then filtered will be best because your firewall is not going to consume CPU and bandwidth

## How exactly does traceroute/tracert work at the protocol level?

Traceroute works by sending a packet from a host computer to a remote machine to determine the route. Its used to identify if packets are redirected, take too long, or if the number of hops used to send traffic to a host

## What is a buffer overflow

Buffers are memory storage regions that hold data while it is being transferred. A buffer overflow occurs when the volume of data exceeds the storage capacity of the memory buffer. As a result, attackers exploit buffer overflow issues by overwriting the memory of an application changing the execution path of the program

## How can one defend against buffer overflows?

-Dont use C/C++ as they dont have safeguards against overwriting or accessing data in memory
-Use safe languages such as java with safeguards
-Address Space Randomization which randomly moves around the space locations of data regions. Harder to determine offsets.
-Use safe functions for copy data into buffers NOT strcpy

## What are Linux's strengths and weaknesses vs Windows?

Windows
-Large range of software
-Beginner-friendly
-Malware
-Cost of licenses

Linux
-Mostly free
-Stable
-Configuration possibilities
