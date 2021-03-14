## Network Gateway vs Router

Network hardware that allows access to computers outside your network like a door

Router determines shortest path from Computer A to Computer B

## What is the difference between Bandwidth, Delay, and Latency

```
Bandwidth
```

Bandwidth is a measure of how much data can be transferred from one network to another within a specific amount of time

```
Latency
```

Latency refers to how much time it takes for a signal to travel to its destination and back


```
Delay
```

The one-way time it takes for traffic to leave the sender and arrive at the destination

## What is MTU, Window Size, Segment(MSS)? Describe 3-way handshake

```
MTU (Maximum Transmission Unit) MSS
```

A MTU is the largest packet or frame size that can be sent in a packet network
1500 bytes is max MTU size

Fragmentation - Divides the datagram into pieces



The best way to avoid fragmentation is to adjust the maximum segment size 

```
Windows Size
```

Simply how much data in bytes the recieving device is willing to recieve at any point in time

```
MSS
```

MSS - Maximum size of payload

## GRE Tunnels

Generic Routing Encapsulation or GRE is a protocol for encapsulating data packets that use one 
routing protocol inside the packets of another protocol

GRE enables the usage of protocols that are not normally supported by a network, because the packets are wrapped within other packets that do use supported protocols

Company needs to setup a connection between the LANS in two offices but both use IPv6 so in order to get from one office to another traffic must pass through a network managed by a third party that only supports IPv4 which can be encapsulated using GRE

## IPsec Tunnel

IPsec is a group of protocols used together to setup an encrypted connectiong between devices
IPsec is used to setup VPNs and it work by encrypting IP packets along with authenticating the source of where the packets come from

Users can access an IPsec VPN by logging into a VPN application or client

Protocols used in IPsec

Authentication Header (AH): AH protocol ensures the data packets are from a trusted source and that the data has not been tampered with

Encapsulating Security Protocol (ESP): ESP encrypts the IP header and the payload for each packet unless transport mode is used in which case it only encrypts the payload

Security Association (SA): SA refers to a number of protocols used for negotiating encryption keys and algorithms 

IPsec runs directly on top of IP

IPsec tunnel mode is used between two dedicated routers with each router acting as one end of a virtual tunnel through a public network 

IPsec tunnel mode - original IP header containing the final destination of the packet is encrypted in addition to packet payload. To tell intermediary routers where to forward packets, IPsec adds a new IP header. At each end of the tunnel, the routers decrypt the IP headers to deliver the packets to their destinations

IPsec transport mode - payload of each packet is encrypted but the original IP header is not. Intermediary routers are thus able to view the final destination of each packet unless a separate tunneling protocl is used

Network port is a virtual location where data goes in a computer



## Discontiguous and Contiguous network

A Discontiguous Network topology is where you have some network (172.16.0.0) that is divided into two parts (perhaps 172.16.0.0-100.0 and 172.16.101.0-200.0) and to go
from one part to the other part you must go through some other different network (192.168.1.0)

## Route flapping

Route flapping occuers when a router alternately advertises a destination network via one route then another (os as unavailable and then available again) in quick sequence

## Route summarization and Prefix Match

Route summarization - method where we reduce the number of routes a router must maintan by representing a series of network numbers in a single summary address to reduce latency

## Stateful / Stateless firewalls

Stateless firewall - network device used to scan and filter network traffic based on source and destination addresses or other static values. Do not account for the fact that a packet might be received by the firewall pretending to be something you asked for

Stateful firewall - network device used to monitor traffic based on the connection state taking up more resources to filter

Small business - Stateless

Large business - Stateful probably

## Network Address Translation (NAT)

NAT - Network Address Translation

NAT - Allows a single device to act as an internet gateway for internal LAN clients by translating the clients internal IP into the IP Address on the NAT-enabled gateway device and hides the rest of the network

Packet flow out of NAT:

Strip Source IP to place public IP in order to send packet to internet

Before NAT:
Destination: 135.xxx.xxx.xxx.
Source: 192.xxx.xxx.xxx

After NAT:
Destination: 135.xxx.xxx.xxx
Source: 141.xxx.xxx.xxx.xxx

## Border Gateway Protocol (BGP)

BGP - Routing protocol of the internet (postal service picking the most efficient routes) 

States:
Established - all is well and working
Active - BGP is actively trying to setup a session with the neighbor
Idle - BGP is currently not trying to setup a BGP session

## TCP (3 Way Handshake)

TCP Handshake - process which is used in a TCP/IP network to make a connection between the server and handshake

1. SYN - Client informs server to establish connection
2. SYN/ACK - Server responds to the client and confirms receipt and how to start segment
3. FIN - Client acknowleges response and establishes connection and starts data transfer

## DHCP

DHCP - Dynamic host config protocol which assigns an IP address and other information to each host on the network
DHCP IP is valid for limited time (DHCP lease time)
- easier management of ips
- accurate ip configuration
- efficient change management if ip range is changed

Security risks - no authentication so any client can join a network

## Difference between TCP and UDP

TCP - Connection oriented protocol such as email or a download
UDP - Connectionless oriented protocol such as phone call or tv
