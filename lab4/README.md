# Lab 4: Network Address Translator

Please refer to the [course administrative handout](https://suclass.stanford.edu/c4x/Engineering/CS144/asset/admin.pdf) for the late policy

## 0. Collaboration Policy
You should direct most questions to Piazza, but **do not** post any source code there. Please make a private post when appropriate.

You must write all the code you hand in for the programming assignments, except for the code that we give you as part of the assignment and system library code. You are not allowed to show your code to anyone else in the class or look at anyone else’s code. You also must not look at solutions from previous years. You may discuss the assignments with other students, but do not copy each others’ code. Please refer to the course administrative handout for more details, and ask questions in Piazza if anything is unclear.
## 1. Introduction
In this lab assignment you will be writing a simple NAT that can handle ICMP and TCP. It will implement a subset of the functionality specified by [RFC5382](http://tools.ietf.org/rfc/rfc5382.txt) and [RFC5508](https://tools.ietf.org/rfc/rfc5508.txt). Expect to refer often to these RFCs.
Before beginning this lab, it is crucial that you:
* Understand how NATs work. Consider re-watching the NAT lectures.
* Understand TCP handshake and teardown packet sequences. Consider working through the TCP state diagram.
* Understand NAT Endpoint Independence.

We will create a NAT that sits in Mininet between the app servers and the rest of the Internet. The internal interface of the NAT faces the Internet, while the external interfaces are connected to app servers. The app servers are “outside” the NAT, while the Internet is “inside.”

Your NAT must rewrite packets from client going to the application servers, such that they appear that they are coming from the NAT interface facing the application servers. For example, consider this topology, where the NAT’s internal interface (eth1) faces the client and its external interface (eth2) has two application servers connected with a switch:

![alt text](https://user-images.githubusercontent.com/61527787/75953810-c2aea000-5ee4-11ea-8cf8-e89f2435714c.png)

The setup for this assignment is very similar to Lab 3. In this topology, the NAT rewrites packets from the client, setting the source IP address to ```184.72.104.221```. When the NAT receives packets addressed to ```184.72.104.221```, it determines whether the packet has a valid mapping to an internal source, and if so, translates the address to the corresponding client.
For this assignment, interface ```eth1``` will always be the internal interface and all other interfaces will always be external interfaces. You can hardcode ```eth1``` as the internal interface.
A correct implementation should support the following operations from the client:
* Pinging the NAT’s internal interface from the client
* Pinging the app server (e.g. ```184.72.104.217```)
* Downloading files using HTTP from the app servers
* All packets to external hosts (app servers) from the NAT should appear to come from eth2's address (e.g. 184.72.104.221 above).

> After this lab, you will have built a working NAT which works on the world-wide web (if the routing table were updated)! Later on on Lab 5, you will put together your cTCP with your router/NAT and will have basically built the Internet!

## 2. General NAT Logic
There are three major parts to the assignment:
* Translating ICMP echo messages (and their corresponding replies)
* Translating TCP packets
* Cleaning up defunct mappings between internal addresses and the external address. Note that your NAT is not required to handle UDP. It is entirely up to you whether you drop or forward UDP traffic.
### Static Router
Your NAT builds on the static router of Lab 3. You must add a new command-line flag, ```-n```, which controls whether the NAT is enabled. If the ```-n``` flag is not passed, then the router should act according the requirements of Lab 3. For example, it should be possible to ```traceroute``` across the router when the -n flag is not passed. All of the ICMP errors in Lab 3 still apply. For example, trying to open a TCP port on the router should cause an ICMP port unreachable reply (with the caveat of TCP requirement 4 below). More precisely:
* Your NAT MUST generate and process ICMP messages as per the static router of Lab 3.
### ICMP Echo
The first four bytes of an ICMP echo request contain a 16-bit query identifier and a 16-bit sequence number. Because multiple hosts behind the NAT may choose the same identifier and sequence number, the NAT must make their combination globally unique. It needs to maintain the mapping between a globally unique identifier and the corresponding internal address and internal identifier, so that it can rewrite the corresponding ICMP echo reply messages. The first three requirements for your NAT are:
* Your NAT MUST translate ICMP echo requests from internal addresses to external addresses, and MUST correctly translate the corresponding ICMP echo replies.
* ICMP echo requests MUST be external host independent: two requests from the same internal host with the same query identifier to different external hosts MUST have the same external identifier.
* An ICMP query mapping MUST NOT expire less than 60 seconds after its last use. This value MUST be configurable, as described below. Other Lab 3 ICMP behavior should continue to work properly (e.g. responding to an echo request from an external host addressed to the NAT’s external interface).
### TCP Connections
When an internal host opens a TCP connection to an external host, your NAT must rewrite the packet so that it appears as if it is coming from the NAT’s external address. This requires allocating a globally unique port, under a set of restrictions as detailed below. The requirements for your NAT are a subset of those in specified in [RFC5382](http://tools.ietf.org/rfc/rfc5382.txt); in some cases they are more restrictive. Refer to the RFC for details on the terms used. Your NAT has the following requirements:
* Your NAT MUST have an “Endpoint-Independent Mapping” behavior for TCP.
* Your NAT MUST support all valid sequences of TCP packets (defined in [RFC0793](http://tools.ietf.org/rfc/rfc0793.txt)) for connections initiated both internally as well as externally when the connection is permitted by the NAT. In particular, in addition to handling the TCP 3-way handshake mode of connection initiation, A NAT MUST handle the TCP [simultaneous-open mode of connection initiation](http://ttcplinux.sourceforge.net/documents/one/tcpstate/tcpstate.html).
* Your NAT MUST have an “Endpoint-Independent Filtering” behavior for TCP.
* Your NAT MUST NOT respond to an unsolicited inbound ```SYN``` packet for at least 6 seconds after the packet is received. If during this interval the NAT receives and translates an outbound ```SYN``` for the connection the NAT MUST silently drop the original unsolicited inbound ```SYN``` packet. Otherwise, the NAT MUST send an ICMP Port Unreachable error (Type 3, Code 3) for the original ```SYN```.
* If your NAT cannot determine whether the endpoints of a TCP connection are active, it MUST abandon the session if it has been idle for some time. In such cases, the value of the “established connection idle-timeout” MUST NOT be less than 2 hours 4 minutes. The value of the “transitory connection idle-timeout” MUST NOT be less than 4 minutes. This value MUST be configurable, as described below. Note that you MUST timeout idle connections.
* Your NAT MUST NOT have a “Port assignment” behavior of “Port overloading” for TCP. **Note**: Hairpinning for TCP is NOT required. It is up to you whether you support it, or other behavior not required here.
### Mappings
When assigning a port to a mapping, you are free to choose a port any way you choose. The only requirement is that you do not use the well-known ports (```0-1023```).
As noted above, mappings should be Endpoint Independent. Once a mapping is made between an internal host’s ```(ip, port)``` pair to an external port in the NAT, any traffic from that host’s ```(ip, port)``` directed to any external host, and any traffic from any external host to the mapped external port will be rewritten and forwarded accordingly.
### Cleaning up defunct mappings
Your NAT must clean up defunct mappings. Your NAT must periodically timeout both defunct ICMP query sessions and idle TCP connections. Once all connections using a particular mapping are closed or timed out, the mapping should be cleared. Once cleared, a mapping can be reused in new connections.
The periodic function that handles timeouts should fire in its own separate thread (more on threading below). The following three timeout intervals for mappings should be configurable via command-line flags:
```
-I INTEGER -- ICMP query timeout interval in seconds (default to 60)
-E INTEGER -- TCP Established Idle Timeout in seconds (default to 7440)
-R INTEGER -- TCP Transitory Idle Timeout in seconds (default to 300)
```
TCP Established Idle Timeout applies to TCP connections in the established (data transfer) state. TCP Transitory Idle Timeout applies to connections in other states (e.g. ```LISTEN```). Refer to the TCP state diagram.
**Note**: Though the RFCs specify minimum timeout intervals, these are reflected in the defaults. The intervals should be configurable to times below those minimums so that we are able to test your timeout functionality in a reasonable time.
### Mapping data structure and Concurrency
Mapping state and delaying incoming ```SYN``` connections will require a data structure similar to the ARP cache from Lab 3. Unlike Lab 3, however, in this assignment it is up to you to implement it!
Be sure to study how the ARP cache works. For handling timeouts, a separate thread is spawned (at the top of ```sr_router.c```) that periodically runs. NAT timeouts should have their own thread as well. Because the main forwarding thread and the ARP cache timeout thread share the data structure, the ARP cache accessors and mutators use locks. Be sure that your NAT’s mapping data structure uses locks as well, otherwise nasty concurrency bugs will be sure to crop up.
In addition, be careful how your mapping table returns mappings, you do not want to hand out pointers to structures that may be freed by the periodic timeout. Take a look at the ```sr_arpcache_lookup()``` code in the ARP cache.
## 3. Implementation Guidance
You will use the same VM that you setup in Lab 3 for this assignment. For instructions on starting the VM, please refer to this [handout](http://web.stanford.edu/class/cs144/assignments/vm/vm-setup.html). To get you started on the right track, we’ve provide skeleton code for a possible NAT mapping data structure.
SSH into your VM and download the skeleton code for Lab 4 using Git:
```
cd ~
git clone https://bitbucket.org/cs144-1617/lab4.git
```
The skeleton code resides in sr_nat_code.tar.gz .
```
cd lab4/
```
The ```router``` directory is a link to your Lab 3 directory for convenience. **We recommend you make a copy of your Lab 3 submission in your Lab 4 directory as follows:**
```
pwd
> /home/cs144/lab4
rm router
cp -r ~/lab3/router ./
```
**When running your compiled ```sr```, please ensure that it sees the ```IP_CONFIG``` and ```rtable``` files corresponding to Lab 4.**
```
cp rtable ~/lab4/router/
cp IP_CONFIG ~/lab4/router/
```
Now untar the file ```sr_nat_code.tar.gz```. Then you will find two files, ```sr_nat.c``` and ```sr_nat.h```.
```
tar xf sr_nat_code.tar.gz
mv sr_nat.c ./router/
mv sr_nat.h ./router/
```
Now, configure the environment and start Mininet and POX by running the following command.
```
sudo ./run_all.sh
```
We provide a reference implementation (```sr_nat```) for you to test the environment. Start the reference ```sr_nat```
```
./sr_nat -n
```
Note that ```-n``` means NAT is enabled. You should see an output like this:
```
mininet@mininet-vm:~/cs144_lab4$ ./sr_nat -n
Using VNS sr stub code revised 2009-10-14 (rev 0.20)
Loading routing table from server, clear local routing table.
Loading routing table
---------------------------------------------
Destination Gateway     Mask    Iface
0.0.0.0     10.0.1.100  0.0.0.0 eth1
184.72.104.217      184.72.104.217  255.255.255.255 eth2
107.23.87.29        107.23.87.29    255.255.255.255 eth2
---------------------------------------------
Client mininet connecting to Server localhost:8888
Requesting topology 0
successfully authenticated as mininet
Loading routing table from server, clear local routing table.
Loading routing table
---------------------------------------------
Destination Gateway     Mask    Iface
0.0.0.0     10.0.1.100  0.0.0.0 eth1
184.72.104.217      184.72.104.217  255.255.255.255 eth2
107.23.87.29        107.23.87.29    255.255.255.255 eth2
---------------------------------------------
Router interfaces:
eth2    HWaddr02:4c:0c:94:8b:9f
    inet addr 184.72.104.221
eth1    HWaddr2a:20:2f:d2:91:15
    inet addr 10.0.1.1
 -- Ready to process packets --
Now, test whether ```ping``` works.
```
ping <SERVER1_IP> (184.72.104.217)
```
To see whether the NAT is doing the translation, let’s take a look at the packet received at server1. To do so, go to the terminal where you run the Mininet, type the following command in the Mininet command line interface (CLI):
```
mininet> server1 tcpdump -n -i server1-eth0
```
If you do not see anything, type ```Ctrl + C``` to flush out the output. And you should be able to see the following output:
```
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on server1-eth0, link-type EN10MB (Ethernet), capture size 65535 bytes
03:22:42.744170 IP 184.72.104.221 > 184.72.104.217: ICMP echo request, id 1051, seq 1, length 64
03:22:42.744202 IP 184.72.104.217 > 184.72.104.221: ICMP echo reply, id 1051, seq 1, length 64
```
Now, let’s disable NAT. Use ```Ctrl + C``` to stop the current ```./sr_nat -n``` process, and run the following command
```
./sr_nat
```
Note that we do not run sr_nat with the ```-n``` parameter, which means the NAT is disabled.

Again, run ```ping``` from your VM terminal:
```
ping <SERVER1_IP>
```
You can also use ```tcpdump``` to see the packets reaching ```server``` in Mininet:
```
mininet> server1 tcpdump -n -i server1-eth0
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on server1-eth0, link-type EN10MB (Ethernet), capture size 65535 bytes
03:25:22.204476 IP 184.72.104.217 > 10.0.1.100: ICMP echo reply, id 10894, seq 7, length 64
03:25:23.211268 IP 10.0.1.100 > 184.72.104.217: ICMP echo request, id 10894, seq 8, length 64
```
This time, since the NAT is disabled, the source IP shows the client IP instead.
This assignment would require some thread programming. If you do not have thread programming experience, then Lectures 9, 10, and 13 of [CS110](https://web.stanford.edu/class/cs110/) might be helpful introductions. There are also many resources on the web explaining why and when systems use them. Finally, there are lots of good [pthreads tutorials](https://computing.llnl.gov/tutorials/pthreads/) on the web, for concrete programming guidance. You can also use the ARP cache code as a guide. Since this isn’t a high performance system, it’s better to be conservative with your locks; a race condition is much harder to debug than a deadlock.
### Tracking Connections
You do not need to keep lots of state per connection. For example, there is no need to track ```seqnos``` or window values or ensure TCP packets are in proper order to the end hosts. Keep only the information that is useful to the NAT for establishing or clearing mappings.
When rewriting TCP packets, remember to update the checksum (over the pseudo-header, TCP header, and payload). The TCP checksum is calculated like the IP checksum, so you can reuse the cksum function. Note that if the ```checksum``` is incorrect when the packet comes in, you can drop it; you should not “correct the checksum” as that would hide potential attackers or errors.
### Adding command-line flags
You must add the following command-line flags to ```sr_main.c```:
```
-n         -- Enable NAT functionality
-I INTEGER -- ICMP query timeout interval in seconds (default to 60)
-E INTEGER -- TCP Established Idle Timeout in seconds (default to 7440)
-R INTEGER -- TCP Transitory Idle Timeout in seconds (default to 300)
```
Make sure to adjust the parameter to ```getopt()```, and add the proper cases. ```getopt()``` is a useful C library call to parse a list of arguments passed to your program. Here is a good tutorial on using getopt: [Command line processing using getopt()](https://www.ibm.com/developerworks/aix/library/au-unix-getopt.html).

For example, starting your NAT with:
```
./sr -s localhost -p 8888 -n -I 70 -R 40
```
Would enable NAT functionality, timeout ICMP mappings after 70 seconds, TCP mappings with at least one established connection after 7440 seconds, and TCP mappings with only transitory connections after 40 seconds.
### Reference Implementation
A reference implementation (binary) is available at ```~/lab4/sr_nat```.


