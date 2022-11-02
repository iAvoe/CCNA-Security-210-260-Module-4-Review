# CCNA-Security-210-260-Module-4-Review
### 9 - Securing Layer 2 Devices
https://www.cram.com/flashcards/9-securing-layer-2-devices-7190486

**Which is the primary Layer 2 mechanism that allows multiple devices in the same VLAN to communicate with each other even though those devices are physically connected to different switches?**

    a. IP address
    b. Default gateway
    c. √ Trunk (802.1Q)
    d. 802.1D

**How does a switch know about parallel Layer 2 paths?**

    a. √ 802.1Q (trunk)
    b. BPDU
    c. CDP
    d. NTP

**Which one helps prevent CAM table (MAC address table) overflows?**

    a. 802.1w
    b. √ BPDU Guard
    c. Root Guard
    d. Port security

**What does STP root guard do?** Enforces the root bridge placement in network.

**Which one is not a best practice for security?**

    a. √ Leaving the native VLAN as VLAN 1
    b. Shutting down all unused ports and placing them in an unused VLAN
    c. Limiting the number of MAC addresses learned on a specific port
    d. Disabling negotiation of switch port mode

**What is the default # of MAC addr allowed on a switch port that is configured with port security?**

    a. √ 1
    b. 5
    c. 15
    d. Depends on the switch mode

**Which two items normally have a one-to-one correlation?**

    a. √ VLANs
    b. Classful IP networks
    c. √ IP subnetworks
    d. Number of switches
    e. Number of routers

**Typical method for a device in VLAN to reach another device in a 2nd VLAN?**

    a. ARP for the remote device's MAC address
    b. Use a remote default gateway
    c. √ Use a local default gateway
    d. Use trunking on the PC

**Which 2 configuration changes prevent users from jumping onto any VLAN they choose to join?**

    a. √ Disabling negotiation of trunk ports
    b. Using something else other than VLAN 1 as the "native" VLAN
    c. Configuring the port connecting to the client as a trunk
    d. √ Configuring the port connecting to the client as an access port

**If you limit the number of MAC addresses learned on a port to 5, what benefits do you get from it? (Choose all that apply.)**

    a. √ Protection for DHCP servers against starvation attacks
    b. Protection against IP spoofing
    c. Protection against VLAN hopping
    d. Protection against MAC address spoofing
    e. √ Protection against CAM table overflow attacks

**Why should you implement Root Guard on a switch?**

    a. To prevent the switch from becoming the root
    b. To prevent the switch from having any root ports
    c. √ To prevent the switch from having specific root ports
    d. To protect the switch against MAC address table overflows

**Why should CDP be disabled on ports that face untrusted networks?**

    a. CDP can be used as a DDoS vector.
    b. √ CDP can be used as a reconnaissance tool to determine info about the device
    c. Disabling it prevents the device from participating in spanning tree w/ untrusted devices.
    d. CDP can conflict with LLDP on ports facing untrusted networks

**Which of the following is not a true statement for DHCP snooping?**

    a. DHCP snooping validates DHCP messages received from untrusted sources, which filters invalid messages
    b. DHCP snooping information is stored in a binding database.
    c. √ DHCP snooping is enabled by default on all VLANs.
    d. DHCP snooping rate-limits DHCP traffic from trusted and untrusted sources.

**Which of the following is not a true statement regarding dynamic ARP inspection (DAI)?**

    a. DAI intercepts, logs, and discards ARP packets with invalid IP-to-MAC address bindings.
    b. DAI helps to mitigate MITM attacks.
    c. DAI determines validity of ARP packets based on IP-to-MAC address bindings found in the DHCP snooping database.
    d. √ DAI is enabled on a per-interface basis

**If there is no 802.1Q tag on the frame, what will the switch assume?** This frame originates from native VLAN

**Why is auto-negotiation risky?** Attacker could set up a trunk link and access VLANs

**How do we comminate from inside VLAN to outside VLANs?** Inter-VLAN Routing

**How to use virtual Sub-interfaces to route?** Setup a trunk port, then configure sub-interfaces on router, which route the corresponding VLAN tags

**802.1 suffix for authenticating users before allowing their data frames on the network?** 802.1X port-based network access control (PNAC)

**Purpose of spanning tree?** break loops and create redundant link for switches


### 10 - Network Foundation Protection
https://www.cram.com/flashcards/10-network-foundation-protection-7190492

**Which one is not a core element addressed by Network Foundation Protection?**

    a. Management plane
    b. Control plane
    c. Data plane
    d. √ Executive plane

**If you add authentication to your routing protocol so that only trusted authorized routers share information, which plane in the NFP are you securing?**

    a. Management plane
    b. √ Control plane
    c. Data plane
    d. Executive plane

**If you use authentication and authorization services to control which administrators can access which networked devices and control what they are allowed to do, which primary plane of NFP are you protecting?**

    a. √ Management plane
    b. Control plane
    c. Data plane
    d. Executive plane

**Which of the following is not a best practice to protect the management plane? (Choose all that apply.)**

    a. √ HTTP
    b. √ Telnet
    c. HTTPS
    d. SSH

**Which of the following is a way to implement role-based access control related to the management plane? (Choose all that apply.)**

    a. √ Views
    b. √ AAA services
    c. Access lists
    d. IPS

**What do Control Plane Policing (CoPP) & Control-Plane Protection (CPPr) have in common? (Choose all that apply.)**

    a. They both focus on data plane protection.
    b. They both focus on management plane protection.
    c. √ They both focus on control plane protection.
    d. √ They both can identify traffic destined for the router that will likely require direct CPU resources to be used by the router

**Which type of attack can you mitigate by authenticating a routing protocol? (Choose all that apply.)**

    a. √ MITM (reconnaissance + spoofing by hiding & forwarding inbetween 2 links)
    b. √ Denial-of-service attack (halting system resources)
    c. √ Reconnaissance attack (gathering information for vulnerability)
    d. Spoofing attack (identifies as another by falsifying data)

**What is a significant difference between CoPP and CPPr?**

    a. One works at Layer 3, and the other works at Layer 2.
    b. √ CPPr can classify and act on more-specific traffic than CoPP.
    c. CoPP can classify and act on more-specific traffic than CPPr.
    d. One protects the data plane, and the other protects the management plane

**Which of the following enables you to protect the data plane?**

    a. √ IOS zone-based firewall
    b. √ IPS
    c. √ Access lists
    d. √ Port security

**DHCP snooping protects which component of NFP?:**

    a. Management plane
    b. Control plane
    c. √ Data plane
    d. Executive plane

**Define management plane:** protocols, traffic that administrator uses

**Define control plane:** protocols, traffic that network devices use on their own automatically

**Define data plane:** common network data user uses

**Define role-based access control:** on management plane, permission given depend on corresponding roles of logged user

**Management plane security measures:** AAA, NTP, SSH, SSL/TLS, syslog, SNMPv3, PARSER VIEWS, bitlocker

**Control plane security measures:** Ctrl plane policing (CoPP) & Ctrl Plane Protection (CPPr)

**Data plane security measures:** ACL, VLAN, STP guards, IPS, Firewall

**How to keep constant times across network devices:** network time protocol (NTP)

**Which version of SNMP has encryption & authentication:** SNMPv3

**How to manage user accounts that need to connect to network devices:** AAA services and manage them from an Automatic Configuration Server (ACS) (e.g., RADIUS). This keeps an audit trail of users who logged in

**Define control plane policing:** Managing router and switches in regards of traffic, e.g., QoS, BPDU guard, DHCP snooping, limit bandwidth on ports, etc

**Define control plane protection:** e.g., shutdown and assign blackhole VLANs to unused switchports

**3 specific sub-interfaces that are classified:** 
 - Host subinterface - handles traffic to one of physical/logical interfaces of the router.
 - Transit subinterface - handles data plane traffic that requires CPU intervention before forwarding (IP options)
 - Cisco Express Forwarding (CEF) Exception traffic (keepalives, ttl packets) that has to involve the CPU.

**Best way to block unwanted traffic at the data plane:** access lists

### 11 - Securing the management plane on Cisco IOS
https://www.cram.com/flashcards/11-securing-the-management-plane-on-ios-7190502

**Which one of the following follows best practices for a secure password?**

    a. ABC123!
    b. √ SlE3peR1#
    c. tough-passfraze
    d. InterEstIng-PaSsWoRd

**When you connect for the first time to the console port on a new router, which privilege level are you using initially when presented with the command-line interface?**

    a. 0
    b. √ 1
    c. 15
    d. 16

**Which of the following is not impacted by a default login authentication method list?**

    a. AUX line
    b. √ HDLC interface
    c. Vty line
    d. Console line

**You are trying to configure a method list, and your syntax is correct, but the command is not being accepted.**
**Which of the following might cause this failure? (Choose all that apply.)**

    a. √ Incorrect privilege level
    b. √ AAA not enabled
    c. √ Wrong mode
    d. √ Not allowed by the view

**Cisco recommends which version of Simple Network Management Protocol (SNMP) on your network if you need it?**

    a. Version 1
    b. Version 2
    c. √ Version 3
    d. Version 4

**How can you implement role-based access control (RBAC)? (Choose all that apply.)**

    a. √ Provide the password for a custom privilege level to users in a given role
    b. √ Associate user accounts with specific views
    c. Use access lists to specify which devices can connect remotely
    d. √ Use AAA to authorize specific users for specific sets of permissions

**Which of the following indirectly requires the administrator to configure a hostname?**

    a. Telnet
    b. HTTP
    c. HTTPS
    d. √ SSH

**What are the two primary benefits of using NTP along with a syslog server? (Choose all that apply.)**

    a. √ Correlation of syslog messages from multiple different devices
    b. Grouping of syslog messages into summary messages
    c. Synchronization in the sending of syslog messages to avoid congestion
    d. √ Accurate accounting of when a syslog message occurred

**Which of the following commands result in a secure bootset? (Choose all that apply.)**

    a. secure boot-set
    b. √ secure boot-config
    c. secure boot-files
    d. √ secure boot-image

**What is a difference between a default and named method list?**

    a. A default method list can contain up to four methods.
    b. A named method list can contain up to four methods.
    c. A default method list must be assigned to an interface or line.
    d. √ A named method list must be assigned to an interface or line

**What is Role based Access Control? not every admin needs full access, which can be limited through AAA

**What are Cisco's password recommendations? <=8 characters. upper/lowercase, numbers, characters, symbols, spaces. Don't use dictionary words. Can be remembered

### 12 - Securing the data plane
https://www.cram.com/flashcards/12-securing-the-data-plane-in-ipv6-7190509

**Which of the following are the valid first 4 characters of a globally routable IPv6 address? (Choose all that apply.)**

    a. 1234
    b. √ 2345
    c. √ 3456
    d. 4567

**Which of the following are the valid first four characters of a link-local address?**

    a. √ FE80
    b. FF02
    c. 2000
    d. 3000

**What is the default method for determining the interface ID for a link-local address on Ethernet?**

    a. √ EUI-64
    b. MAC address with FFFE at the end
    c. MAC address with FFFE at the beginning
    d. Depends on the network address being connected to

**How many groups of four hexadecimal characters does an IPv6 address contain?**

    a. 4
    b. √ 8
    c. √ 16
    d. 32

**Which of the following routing protocols have both an IPv4 and IPv6 version? (Choose all that apply.)**

    a. √ Routing Information Protocol (RIP)
    b. √ Enhanced Interior Gateway Routing Protocol (EIGRP)
    c. √ Open Shortest Path First (OSPF)
    d. Interior Gateway Routing Protocol (IGRP)

**Which best practices apply to networks that run both IPv4 and IPv6? (Choose all that apply.)**

    a. √ Physical security
    b. √ Routing protocol authentication
    c. √ Authorization of administrators
    d. √ Written security policy

**Which of protocols, if abused, could impair an IPv6 network, but not IPv4? (Choose all that apply.)**

    a. ARP
    b. √ NDP
    c. Broadcast addresses
    d. √ Solicited node multicast addresses

**If a rogue IPv6 router is allowed on the network, which information could be incorrectly delivered to the clients on that network? (Choose all that apply.)**

    a. √ IPv6 default gateway
    b. √ IPv6 DNS server
    c. √ IPv6 network address
    d. IPv6 ARP mappings

W**hy is tunneling any protocol (including IPv6) through another protocol a security risk?**

    a. √ The innermost contents of the original packets may be hidden from normal security filters.
    b. √ The tunnels, if they extend beyond the network perimeter, may allow undesired traffic through the tunnel.
    c. Functionality might need to be sacrificed when going through a tunnel.
    d. Quality of service, for the underlying protocol, might be compromised.

**What is one method to protect against a rogue IPv6 router?**

    a. Port security
    b. Static ARP entries
    c. DHCPv6
    d. √ RA guard

**Does IPv6 support NAT?** No

**IPv6 address is split in two parts called:** Network ID, Host ID

**How can you shorten IPv6 addresses?** Drop leading 0's, consecutive 0's shortened to ::

**What is the loopback IPv6?** ::1. (127 0's followed by a 1)

**What is the all-nodes multicast address?** Multicasts begin with FFxx:. Usually FF02::1

**What does the system automatically configure when setting IPv6 on an interface?**

 - A link local address starting with FE80

**How do you reach remote networks with IPv6:**

 - Need to have a default route to that network or default gateway.

**What is a link local address?**

 - May be manually configured, but if not are dynamically configured by host/router.
 - Used for network discovery and self-configuration when DHCP is down
 - Always begin with FE80. Last 64 bits are the host ID.

### 13 Securing Routing Protocols and the Control Plane
https://www.cram.com/flashcards/13-securing-routing-protocols-and-the-control-plane-7190512
**Control plane packets are handled by:** CPU

**Which of the following functions is not handled by the control plane?**

    a. BGP
    b. RSVP
    c. √ SSH (management plane)
    d. ICMP

**Which command provides information on receive adjacency traffic?**

    a. show ip bgp
    b. show processes cpu
    c. show interfaces summary
    d. √ show ip cef

**Control plane policing helps to protect the CPU by doing what?**

    a. Diverting all control plane traffic to the data and management planes
    b. √ Filtering and rate-limiting traffic destined to the control plane
    c. Rate-limiting SNMP traffic to reduce the impact on the CPU
    d. Throttling all traffic ingressing the device during heavy traffic periods until the CPU performance has improved

**In the following CoPP access control list example, which traffic is being prevented from reaching the control plane?**
Extended IP access list 123
 10 deny tcp 192.168.1.0 0.0.0.255 any eq telnet
 20 deny udp 192.168.1.0 0.0.0.255 any eq domain
 30 permit tcp any any eq telnet
 40 permit udp any any eq domain
 50 deny ip any any
a. Telnet traffic from the 192.168.1.0/24
    b. √ Telnet and DNS traffic from outside the 192.168.1.0./24 subnet
    c. Telnet and DNS traffic from the 192.168.1.0/24 subnet
    d. DNS traffic from the 192.168.1.0/24 subnet

**Which of the following is not a sub-interface that can be leveraged as part of control plane protection?**

    a. Host subinterface
    b. √ Frame Relay subinterface
    c. CEF-Exception subinterface
    d. Transit subinterface

**Which line in the following OSPF configuration will not be required for MD5 auth to work?**
interface GigabitEthernet0/1
 ip address 192.168.10.1 255.255.255.0
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 CCNA
!
router ospf 65000
 router-id 192.168.10.1
 area 20 authentication message-digest
 network 10.1.1.0 0.0.0.255 area 10
 network 192.168.10.0 0.0.0.255 area 0
!
a. ip ospf authentication message-digest
    b. network 192.168.10.0 0.0.0.255 area 0
    c. √ area 20 authentication message-digest
    d. ip ospf message-digest-key 1 md5 CCNA

**Which of the following pairs of statements is true in terms of configuring MD5?**

    a. Interface statements (OSPF, EIGRP) must be configured; use of key chain in OSPF
    b. Router process (OSPF, EIGRP) must be configured; key chain in EIGRP
    c. √ Router process (only for OSPF) must be configured; key chain in EIGRP
    d. Router process (only for OSPF) must be configured; key chain in OSPF

**Which of the following statements is true?**

    a. RIPv1 supports cleartext authentication, and RIPv2 supports MD5 authentication.
    b. RIPv2 and OSPF make use of a key chain for authentication.
    c. RIPv2 and EIGRP both require router process configuration for authentication.
    d. √ RIPv2 and EIGRP both make use of a key chain for authentication.

**What is needed to implement MD5 authentication for BGP?**

    a. Interface and router process configuration
    b. Interface and key chain configuration
    c. √ Router process configuration
    d. Router process and key chain configuration

**What is process switched traffic?** Type of packets that are blocked to save CPU load

**Define the 2 types of switched traffic:**
 - received from adjacency
 - data plane traffic requiring special processing by the CPU

**What does the command show ip cef do?** Shows which IP receive is listed as the next hop address, packets destined for this address space will end up hitting the control plane and CPU

**CEF stands for?** Cisco express forwarding

### 14A - Understanding Firewall Fundamentals
https://www.cram.com/flashcards/14-understanding-firewall-fundamentals-7190521

**Which firewall method requires the adminto know & config all the specific ports, IPs, and protocols required for the firewall?**

    a. AGL
    b. √ Packet filtering
    c. Stateful filtering
    d. Proxy server

**Which technology dynamically builds a table for the purpose of permitting the return traffic from an outside server, back to the client, in spite of a default security policy that says no traffic is allowed to initiate from the outside networks?**

    a. Proxy
    b. NAT
    c. Packet filtering
    d. √ Stateful filtering

**What does application layer inspection provide?**

    a. Packet filtering at Layer 5 and higher
    b. √ Enables a firewall to listen in on a client/server communication, looking for information regarding communication channels
    c. Proxy server functionality
    d. Application layer gateway functionality

**Which one of the following is true about a transparent firewall?**

    a. Implemented at Layer 1
    b. Implemented at Layer 2
    c. √ Implemented at Layer 3
    d. Implemented at Layer 4 and higher

**What is the specific term for performing NAT for multiple inside devices but optimizing the number of global addresses required?**

    a. NAT-T
    b. NAT
    c. √ PAT
    d. PAT-T

**What term refers to the internal IP address of a client using NAT as seen from other devices on the same internal network as the client?**

    a. √ Inside local
    b. Inside global
    c. Outside local
    d. Outside global

**Which of the following describes a rule on the firewall which will never be matched because of where the firewall is in the network?**

    a. √ Orphaned rule
    b. Redundant rule
    c. Shadowed rule
    d. Promiscuous rule

**What is the long-term impact of providing a promiscuous rule as a short-term test in an attempt to get a network application working?**

    a. √ The promiscuous rule may be left in place, leaving a security hole.
    b. The rule cannot be changed later to more accurately filter based on the business req
    c. It should be a shadowed rule.
    d. Change control documentation may not be completed for this test.

**Should a firewall be resistant to attacks?** Yes, if a firewall can be infiltrated or brought down with a DoS then it can no longer serve it's purpose

**Where should network traffic flow when firewalls are in the infrastructure?** Traffic should be forced through the firewall.

**How do we reduce the risk of exposing sensitive systems to untrusted individuals?** By hiding most of the functionality of a host/network devic    e. Only the minimum required connectivity should be allowed to a given system. i.e., allowing only web traffic to a webserver in a DMZ

**How do we reduce exploitation of protocol flaws?** Firewalls can be configured to inspect protocols to ensure compliance with the standards

**How do we eliminate unauthorized users/access?** Need to use authentication methods. Can control which user traffic can pass through, and can block based on policy.

**How can we stop malicious data?** A firewall can detect/block malicious data with an IPS

**What might happen with a configuration mistake in a firewall?** firewall can't do its job, or block wrong packets

**Why might people try to engineer a way around the firewall?** the policy is too strict for its environment

**Why might latency be added by the firewall?** When firewall has to analyze a large amount of traffic

**Firewalls provide key features for perimeter security.What processes can we use for this?**
 - Simple packet filtering, proxy servers, NAT, stateful inspection firewalls, transparent firewalls

**What is static packet filtering?** A static set of policies, like ACLs that require an administrator to change them

**What are application layer gateways?** Acts as an intermediary between original client and server. No direct comms occurs between client & destination server. Operates on Layer 3 & up

**What is stateful packet filtering?** It remembers the state of sessions passing through the firewall, the firewall remembers it and allows a reply to send back

**Advantages of stateful firewalls?** used as a primary means of defense by filtering traffic

**What is an application inspection firewall?** Analyze and verify protocols up to layer 7, but does not act as a proxy

**What are the features of application firewalls?** Prevent more kinds of attacks than stateful

**What are transparent firewalls?** firewall in injected in the network as it can use packet-based filtering, stateful filtering, and application inspection, but applied at layer 2, acts as a bridge

**What are next generation firewalls (NGFW)?** Cisco Adaptive Security Appliance (ASA) with FirePOWER. Combines firewall with Sourcefire threat prevention and advanced malware protection

**Where should firewalls be placed?** At security boundaries, i.e., between two networks.

**Should a firewall be the only security device?** No, they should exist in conjunction with other security measures

**Define zone policy firewall (ZPF) / zone based firewall (ZBF):** Improved older interface-based model to a more flexible, more easily understood zone-based configuration model. Interfaces are assigned to zones, and an inspection policy is applied to traffic moving between the zones.

**How is the ZPF model inherently different from the context-based access control (CBAC)?**

**ZPF model:**
 - operates as a function of interfaces, which is better integrated than ACLs
 - allows different inspection policies applied to many host groups on the same interface
 - protocol specific, granular control
 - in default, security zones are deny-ed to communicate intercontinentally 
**CBAC model:**
 - running on routers are ACLs that just filters based on application types or ip address
 - easier on memory and CPU usage
 - start configure from small, specific unit and then gradually increase to larger range, finally global
 - hard to understand, and no commentary other than a name can be put in ACL
 - no failovers
 - needs to be very sure about what to do
 - cannot inspect encrypted packets

**What makes Router self-zone different:**
Purpose:** to control IP traffic that moves to the router's interfaces
Application Inspection is not available for self-zone
Session and rate limiting cannot be configured on self-zone
Deny Telnet connectivity
Allow HTTP connectivity
Restrict SNMP
Block ICMP from public internet

**How to setup ZPF from IOS?**
https://itexamanswers.net/4-4-1-2-lab-configuring-zone-based-policy-firewalls-answers.html

1. **Create security zones**

    R3(config)# zone security INSIDE
    R3(config)# zone security CONFROOM
    R3(config)# zone security INTERNET

2. **Create security policies depends on zones and protocols (class maps)**

    R3(config)# class-map type inspect match-any INSIDE_PROTOCOLS
    R3(config-cmap)# match protocol tcp
    R3(config-cmap)# match protocol udp
    R3(config-cmap)# match protocol icmp

    R3(config)# class-map type inspect match-any CONFROOM_PROTOCOLS
    R3(config-cmap)# match protocol http
    R3(config-cmap)# match protocol https
    R3(config-cmap)# match protocol dns

3. **Create policy maps**

    R3(config)# policy-map type inspect INSIDE_TO_INTERNET
    R3(config-pmap)# class type inspect INSIDE_PROTOCOLS
    R3(config-pmap-c)# inspect
    R3(config)# policy-map type inspect CONFROOM_TO_INTERNET
    R3(config-pmap)# class type inspect CONFROOM_PROTOCOLS
    R3(config-pmap-c)# inspect

4. **Create zone pairs**

    R3(config)# zone-pair security INSIDE_TO_INTERNET source INSIDE destination INTERNET
    R3(config)# zone-pair security CONFROOM_TO_INTERNET source CONFROOM destination INTERNET
    R3# show zone-pair security
    Zone-pair name INSIDE_TO_INTERNET
        Source-Zone INSIDE  Destination-Zone INTERNET
        service-policy not configured
    Zone-pair name CONFROOM_TO_INTERNET
        Source-Zone CONFROOM  Destination-Zone INTERNET
        service-policy not configured

5. **Applying Security Policies**

    R3(config)# zone-pair security INSIDE_TO_INTERNET
    R3(config-sec-zone-pair)# service-policy type inspect INSIDE_TO_INTERNET
    R3(config)# zone-pair security CONFROOM_TO_INTERNET
    R3(config-sec-zone-pair)# service-policy type inspect CONFROOM_TO_INTERNET

    R3#show zone-pair security 
    Zone-pair name INSIDE_TO_INTERNET
        Source-Zone INSIDE  Destination-Zone INTERNET 
        service-policy INSIDE_TO_INTERNET
    Zone-pair name CONFROOM_TO_INTERNET
        Source-Zone CONFROOM  Destination-Zone INTERNET 
        service-policy CONFROOM_TO_INTERNET

    R3#show policy-map type inspect zone-pair

6. **Assign interfaces to zones**

    R3(config)# interface g0/0
    R3(config-if)# zone-member security CONFROOM

    R3(config)# interface g0/1
    R3(config-if)# zone-member security INSIDE

    R3(config)# interface s0/0/1
    R3(config-if)# zone-member security INTERNET

    R3# show zone security

**What is the goal of NAT?** Translates addresses from the private space to the public internet, but bad for security

**Define inside global NAT:** mapped/global address that the router is swapping out for the inside host during NAT. The outside world sees 1 user

**Define outside local NAT:** The real IP configured on an outside host

**How does PAT work?** Subset of NAT, though everyone doesn't get their own unique IP address. Keeps track of individual sessions on an array of ports

**Define Static NAT:** one to one permanent mapping
**Define Dynamic NAT:** pool of global addresses and only map devices need traffic
**Define dynamic PAT:** a feature used for most users who access the internet. Combines benefits of dynamically assigning global addresses only when needed and uses overload so thousands of inside devices can be translated with PAT

**Dynamic NAT/PAT is the best practice for multiple client situation?** True

**Should you filter bogus traffic and perform logging on that traffic?** True

**The problem with shadowed rule implementation:** When a line appears in the wrong order

### 14B - Implementing Cisco IOS ZoneBased Firewalls
https://quizlet.com/403509604/ccna-security-15-flash-cards/

**Which zone is implied by default and does not need to be manually created?**

    a. Inside-zone
    b. Outside-zone
    c. DMZ
    d. √ Self-zone

**If interface number 1 is in zone A, and interface number 2 is in zone B, and there are no policy or service commands applied yet to the configuration, what is the status of transit traffic that is being routed between these two interfaces?**

    a. √ Denied
    b. Permitted
    c. Inspected
    d. Logged

**When creating a specific zone pair and applying a policy to it, policy is being implemented on initial traffic in how many directions?**

    a. 1
    b. 2
    c. 3
    d. Depends on the policy

**What is the default policy between an administratively created zone and the self-zone?**

    a. Deny
    b. Permit
    c. Inspect
    d. Log

**What is one of the added configuration elements that the Advanced security setting has in the ZBF Wizard that is not included in the Low security setting?**

    a. Generic TCP inspection
    b. Generic UDP inspection
    c. √ Filtering of peer-to-peer networking applications
    d. NAT

**Why is it that the return traffic, from previously inspected sessions, is allowed back to the user, in spite of not having a zone pair explicitly configured that matches on the return traffic?**

    a. √ Stateful entries (from the initial flow) are matched, which dynamically allows return traffic.
    b. Return traffic is not allowed because it is a firewall.
    c. Explicit ACL rules need to be placed on the return path to allow the return traffic.
    d. A zone pair in the opposite direction of the initial zone pair (including an applied policy) must be applied for return traffic to be allowed.

**What does the keyword overload imply in a NAT configuration?**

    a. NAT is willing to take up to 100 percent of available CPU.
    b. PAT is being used.
    c. NAT will provide "best effort" but not guaranteed service, due to an overload.
    d. Static NAT is being used

**Which of the following commands shows the current NAT translations on the router?**

    a. show translations
    b. show nat translations
    c. √ show ip nat translations
    d. show ip nat translations *

### Configuring Basic Firewall Policies on Cisco ASA
https://quizlet.com/178121211/ccna-security-ocg-do-i-know-this-already-31-days-study-guide-flash-cards/

**Which of the following features does the Cisco ASA provide? (Choose all that apply.)**

    a. √ Simple packet filtering using standard or extended access lists
    b. √ Layer 2 transparent implementation
    c. √ Support for remote-access SSL VPN connections
    d. Support for site-to-site SSL VPN connections

**Which of the following Cisco ASA models are designed for small and branch offices? (Choose all that apply.)**

    a. √ 5505
    b. √ 5512-X
    c. 5555-X
    d. 5585-X with SSP10

**When used in an access policy, which component could identify multiple servers?**

    a. Stateful filtering
    b. Application awareness
    c. √ Object groups
    d. DHCP services

**Which one is accurate description of the word inbound as it relates to Cisco Adaptive Security Appliance (ASA)? (Choose all that apply.)**

    a. Traffic from a device that is located on a high-security interface
    b. √ Traffic from a device that is located on a low-security interface
    c. √ Traffic that is entering any interface
    d. Traffic that is exiting any interface

**When is traffic allowed to be routed & forwarded if the source of the traffic is from a device located off of a low-security interface if the destination device is located off of a high-security interface? (Choose all that apply.)**

    a. This traffic is never allowed.
    b. √ This traffic is allowed if the initial traffic was inspected and this traffic is the return traffic.
    c. √ If there is an access list that is permitting this traffic.
    d. This traffic is always allowed by default.

**Which of the following tools could be used to configure or manage an ASA? (Choose all that apply.)**

    a. √ Cisco Security Manager (CSM)
    b. √ ASA Security Device Manager (ASDM)
    c. Cisco Configuration Professional (CCP)
    d. √ The command-line interface (CLI)

**Which of the following elements, which are part of the Modular Policy Framework on the ASA, are used to classify traffic?**

    a. √ Class maps
    b. Policy maps
    c. Service policies
    d. Stateful filtering

**When you configure the ASA as a DHCP server for a small office, what default gateway will be assigned for the DHCP clients to use?**

    a. The service provider's next-hop IP address.
    b. The ASA's outside IP address.
    c. √ The ASA's inside IP address.
    d. Clients need to locally configure a default gateway value

**When you configure network address translation for a small office, devices on the Internet will see the ASA inside users as coming from which IP address?**

    a. The inside address of the ASA.
    b. √ The outside address of the ASA.
    c. The DMZ address of the ASA.
    d. Clients will each be assigned a unique global address, one for each user.

**You are interested in verifying whether the security policy you implemente    d. **How can you verify this without involving end users?**

    a. Run the policy check tool, which is built in to the ASA.
    b. The ASA automatically verifies that policy matches intended rules.
    c. √ Use Packet Tracer
    d. You must manually generate the traffic from an end-user device to verify that the firewall will forward it or deny it based on policy.

### 14C - Cisco intrusion detection systems (IDS) / intrusion prevention systems (IPS) Fundamentals
https://quizlet.com/226530774/cisco-ipsids-fundamentals-flash-cards/

**Which method should you implement when it is not acceptable for an attack to reach its intended victim?**

    a. IDS
    b. √ IPS
    c. Out of band
    d. Hardware appliance

**A company has hired you to determine whether attacks are happening against the server farm, and it does not want any additional delay added to the network.**
**Which deployment method should be used?**

    a. Appliance-based inline
    b. IOS software-based inline
    c. Appliance-based IPS
    d. √ IDS

**Why does IPS have the ability to prevent an ICMP-based attack from reaching the intended victim?**

    a. Policy-based routing.
    b. TCP resets are used.
    c. √ The IPS is inline with the traffic.
    d. The IPS is in promiscuous mode.

**Which method of IPS uses a baseline of normal network behavior and looks for deviations from that baseline?**

    a. Reputation-based IPS
    b. √ Policy-based IPS
    c. Signature-based IPS
    d. Anomaly-based IPS

**Which type of implementation requires custom signatures to be created by the administrator?**

    a. √ Reputation-based IPS
    b. Policy-based IPS
    c. Engine-based IPS
    d. Anomaly-based IPS

**Which method requires participation in global correlation involving groups outside your own enterprise?**

    a. √ Reputation-based IPS
    b. Policy-based IPS
    c. Signature-based IPS
    d. Anomaly-based IPS

**Which of the micro-engines contains signatures that can only match on a single packet, as opposed to a flow of packets?**

    a. √ Atomic
    b. String
    c. Flood
    d. Other

**Which of the following are properties directly associated with a signature? (Choose all that apply.)**

    a. √ ASR (Alert Severity Rating)
    b. ARR (Attack Relevancy Rating)
    c. √ SFR (Signature Fidelity Rating)
    d. TVR (Target Value Rating)
    e. RR (Risk Rating)

Note:
75—Low Asset Value
100—Medium Asset value
150—High Asset Value
200—Mission Critical Asset Value

**Which of the following is not a best practice?**

    a. Assign aggressive IPS responses to specific signatures
    b. Assign aggressive IPS responses based on the resulting risk rating generated by the attack
    c. Tune the IPS and revisit the tuning process periodically
    d. Use correlation within the enterprise and globally for an improved security posture

**What is the name of Cisco cloud-based services for IPS correlation?**

    a. √ SIO
    b. EBAY
    c. ISO
    d. OSI

**Which of the following is not a Next-Generation IPS (NGIPS) solution?**

    a. NGIPSv
    b. ASA with FirePOWER
    c. √ SIO IPS
    d. FirePOWER 8000 series appliances

### Unlisted - Advanced Switch Security (only 58% was correct)

**What is the easiest way for an attacker to perform VLAN hopping?**

    a. Perform DHCP starvation
    b. √ Negotiate a trunk using the connection to the access switch
    c. Use multiple virtual machines on the same access port
    d. Implement MAC flooding

**If a switch is working in the fail-open mode, what will happen when the switch’s CAM table fills to capacity and a new frame arrives?**

    a. The switch sends a NACK segment to the frame’s source MAC address.
    b. √? A copy of the frame is forwarded out all switch ports other than the port the frame was received on.
    c. The frame is dropped.
    d. The frame is transmitted on the native VLAN.

**___________ are dynamically learned and stored only in the address tabl    e. MAC addresses configured in this way are removed when the switch restarts.**

    a. Static secure MAC address
    b. √? Dynamic secure MAC address
    c. Sticky secure MAC address
    d. Pervasive secure MAC address

**Why is BPDU guard an effective way to prevent an unauthorized rogue switch from altering the spanning-tree topology of a network?**

    a. BPDU guard can guarantee proper selection of the root bridge.
    b. √? BPDU guard can be utilized along with PortFast to shut down ports when a switch is connected to the port.
    c. BPDU guard can be utilized to prevent the switch from transmitteing BPDUs and incorrectly altering the root bridge election.
    d. BPDU guard can be used to prevent invalid BPDUs from propagating throughout the network.

**How does a switch react when an attacker has flooded the CAM table on the device and the switch receives a unicast frame?**

    a. √? The switch floods the frame.
    b. The switch redirects the frame out the port it was received.
    c. The switch drops the frame.
    d. The switch buffers the frame until the CAM is no longer full.

**Which description correctly describes a MAC address flooding attack?**

    a. The attacking device crafts ARP replies intended for valid hosts. The MAC address of the attacking device then becomes the destination address found in the Layer 2 frames sent by the valid network device.
    b. The attacking device crafts ARP replies intended for valid hosts. The MAC address of the attacking device then becomes the source address found in the Layer 2 frames sent by the valid network device.
    c. The attacking device spoofs a destination MAC address of a valid host currently in the CAM tabl    e. The switch then forwards frames destined for the valid host to the attacking device.
    d. The attacking device spoofs a source MAC address of a valid host currently in the CAM tabl    e. The switch then forwards frames destined for the valid host to the attacking device.
    e. Frames with unique, invalid destination MAC addresses flood the switch and exhaust CAM table spac    e. The result is that new entries cannot be inserted because of the exhausted CAM table space, and traffic is subsequently flooded out all ports.
    f. √? Frames with unique, invalid source MAC addresses flood the switch and exhaust CAM table spac    e. The result is that new entries cannot be inserted because of the exhausted CAM table space, and traffic is subsequently flooded out all ports.

**Which type of Layer 2 attack causes a switch to flood all incoming traffic to all ports?**

    a. MAC spoofing attack
    b. √? CAM overflow attack
    c. VLAN hopping attack
    d. STP attack
 
**Characteristic of the double-encapsulated VLAN hopping attack is that it works even if trunk ports are disabled.**

    a. √? True
    b. False

**When the MAC table is full, the switch enters into what is known as a ________, and starts acting as a hub, broadcasting packets to all the machines on the network.**

    a. failed-open mode
    b. failure-open mode
    c. √? fail-open mode
    d. failed-close mode
    e. fail-close mode

**The BPDU guard feature disables which kind of port when the port receives a BPDU packet?**

    a. any port
    b. nonegotiate port
    c. √? access port
    d. portfast port
    e. root port

**Which statement is currect about Layer 2 security threats?**

    a. MAC spoofing attacks allow an attacking device to receive frames intended for a different network host.
    b. Port scanners are the most effective defense against dynamic ARP inspection.
    c. √? MAC spoofing, in conjunction with ARP snooping, is the most effective counter-measure against reconnaissance attacks that use dynamic ARP inspection (DAI) to determine vulnerable attack points.
    d. Dynamic ARP inspection in conjunction with ARP spoofing can be used to counter DHCP snooping attacks.
    e. DHCP snooping sends unauthorized replies to DHCP queries.
    f. ARP spoofing can be used to redirect traffic to counter dynamic ARP inspection.

**Refering to the exhibit:**

    Switch#show run interface FastEthernet 0/1
    Building configuration...

    Current configuration:** 119 bytes
    !
    interface FastEthernet0/1
     switchport mode access
     switchport port-security
     switchport port-security maximum 5
    end

    Switch#show port-security interface FastEthernet 0/1
    Port Security              :** Enabled
    Port Status                :** Secure-down
    Violation Mode             :** Shutdown
    Aging Time                 :** 0 mins
    Aging Type                 :** Absolute
    SecureStatic Address Aging :** Disabled
    Maximum MAC Addresses      :** 5
    Total MAC Adresses         :** 0
    Configured MAC Addresses   :** 0
    Sticky MAC Addresses       :** 0

**What of attack would be mitigated by this configuration?**

    a. ARP spoofing
    b. MAC spoofing
    c. VLAN hopping
    d. CDP manipulation
    e. √ MAC flood / CAM overflow attack
    f. spanning tree compromises
g. √ DHCP Starvation attack

**Refering to the exhibit on a Cisco Catalyst 3560 Series Switch:**

    Switch# conf t
    Switch(config)# int g0/2
    Switch(config-if)# no switchport
    Switch(config-if)# ip address 192.20.135.21 255.255.255.0
    Switch(config-if)# no shut
    
**What can you determine Level 3 routing functionality of the interface?**

    a. The interface is configured correctly for Layer 3 routing capabilities.
    b. √? The interface needs an additional configuration entry to enable IP routing protocols.
    c. The interface subcommand ip routing is required to enable IP routing on the interface.
    d. An SVI interface is required to enable IP routing for network 192.20.135.0.

**If you change the native VLAN on the trunk port to an unused VLAN, what happens if an attacker attempts a double-tagging attack?**

    a. The trunk port would go into an error-disabled state.
    b. A VLAN hopping attack would be successful.
    c. √? A VLAN hopping attack would be prevented.
    d. The attacked VLAN will be pruned.

**What could prevent users from jumping onto any VLAN they choose to join? (Choose all that appliy.)**

    a. √? Configuring the port connecting to the client as an access port
    b. √? Disabling negotiation of trunk ports
    c. Using something else other than VLAN 1 as the "native" VLAN
    d. Configuring the port connecting to the client as a trunk

**Refering to the exhibit:**

    R2(config)#enable secret kjfd73j3h01!
    R1(config)#aaa new-model
    R1(config)#exit
    R1#

**What command would be the next to create a custom parser view?**

    a. √ parser view
    b. enable view
    c. view enable
    d. configure terminal

**Which of the following features cannot protect the data plane?**

    a. √? policing
    b. ACLs
    c. IPS
    d. DHCP-snooping

**Which feature is a potential security weakness of a traditional stateful firewall?**

    a. It cannot ensure each TCP connection follows a legitimate TCP three-way handshake.
    b. It cannot detect application-layer attacks.
    c. √? It cannot support UDP flows.
    d. The status of TCP sessions is retained in the state table after the sessions terminate.

**When using the ASA Security Appliance as a DHCP server you can configure static address assignments as well as dynamic address assignments from a pool of contiguous IP addresses.**

    a. √? True
    b. False

**Which of the following commands will reset the ASA back to its factory default settings on a Cisco ASA 5510?**

    a. √? write erase
    b. copy factory-config startup-config
    c. configure factory-default
    d. clear configure default
    e. reload /default
    f. restore factory-default

**On the Cisco ASA, what is the default access rule if no user defined access lists are defined on interface?**

    a. All inbound connections from the lower security interfaces to the higher security interfaces are permitted.
    b. All outbound connections from the higher security interfaces to the lower security interfaces are permitted.
    c. All IP traffic between interfaces with the same security level are permitted.
    d. All IP traffic in and out of the same interface is permitted.
    e. √? All IP traffic is denied.

**Which of the following enables RIPv2 on an ASA?**

    a. ripv2 enable
    b. router ripv2
    c. √? router rip
       version 2
    d. router rip

**By default, which access rule is applied inbound to the inside interface?**

    a. √? All IP traffics are denied.
    b. All IP traffic is permitted.
    c. All IP traffic sourced from any source to any less secure network destinations is permitted.
    d. All IP traffic sourced from any source to any more secure network destinations is permitted

**If no ACL is applied to an interface, the following ASA policy is applied:**
 - Outbound packet is permitted by default
 - Inbound packet is denied by default
    a. √? True
    b. False

**After you have configured access to the HTTP server, you also have to add the host that you wish to connect to the firewall's access lists.**

    a. √? True
    b. False

**Which of the following interfaces should normally be assigned a security level of 100?**

    a. outside
    b. dmz
    c. dmz2
    d. √? inside
    e. It doesn't matter because you can assign any level you want.

**Which statement about the Cisco ASA 5505 configuration is true?**

    a. The IP address is configured under the physical interface (ethernet 0/0 to ethernet 0/7).
    b. With the default factory configuration, the management interface (management 0/0) is configured with the 192.168.1.1/24 IP address.
    c. With the default factory configuratoin, Cisco ASDM access is not enabled.
    d. √? The switchport access vlan command can be used to assign the VLAN to each physical interface (ethernet 0/0 to ethernet 0/7).
    e. With the default factory configuration, both the inside and outside interface will use DHCP to acquire its IP address.

**Refering to the exhibits:**

    Rebooting...
    Cisco Secure PIX Firewall Bios (3.6) #0:** Mon May 6
    05:18:49 PST 2000
    Platform PIX-515
    Flash-i28f640J5 @ 0X300

    Use BREAK or ESC to interrupt flash boot.
    User SPACE to begin flash boot immediately.
    Flash boot interrupted
    0:** i8255x @ PCI(bus:0 dev:13 irq:10)
    1:** i8255x @ PCI(bus:0 dev:14 irq:7)
    2:** i8255x @ PCI(bus:1 dev:0 irq:11)
    3:** i8255x @ PCI(bus:1 dev:1 irq:11)
    4:** i8255x @ PCI(bus:1 dev:2 irq:11)
    5:** i8255x @ PCI(bus:1 dev:3 irq:11)
    
**The firewall is running in which mode?**

    a. Unprivileged mode
    b. Privileged mode
    c. Configuration mode
    d. Monitor mode
    e. √? Setup mode

**Refering to the exhibits:**

    Firewall(config)# interface
      gigabitethernet0
    Firewall(config-if)# speed auto
    Firewall(config-if)# duplex auto
    Firewall(config-if)# nameif inside
    Firewall(config-if)# security-level 100
    Firewall(config-if)# ip address
    172.16.1.1
      255.255.0.0

    Firewall(config)# interface
      gigabitethernet0
    Firewall(config-if)# speed auto
    Firewall(config-if)# duplex auto
    Firewall(config-if)# nameif outside
    Firewall(config-if)# security-level 0
    Firewall(config-if)# ip address
    172.17.1.1
      255.255.0.0
    Firewall(config)# interface
      gigabitethernet0
    Firewall(config-if)# speed auto
    Firewall(config-if)# duplex auto
    Firewall(config-if)# nameif inside
    Firewall(config-if)# security-level 50
    Firewall(config-if)# ip address
    172.18.1.1
      255.255.0.0

**Which software version is this Cisco Security Appliance OS running at?**

    a. PIX 5.1
    b. PIX 6.5
    c. PIX 6.3
    d. √? ASA

**Refering to the exhibits:**

    Firewall# show route
    O IA 192.168.167.1 255.255.255.255
    [110/11] via 192.168.198.4, 82:39:36, inside
    C 192.168.198.0 255.255.255.0 is directly connected, inside
    C 128.163.93.128 255.255.255.128 is directly connected, outside
    S* 0.0.0.0 0.0.0.0 [1/0] via 128.163.93.129, outside
    Firewall#

**Which software version is this Cisco Security Appliance OS running at?**

    a. PIX 6.3
    b. √? ASA

**In a Zone-Based Firewall which action(s) permit the traffic from firewall in the direction of zone pair? (Choose all that apply.)**

    a. Permit
    b. √ Inspect
    c. Prioritize
    d. √ Pass

**In legacy Cisco IPS, when does a signature consume memory?**

    a. √? **When it is retired and disabled
    b. **When it is unretired and enabled
    c. **When it is retired and enabled
    d. **When it is simply enabled

**A security mechanism has the following attributes:**
    it is a sensor appliance
    it searches for potential attacks by capturing and analyzing traffic
    it is a "purpose-built device"
    it is installed passively
    it introduces no delay or overhead
**Which security mechanism is this?**

    a. √? NIDS
    b. PIX
    c. IKE
    d. HIPS
    e. HMAC

**What is the default policy between an administratively created zone and the self zone?**

    a. √ Permit
    b. Deny
    c. Inspect
    d. Log

**Which of the following is true when NAT control is enabled?**

    a. Translation rules are not required, but will be performed if configured.
    b. Configuration of translation rules is not permitted.
    c. Translation rules are required for all transit traffic.
    d. √ Translation rules are required only for sessions initiated on a higher-security interface, bound for a lower-security interface.

**_________ was used in features that support Cisco TrustSec by including the group in an extended ACL, which in turn can be used in an access rule.**

    a. ICMP-type
    b. User
    c. √? Security
    d. Protocol
    e. Network

**You have decided to practice your CLI skills instead of using the ASDM interface to configure a security policy in the MPF.**
**Which of the following should be configured first?**

    a. A class map
    b. √ A policy map
    c. A service policy
    d. An access policy
    e. A service map
    f. An access map
