# analyse-packets-with-wireshark
This project opens a packet capture (`.pcap`) file and explores the basic Wireshark Graphical User Interface. It opens a detailed view of a single packet and explores how to examine the various protocol and data layers inside a network packet. It applies filters to TCP packet data to search for specific payload text data.

## Step 1: Explore data with Wireshark.
Let’s open a network packet capture file called `sample` as pointed to by the 2nd arrow, which contains data captured from a system that made web requests to a site. We need to open this data with Wireshark to get an overview of how the data is presented in the application.

Wireshark is already installed on Windows, as indicated by the 1st arrow. To open the packet capture file, double-click the `sample` file, as shown by the 2nd arrow below on the Windows desktop. This will start Wireshark. Note that the sample packet capture file has a `.pcap` file extension, which is hidden by default in Windows Explorer and the desktop view.<br>
**View: [step1A](sreenshots/step1A)**

After we double-click the sample pcap file, the Wireshark window below will be displayed. Many network packet traffic is listed, so we will apply filters to find the information needed.

The area pointed to by the 1st arrow is the `filter text box` used to filter and select intended network traffic. As pointed out by the 2nd arrow, you can scroll up and down the Wireshark interface to view more network traffic.<br>
**View: [step1B](sreenshots/step1B)**

Scroll down the packet list until a packet is listed where the `info` column starts with the words `Echo (ping) request` as pointed to by the 1st arrow. The 2nd arrow points to the `ICMP` Protocol contained in the traffic.<br>
**View: [step1C](sreenshots/step1C)**

**Let us look at common Protocol Names and their meaning.**
- **ARP** (Address Resolution Protocol) --> used to map IP addresses to MAC addresses.
- **IP** (Internet Protocol) --> used for routing and addressing packets.
- **TCP** (Transmission Control Protocol) --> used for reliable data transport.
- **UDP** (User Datagram Protocol) --> used for faster, connectionless transport.
- **DNS** (Domain Name System) --> This protocol translates domain names to IPs.
- **HTTP/HTTPS** (HyperText Transfer Protocol Secure) --> use in web traffic for regular and secure browser/server communication.
- **ICMP** (Internet Control Message Protocol) --> used in ping and traceroute.
- **TLS** (Transport Layer Security) --> used for encrypted communication.
- **SSH** (Secure SHell) --> used to connect to a system remotely (Secure remote login).
- **FTP** (File Transfer Protocol) -->  used for file transfers between client and server.
- **SMTP** (Simple Mail Transfer Protocol)--> Used in email delivery or sending email, but not for receiving email.
- **IMAP** (Internet Message Access Protocol) --> used to retrieve emails from a mail server to your device (computer, phone, or app), but not for sending email.
- **POP3** (Post Office Protocol v3) --> This is also used to retrieve emails from a mail server to your device, but not for sending email.

## Step 2: Apply a basic Wireshark filter and inspect a packet.
**An overview of the key property columns listed for each packet:**
- **No.:** The index number of the packet in this packet capture file.
- **Time:** The timestamp of the packet.
- **Source:** The source IP address. The IP address from which the traffic emanates.
- **Destination:** The destination IP address. The IP address where the traffic is expected to go.
- **Protocol:** This is the protocol contained in the packet.
- **Length:** The total length of the packet.
- **Info:** Some information about the data in the packet (the payload) as interpreted by Wireshark.

The 1st arrow points to the name of the file currently opened in Wireshark. The 2nd arrow points to the filter text box. Inside the filter text box, we can run queries as pointed to by the 3rd arrow to return, extract, or filter network traffic. When the `filter text box turns `pink` after inputting the query, as shown below, it means the command/query entered is wrong. The query `ip.address` is a bad syntax. But when the `filter text box` turns `green` after inputting the query, it means that the syntax is correct. For example, instead of `ip.address`, the correct syntax is  `ip-addr`.

The 4th arrow points to the packets columns starting from `No` all the way to `Info`. Click on `x` as pointed to by the 6th arrow to cancel the query you entered, or click on the Apply Display Filter symbol as pointed to by the 5th arrow to run/execute the query entered.<br>
**View: [step2A](sreenshots/step2A)**

Enter the query below to filter for traffic associated with the specified IP address, i.e `142.250.1.139`.
```wireshark
ip.addr == 142.250.1.139 
```
Press `ENTER` or click the Apply display filter icon located at the end of the filter text box. Because the filter/query syntax is correct, the filter text box turns `green` as shown below.<br>
**View: [step2B](sreenshots/step2B)**

The `details pane` is located at the bottom portion of the main Wireshark window, as pointed to by the first and second arrows. This can be opened in a completely separate window when you double-click a particular packet from the main Wireshark window.<br>
**View: [step2C](sreenshots/step2C)**

The above `details pane` can also be accessed in a new window by double-clicking a packet. The upper section of the window below contains `subtrees` where Wireshark will provide you with an analysis of the various parts of the network packet. As illustrated below, the upper section of the window, as indicated by the first arrow, contains subtrees (`e.g. Frame, Ethernet II, Internet Protocol Version 4 and Transmission Control Protocol`) where Wireshark will provide you with an analysis of the various parts of the network packet. The lower section of the window, as indicated by the second arrow, contains the `raw packet data` displayed in `hexadecimal` and `ASCII` text. There is also `placeholder text` for fields where the character data does not apply, as indicated by the dot `.`
> Double-click any of the subtrees in the upper section to have a detailed view of all information about the data packet.

**View: [step2D](sreenshots/step2D)**

Double-click the `Frame` subtree to view details about the overall network packet, or frame, including the `frame length` and the `arrival time` of the packet. At this level, we are viewing information about the entire packet of data.

Double-click `Frame` again to collapse the subtree, and then double-click the `Ethernet II` subtree. This item contains details about the packet at the Ethernet level, including the source and destination MAC addresses and the type of internal protocol that the Ethernet packet contains.

Double-click `Ethernet II` again to collapse that subtree and then double-click the `Internet Protocol Version 4` subtree. This provides packet data about the Internet Protocol (`IP`) data contained in the Ethernet packet. It contains information such as the source and destination IP addresses and the Internal Protocol (for example, `TCP` or `UDP`), which is carried inside the IP packet. The `Internet Protocol Version 4` subtree is Internet Protocol Version 4 (`IPv4`). The third subtree label reflects the protocol. The source and destination IP addresses shown here match the source and destination IP addresses in the summary display for this packet in the main Wireshark window.

Double-click `Internet Protocol Version 4` again to collapse that subtree, and then double-click the `Transmission Control Protocol` subtree. This provides detailed information about the TCP packet, including the `source` and `destination TCP ports`, the `TCP sequence numbers`, and the `TCP flags`.

## Step 3: Use filters to select packets.
We will use filters to analyse specific network packets based on where the packets come from or where they are sent to. We will explore how to select packets using either their physical Ethernet Media Access Control (`MAC`) address or their `Internet Protocol (IP)` address.

**Filter traffic for a specific source IP address only.**
```wireshark
ip.src == 142.250.1.139
```
A filtered list is returned with fewer entries than before. It contains only packets that came from `142.250.1.139` as pointed to by the 2nd arrow. Notice that all the `IPs` under the `Source` column match the `IP` we filtered in the `filter text box`.<br>
**View: [step3A](sreenshots/step3A)**

**Next, let's filter to select traffic for a specific destination IP address only.**
```wireshark
ip.dst == 142.250.1.1399
```
A filtered list is returned that contains only packets that were sent to `142.250.1.139` as pointed to by the 2nd arrow. Notice that all the `IPs` under the `Destination` column match the `IP` we filtered in the `filter text box`, as pointed to by the 1st arrow.<br>
**View: [step3B](sreenshots/step3B)**

Enter the following filter to select traffic to or from a specific `Ethernet MAC address`. This filters traffic related to one MAC address, regardless of the other protocols involved.
```wireshark
eth.addr == 42:01:ac:15:e0:02
```
Double-click the first packet in the list as pointed to by the 2nd arrow. Double-click the `Ethernet II` subtree if it is not already open as pointed to by the 3rd arrow. The `MAC` address you specified in the filter is listed as either the source or destination address in the expanded `Ethernet II` subtree; in this case, it is listed as the source address as pointed to by the 4th arrow.<br>
**View: [step3C](sreenshots/step3C)**

Double-click the `Internet Protocol Version 4` subtree to expand it as pointed to by the 1st arrow and scroll down until the `Time to Live` and `Protocol` fields appear as pointed to by the 2nd arrow.<br>
**View: [step3D](sreenshots/step3D)**
> Always double-click a subtree that is already open to close or collapse it.

## Step  4: Use filters to explore DNS packets.
We will use filters to select and examine `DNS` traffic. Once you have selected sample `DNS` traffic, we will drill down into the protocol to examine how the DNS packet data contains both `Queries` (names of internet sites that are being looked up) and `Answers` (IP addresses that are being sent back by a DNS server when a name is successfully resolved).

Enter the following filter to select `UDP port 53` traffic. `DNS traffic` uses `UDP port 53`, so this will list traffic related to DNS queries and responses only. Enter this into the Apply a display filter... text box immediately above the list of packets.
```wireshark
udp.port == 53
```
Click on the first packet as pointed to by the 2nd arrow to highlight it, or we can double-click the first packet in the list to open the detailed packet window. Notice that the `Protocol` column contains only `DNS`, just as described in the filter text box.<br>
**View: [step4A](sreenshots/step4A)**

Scroll down and double-click the `Domain Name System (query)` subtree as pointed to by the 1st arrow to expand it. You will notice that the name of the website that was queried is `opensource.google.com`, as indicated by the 2nd and 3rd arrow.<br>
**View: [step4B](sreenshots/step4B)**

Let us again double-click the fourth packet in the list as pointed to by the 1st arrow to open the detailed packet window.<br>
**View: [step4C](sreenshots/step4C)**

Scroll down and double-click the `Domain Name System (query)` subtree to expand it. Click `Answers` as pointed by the first arrow, which is in the `Domain Name System (query)` subtree. The `Answers` data includes the names that were queried (`opensource.google.com`) as pointed to by the 2nd arrow and the `IP addresses` that are associated with the names, as pointed to by the 3rd arrow. The 4th arrow points to the `time` it takes to look up the name.<br>
**View: [step4D](sreenshots/step4D)**

## Step 5: Use filters to explore TCP packets.
We will use additional filters to select and examine `TCP packets`. We will learn how to search for text that is present in `payload` data contained inside network packets. This will locate packets based on something such as a name or some other text that is of interest to us.

Enter the query below to select TCP port 80 traffic.
```wireshark
tcp.port == 80
```
`TCP port 80` is the default port that is associated with `web traffic`. Click the first packet in the list as pointed to by the 2nd arrow. The `Destination IP address` of this packet is `169.254.169.254`. The 3rd arrow points to the `detailed pane` of the selected traffic, which comprises of subtrees.<br>
**View: [step5A](sreenshots/step5A)**

In the `detail pane`, we will look up the `Time to Live` value as pointed to by the 2nd arrow, `Header Length` as pointed to by the 1st arrow, and `Destination Address` of the packet as pointed to by the 3rd arrow specified in the `Internet Protocol Version 4` subtree.<br>
**View: [step5B](sreenshots/step5B)**

and the `Frame Length` as pointed to by the 2nd arrow specified in the `Frame` subtree of the packet subtree in the `detailed pane` as pointed to by the 1st arrow.<br>
**View: [step5C](sreenshots/step5C)**

Let's also enter the query below to select `TCP packet` data that contains specific text data.
```wireshark
tcp contains "curl"
```
Click the `Hypertext Transfer Protocol` subtree in the `detailed pane` as pointed to by the 2nd arrow. The 3rd arrow points to the `user-agent`, which contains the text `curl`.
**View: [step5D](sreenshots/step5D)**

Seeing `curl` in the `User-Agent` string during a security investigation or analysis indicates that a request to the server was made using the `curl command-line tool`, not a standard web browser like Chrome or Firefox. Attackers, researchers, or bots often use `curl` in scripts to send automated requests. Sometimes, the `curl` is often used to bypass browser protections, headers, or cookies.

> The curl command-line tool is used for both legitimate and malicious purposes. Therefore, the context used matters a lot. For example, check if curl requests are hitting sensitive endpoints like `/login`, `/admin`, etc.

## Summary.
This article describes the process of analysing network packet data using Wireshark. It begins with opening a packet capture file (`.pcap`) in Wireshark and exploring the basic Graphical User Interface. We then guide through applying filters to select specific packets based on criteria such as `IP address`, `MAC address`, or `protocol`.

It also explains how to inspect individual packets in detail, showing how to examine different protocol layers (`Ethernet, IP, TCP`) and their data. It further demonstrates how to filter and inspect specific types of traffic, like DNS or TCP traffic, and how to search for specific text within packet payloads.

## LinkedIn Article.
- [Analyse Packets with Wireshark]()<br>

## Connect with me.
[🔗 LinkedIn](https://www.linkedin.com/in/agbuenoch)<br>
[🔗 X](https://www.x.com/agbuenoch)

