# analyse-packets-with-wireshark
This project opens a packet capture (pcap) file and explores the basic Wireshark Graphical User Interface. It opens a detailed view of a single packet and explores how to examine the various protocol and data layers inside a network packet. It applies filters to TCP packet data to search for specific payload text data.

## Step 1: Explore data with Wireshark.
Let’s open a network packet capture file called sample as pointed to by the 2nd arrow, which contains data captured from a system that made web requests to a site. We need to open this data with Wireshark to get an overview of how the data is presented in the application.

Wireshark is already installed on Windows, as indicated by the 1st arrow. To open the packet capture file, double-click the sample file, as shown by the 2nd arrow below on the Windows desktop. This will start Wireshark. Note that the sample packet capture file has a .pcap file extension, which is hidden by default in Windows Explorer and the desktop view.<br>
**View: [step1A](sreenshots/step1A)**

After we double-click the sample pcap file, the Wireshark window below will be displayed. Many network packet traffic is listed, so we will apply filters to find the information needed.

The area pointed to by the 1st arrow is the filter text box used to filter and select intended network traffic. As pointed out by the 2nd arrow, you can scroll up and down the Wireshark interface to view more network traffic.<br>
**View: [step1B](sreenshots/step1B)**

Scroll down the packet list until a packet is listed where the info column starts with the words 'Echo (ping) request' as pointed to by the 1st arrow. The 2nd arrow points to the ICMP Protocol contained in the traffic.<br>
**View: [step1C](sreenshots/step1C)**

Let us look at common Protocol Names and their meaning.

ARP (Address Resolution Protocol) --> used to map IP addresses to MAC addresses.

IP (Internet Protocol) --> used for routing and addressing packets.

TCP (Transmission Control Protocol) --> used for reliable data transport.

UDP (User Datagram Protocol) --> used for faster, connectionless transport.

DNS (Domain Name System) --> This protocol translates domain names to IPs.

HTTP/HTTPS --> use in web traffic for regular and secure browser/server communication.

ICMP (Internet Control Message Protocol) --> used in ping and traceroute.

TLS (Transport Layer Security) --> used for encrypted communication.

SSH (Secure SHell) --> used to connect to a system remotely (Secure remote login).

FTP (File Transfer Protocol) -->  used for file transfers between client and server.

SMTP (Simple Mail Transfer Protocol)--> Used in email delivery or sending email, but not for receiving email.

IMAP (Internet Message Access Protocol) --> used to retrieve emails from a mail server to your device (computer, phone, or app), but not for sending email.

POP3 (Post Office Protocol v3) --> This is also used to retrieve emails from a mail server to your device, but not for sending email.

## Step 2: Apply a basic Wireshark filter and inspect a packet.
**An overview of the key property columns listed for each packet:**
- No.: The index number of the packet in this packet capture file.
- Time: The timestamp of the packet.
- Source: The source IP address. The IP address from which the traffic emanates.
- Destination: The destination IP address. The IP address where the traffic is expected to go.
- Protocol: This is the protocol contained in the packet.
- Length: The total length of the packet.
- Info: Some information about the data in the packet (the payload) as interpreted by Wireshark.

The 1st arrow points to the name of the file currently opened in Wireshark. The 2nd arrow points to the filter text box. Inside the filter text box, we can run queries as pointed to by the 3rd arrow to return, extract, or filter network traffic. When the filter text box space turns pink after inputting the query, as shown below, it means the command/query entered is wrong. The query ip.address is a bad syntax. But when the filter text box space turns green after inputting the query, it means that the syntax is correct. For example, instead of ip.address, the correct syntax is  ip-addr.

The 4th arrow points to the packets columns starting from No all the way to Info. Click on X as pointed to by the 6th arrow to cancel the query you entered, or click on the Apply Display Filter symbol as pointed to by the 5th arrow to run/execute the query entered.
**View: [step2A](sreenshots/step2A)**

Enter the query:
```wireshark
ip.addr == 142.250.1.139 
```

**View: [step2A](sreenshots/step2A)**
```bash
ip.addr == 142.250.1.139 
```


## LinkedIn Article.
- [Analyse Packets with Wireshark]()<br>

## Connect with me.
[🔗 LinkedIn](https://www.linkedin.com/in/agbuenoch)<br>
[🔗 X](https://www.x.com/agbuenoch)

```
ip.addr == 142.250.1.139 
```
