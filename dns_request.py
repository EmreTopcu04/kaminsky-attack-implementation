from scapy.all import *

# DNS Question Section
# Using a random subdomain to bypass the recursive resolver's cache
query_name = 'abcde.example.com'
dns_question = DNSQR(qname=query_name)

# DNS Header Configuration
dns_header = DNS(id=0xAAAA, qr=0, qdcount=1, ancount=0, nscount=0, arcount=0, qd=dns_question)

# Network Layers (IP and UDP)
# Target: Local Recursive DNS Server (IP: 10.9.0.53)
ip_layer = IP(dst='10.9.0.53', src='10.9.0.5') 
udp_layer = UDP(dport=53, sport=12345, chksum=0)

# Assemble and transmit the DNS Query packet
dns_packet = ip_layer/udp_layer/dns_header
send(dns_packet, verbose=0)
