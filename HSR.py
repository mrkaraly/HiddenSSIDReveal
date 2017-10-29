#!/usr/bin/python3
import socket
from termcolor import colored, cprint
from scapy.all import *
asciart = colored(''' _   _ _     _     _              _____ _____ ___________  ______                     _ 
| | | (_)   | |   | |            /  ___/  ___|_   _|  _  \ | ___ \                   | |
| |_| |_  __| | __| | ___ _ __   \ `--.\ `--.  | | | | | | | |_/ /_____   _____  __ _| |
|  _  | |/ _` |/ _` |/ _ \ '_ \   `--. \`--. \ | | | | | | |    // _ \ \ / / _ \/ _` | |
| | | | | (_| | (_| |  __/ | | | /\__/ /\__/ /_| |_| |/ /  | |\ \  __/\ V /  __/ (_| | |
\_| |_/_|\__,_|\__,_|\___|_| |_| \____/\____/ \___/|___/   \_| \_\___| \_/ \___|\__,_|_|
                                                                                        

                      by Mr.Kara                                                       ''','red')
print (asciart)
inter_face= input("input the interface name: ")
pakets_num= input("input the number of packets: ")
hidden_ssid_aps = set()
def PacketHandler(pkt):
	if pkt.haslayer(Dot11Beacon):
		if not pkt.info:
			if pkt.addr3 not in hidden_ssid_aps:
				hidden_ssid_aps.add(pkt.addr3)
				print("Hidden SSID Network Found, BSSID: " , pkt.ddr3 )
	elif pkt.haslayer(Dot11ProbeRes) and (pkt.addr3 in hidden_ssid_aps):
		print ("Hidden SSID Revealed: ", pkt.info , pkt.addr3)
sniff(iface = inter_face , count =int(pakets_num) , prn = PacketHandler)
