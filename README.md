# SYNFloodDetector

Python script to detect SYN floods, it can connect to a router and enable/disable the TCPintercept command found on Cisco Routers. 
https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_data_dos_atprvn/configuration/15-mt/sec-data-dos-atprvn-15-mt-book/sec-cfg-tcp-intercpt.html

The script is designed for Linux operating systems and should be run as root.
![image](https://user-images.githubusercontent.com/131812058/234381308-f5885015-839d-4aeb-bbc8-7da50862e12f.png)

The script has three modes: “Sniffer mode”, “Manual defender mode”, and “Dynamic defender mode”. The first mode acts as a packet sniffer for SYN packets and will calculate and print statistics to a CSV file.
This mode ties in with the Manual defender mode as it allows users to determine appropriate values for the threshold and interval. The final mode, Dynamic defender, calculates a moving average of SYNs per second and compares the current and previous of these averages to determine if there is an attack occurring.

