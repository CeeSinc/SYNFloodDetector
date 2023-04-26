#!/usr/bin/python3

"""
Authour: Callum Sinclair

This script is designed to detect SYN flood attacks,
it is made to work with Linux and must be run as root.
To avoid SYN floods affecting the device the script
runs on, an IPtables rule is recomended:

sudo iptables -A INPUT -p tcp --syn -j DROP

This makes sure all incoming SYN packets are dropped.
"""

import socket
import struct
import time
from datetime import datetime
import sys
import signal
from multiprocessing import Process, Pipe, Queue, Value, RawValue
from queue import Empty, Full
import csv
import paramiko
import atexit

# {
# used in TCPpackets function
# creates a custom exception
# raises exception
# tells signal to execute 'timeout_handler' when alarm is received'


class TimeoutException(Exception):
    pass


def timeout_handler(signum, frame):
    raise TimeoutException


signal.signal(signal.SIGALRM, timeout_handler)

# }


def handle_ctrl_c(signal, frame):
    """
    exits the program when CTRL+C is used
    """
    sys.exit(130) # exits the program with exit code 130
    
    
signal.signal(signal.SIGINT, handle_ctrl_c) # when ctrl+c do handle_ctrl_c


def on_exit():
    """
    At script termination will notify user and print Total SYNs detected in the session
    Can also print to CSV
    """
    print("\n\n" + "~"*21 + "Exiting" + "~"*22)
    if choice_shared.value == 1:
        end = datetime.utcnow() # records endtime
        endstring = str(end)
        duration = end - start # duration
        timestring = str(duration)
        seconds = duration.total_seconds() # duration in seconds
        # writes data to csv file
        with open("SYNhistory.csv", 'a') as file:
            writer = csv.writer(file)
            writer.writerow(["end: ",endstring])
            writer.writerow(["duration: ",timestring])
            writer.writerow(["Total SYNs: ",total_syn_count.value])
            writer.writerow(["Average SYN/s: ",("{:.2f}".format(total_syn_count.value/seconds))])
    print("Total SYNs Detected: {}".format(total_syn_count.value))


atexit.register(on_exit)


def tcppackets(conn):
    """
    receives data from chosen interface, upacks the data and checks
    if SYN is set. Then counts calculates the number of SYN per second
    and sends the value to the funtion "tcpcount".
    """
    # ignores ctrl+c signal (will close with main process anyway since daemon)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    # defines interface to be used
    interface = "ens33"
    # creates a raw Packet socket
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    # binds the socket with the interface
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, str(interface + '\0').encode('utf-8'))
    
    while True:
        syn_count = 0 # resets syn_count
        signal.alarm(1) # starts 1 second alarm
        try:
            while True: # counts the amount of SYNs received per second
                data = s.recvfrom(65535)
                # puts the data in a tuple
                data = data[0]
                # unpacks the Version+IHL and protocol from IP header
                # (Ethernet header = 14 bytes)
                ip_h = struct.unpack("!BBHHHBB", data[14:14+10])
                proto = ip_h[6]
                if proto == 6: # if protocol is TCP
                    # calculates where the start of the TCP header is
                    ver_hl = ip_h[0]
                    hl = (ver_hl & 0xF) * 4
                    tcp_h = data[14+hl:14+hl+14]
                    # ^     data[eth header+IP header len:eth header+IP header len+first 14 bytes from TCP header])
                    # take the first 14 bytes from the TCP header
                    unpack_tcp = struct.unpack("!HHLLH", tcp_h)
                    flags = unpack_tcp[4]
                    # gets the value for SYN flags
                    syn = (flags & 0x02) >> 1
                    ack = (flags & 0x10) >> 4

                    if syn == 1 and ack == 0:
                        syn_count = syn_count + 1
                        total_syn_count.value += 1
                
        except TimeoutException: # exception raised after one second
            # sends to tcpcount
            conn.send(syn_count)           


def tcpcount(conn, queue):
    """
    receives data from function tcppackets and counts the amount
    of SYN packets received in one second, and uses this to calculate
    totals and averages.
    also keeps track of total SYN count,
    """
    # ignores ctrl+c signal (will close with main process anyway since daemon)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    # defines variables and lists
    syn_minute = []
    syn_hour = []
    syn_interval = []
    movingave = []
    syn = 0
    sniffmode = False
    mdefencemode = False
    defencemode = False
    
    if choice_shared.value == 1:
        sniffmode = True
    elif choice_shared.value == 2:
        mdefencemode = True
        user_interval = interval.value
    elif choice_shared.value == 3:
        defencemode = True
           
    while True:
            try:
                syn = conn.recv()
            except EOFError:
                continue
                            
            if sniffmode:
                # if user selects sniffmode, more data prints to console and data is saved to file
                print("SYN/s: ", syn, "   ", end="\r", flush=True)
                syn_minute.append(syn)
                
                if len(syn_minute) == 60: # 1 minute
                    syn_hour.append((sum(syn_minute)))
                    total = (sum(syn_minute))
                    average = ("{:.2f}".format((sum(syn_minute)/60)))
                    print("Total SYN per minute: {}".format(total))
                    print("Average SYN per second in last minute: {}".format(average))
                    with open("SYNhistory.csv", 'a') as file:
                        writer = csv.writer(file)
                        writer.writerow(["Total SYN/m: ",str(total)])
                        writer.writerow(["Average SYN/s in last minute: ",str(average)])
                    syn_minute.clear()
                    
                    if len(syn_hour) == 60: # 1 hour
                        total = (sum(syn_hour))
                        average = ("{:.2f}".format((sum(syn_hour)/3600)))
                        average_min = ("{:.2f}".format((sum(syn_hour)/60)))
                        print("\nTotal SYN per hour: {}".format(total))
                        print("Average SYN per second in last hour: {}".format(average))
                        print("Average SYN per minute in last hour: {}\n".format(average_min))
                        with open("SYNhistory.csv", 'a') as file:
                            writer = csv.writer(file)
                            writer.writerow(["Total SYN/h: ",str(total)])
                            writer.writerow(["Average SYN/s in last hour: ",str(average)])
                            writer.writerow(["Average SYN/m in last hour: ",str(average_min)])
                        syn_hour.clear()
                    
            elif mdefencemode:
                # if user selects defense mode, calculate the SYNs per user defined interval
                syn_interval.append(syn)
                if len(syn_interval) == user_interval:
                    total = sum(syn_interval)
                    averagesyn = total // user_interval
                    print("Total SYN per interval: {}\nAverage SYN per second in last interval: {}     "
                    .format(total, averagesyn))
                    try:
                        queue.put(averagesyn, block=False) # puts the value in the queue for main to get
                    except Full:
                        queue.get() # empties the queue
                    syn_interval.clear()
            
            elif defencemode:
                # if user selects dynamic defence mode, calculates the moving average of the last ten seconds
                movingave.append(syn)
                if len(movingave) == 10:
                    ave = sum(movingave) // 10
                    print("Average SYN/s: {}".format(ave))
                    try:
                        queue.put(ave, block=False) # puts the value in the queue for main to get
                    except Full:
                        queue.get() # empties the queue
                    del movingave[0]         

            continue


def SSHrouter(command):
    """
    Sets up an SSH connection and sends the specified command.
    used to turn on/off the TCP intercept feature (Cisco IOS)
    """
    ip = "192.168.20.1"
    user = "admin"
    Password = "P@ssw0rd"
    Port = 22
    
    if "no" in command:
        text = " OFF"
    else:
        text = "  ON"
    
    print("\033[33;1;4m~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Connecting to Router\033[0m")
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # sets up an SSH connection with the Router
        ssh.connect(ip, port=Port, username=user, password=Password, look_for_keys=False, allow_agent=False)
        connection = ssh.invoke_shell()
        connection.send("enable\n")
        time.sleep(.5)
        connection.send("P@ssw0rd\n")
        time.sleep(.5)
        connection.send("conf t\n")
        connection.send(command) # inputs the command to turn on/off an access list
        connection.send("\nend\n")
        connection.close()
        print("\033[33;1;4m~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~TCP Intercept:" + text + "\033[0m")
    except paramiko.ssh_exception.NoValidConnectionsError:
        print("\033[33;1;4m~~~~Could not establish a connection to the Router\033[0m")
    except paramiko.ssh_exception.SSHException:
        print("\033[33;1;4m~~~~Could not establish a connection to the Router\033[0m")
    except socket.error:
        print("\033[33;1;4m~~~~Could not establish a connection to the Router\033[0m")


def usrchoice():
    """
    Gives the user a menu and records user response
    """
    print("\n" + "~"*50)
    print("SYN Flood Detector".center(50))
    print("~"*50)
    print("~~~~~~~~~At any time press ctrl+c to exit~~~~~~~~~\n")
    while True:
        option1 = "Sniffer Mode"
        option2 = "Manual Defender Mode"
        option3 = "Dynamic Defender Mode"
        options = "Options:\n\t[1]: {}\n\t[2]: {}\n\t[3]: {}\nChoice: ".format(option1, option2, option3)
        user_input = input(options)
        if user_input == "1" or user_input == "2" or user_input == "3":
            return user_input
        else:
            print("\n~~~~~~~~~~~~~~Select a valid option~~~~~~~~~~~~~~~\n")
               
 
q = Queue(maxsize = 1) # creates a queue with size 1, used to share data between TCPcount and main
    
    
def main(queue):
    # defines global variables used across functions
    global total_syn_count
    global interval
    global choice_shared
    global start
    # defines shared variables used across processes
    total_syn_count = RawValue('i', 0)
    interval = Value('i', 0)
    choice_shared = Value('i', 0)
    
    choice = usrchoice()
    if choice == "1":
        print("\n" + "~"*50)
        print("Sniffing for SYNs...".center(50))
        print("~"*50 + "\n")
        choice_shared.value = 1
    elif choice == "2":
        print("")
        while True: # trys to get user input for interval
            try:
                user_interval = int(input("Interval(seconds): "))
            except ValueError:
                print("\n~~~~~~~~~~~~~~~~~Enter a number~~~~~~~~~~~~~~~~~~~\n")
                continue
            interval.value = user_interval
            break
        while True: # trys to get user input for threshold
            try:
                threshold = float(input("Threshold: "))
            except ValueError:
                print("\n~~~~~~~~~~~~~~~~~Enter a number~~~~~~~~~~~~~~~~~~~\n")
                continue
            break
        print("\n" + "~"*50)
        print("Detecting for SYN floods".center(50))
        print("~"*50 + "\n")
        choice_shared.value = 2
    elif choice == "3":
        print("\n" + "~"*50)
        print("Detecting for SYN floods".center(50))
        print("~"*50 + "\n")
        choice_shared.value = 3
        
    conn1, conn2 = Pipe(duplex=False)  # creates a pipe between TCPcount(receiver) and TCPpackets(sender)
    # create two processes with pipe between
    tcp_packets = Process(target=tcppackets, daemon=True, args=(conn2,), name="TCPpackets")
    tcp_count = Process(target=tcpcount, daemon=True, args=(conn1,q), name="TCPcount")
    start = datetime.utcnow() # records start time of SYN detection
    startstring = str(start)
    
    if choice == "1":
        with open("SYNhistory.csv", 'a') as file:
            writer = csv.writer(file)
            writer.writerow(["~~~~~~~"])
            writer.writerow(["start: ",startstring])
    
    # starts the two processes       
    tcp_packets.start()
    tcp_count.start()
    
    if choice == "2": # checks if amount of SYNs in interval > threshold
        # TCP intercept set to intercept traffic matching ACL 100:
        intercept_on = "access-list 100 permit tcp any host 192.168.20.100 eq 80"
        intercept_off = "no access-list 100 permit tcp any host 192.168.20.100 eq 80"
        flood = False
        
        while True:
            try:
                averagesyn = queue.get(block=False) # gets average from TCPcount
            except Empty:
                continue
            if not flood: # if current average > threshold: Flood
                if averagesyn < threshold or averagesyn == threshold:
                    print("\033[32;1;4m~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Normal Traffic\033[0m", end="\r", flush=True)
                elif averagesyn > threshold:
                    print("\033[31;1;4m~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Probable Flood\033[0m")
                    SSHrouter(intercept_on)
                    flood = True
            elif flood: # checks if SYN flood is still happening
                if averagesyn > threshold:
                    print("\033[31;1;4m~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Probable Flood\033[0m", end="\r", flush=True)
                elif averagesyn < threshold or averagesyn == threshold:
                    print("\033[32;1;4m~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Normal Traffic\033[0m")
                    SSHrouter(intercept_off)
                    flood = False 
            time.sleep(0.5)

    elif choice == "3": # calculates if SYN flood
        avlist = []
        # TCP intercept set to intercept traffic matching ACL 100:
        intercept_on = "access-list 100 permit tcp any host 192.168.20.100 eq 80"
        intercept_off = "no access-list 100 permit tcp any host 192.168.20.100 eq 80"
        flood = False
        
        while True:
            try: 
                movingaverage = queue.get(block=False) # gets moving average from TCPcount
            except Empty:
                continue
            avlist.append(movingaverage) # stores the current moving average and last moving average
            if len(avlist) == 2:
                if not flood: # if current moving average > twice the last moving average: Flood
                    if avlist[1] == avlist[0] or avlist[1] < avlist[0] or avlist[1] < (avlist[0] * 2):
                        print("\033[32;1;4m~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Normal Traffic\033[0m", end="\r", flush=True)
                    elif avlist[1] > (avlist[0] * 2) and avlist[1] > 50:
                        print("\033[31;1;4m~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Probable Flood\033[0m")
                        SSHrouter(intercept_on)
                        flood = True
                elif flood: # checks if SYN flood is still happening
                    if avlist[1] == avlist[0] or avlist[1] > avlist[0] or avlist[1] > (avlist[0] / 2):
                        print("\033[31;1;4m~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Probable Flood\033[0m", end="\r", flush=True)   
                    elif avlist[1] < (avlist[0] / 2):
                        print("\033[32;1;4m~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Normal Traffic\033[0m")
                        SSHrouter(intercept_off)
                        flood = False  
                del avlist[0]   
    else:       
        while True:
            time.sleep(0.1) # so main process will not end (unless ctrl+c)    
    
        
if __name__ == '__main__':
    main(q)
