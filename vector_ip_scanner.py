#!/usr/bin/env python3

"""
***Vector IP scanner***

This program helps scanning for a Vector on a roaming DHCP server. When running for the first time, it will prompt for the ip address and serial. Once a correct ip is given, the MAC address is saved. Every next time the program is run, it will search the ip range of the last known working ip address. If it has changed, it will use Anki's configure.py to set the new ip. 

Notes:
- Make sure the file 'vector_ip_scanner.py' is in the same directory as Anki's SDK configure.py
- Only the first 50 ip's are scanned by default. Change the value of ip_range_max if more range or speed is needed.
- This program does not make things easier when changing to a different network, like changing from 192.168.0.XXX to 10.178.0.XXX (delete ipscanner_config.json if you do, then run this program again).
- Tested on Mac with SDK 0.5.0, untested on Linux and Windows.
- Some error messages can occur during scanning ('ping: sendto: No route to host'), they have no effect on the result.

Author: GrinningHermit

"""

import subprocess
from subprocess import Popen, PIPE
import sys
from datetime import datetime
import threading
from queue import Queue
import time
import re
from anki_vector.configure.__main__ import write_config
import json
import socket
import ipaddress
from getmac import get_mac_address
import configparser
from pathlib import Path
from netifaces import interfaces, ifaddresses, AF_INET


# Setup config parser for reading the sdk config
config = configparser.ConfigParser()

ip_range_max = 255
vector_ip = ''
get_mac_count = 0

def get_mac(ip):
    global get_mac_count
    get_mac_count = get_mac_count + 1
    if get_mac_count < 10:
        try:
            # Display mac address of found host. Trying a couple of times as the process seems to fail sometimes
            return get_mac_address(ip=ip, network_request=True)

        except:
            print('no mac id found, retrying')
            time.sleep(0.5)
            get_mac(ip)
    else: 
        get_mac_count = 0
        return 'mac address not found'

def enter_ip():
    global vector_config_ip
    vector_config_ip = input()
    try:
        socket.inet_aton(vector_config_ip)
    except socket.error:
        print('That ip address is invalid. Try again or quit (Ctrl-C): ')
        enter_ip()

def enter_serial():
    global vector_serial
    vector_serial = input()
    if len(vector_serial) != 8:
        print('That serial has an invalid length. Try again or quit (Ctrl-C): ')
        enter_serial()

def readJson():
    global vector, vector_mac, vector_serial, vector_config_ip
    with open('ipscanner_config.json') as json_data_file:
        vector = json.load(json_data_file)
        vector_mac = vector['0']['mac']
        vector_config_ip = vector['0']['ip']
        vector_serial = vector['0']['serial']
        print('Json file loaded\n')
        print(vector_config_ip)

def readSDKConfig():
    global vector_serial, vector_config_ip, vector_sdk_ip
    config.read(str(Path.home()) + '/.anki_vector/sdk_config.ini')
    print("Read anki_vector sdk config")
    vector_sdk_ip = None
    try:
        vector_serial = config.sections()[0]
        vector_sdk_ip = config.get(vector_serial, 'ip')
    except:
        pass
    if vector_sdk_ip == None:
        print("vector IP not found in sdk config")
    elif not vector_config_ip == vector_sdk_ip:
        print("vector IP not the same as the SDK IP")
    else:
        print("vector ip and sdk ip are the same")

def saveJson():
    global vector_config_ip, vector_serial, vector_mac
    vector_mac = get_mac(vector_config_ip)
    print('\nip:', vector_config_ip, '\nserial:', vector_serial, '\nmac:', str(vector_mac), '\n')
    vector = {
        '0': {
            'ip':vector_config_ip,
            'serial':vector_serial,
            'mac':vector_mac
        }
    }
    with open('ipscanner_config.json', 'w+') as outfile:
        json.dump(vector, outfile)
        print('json config written as ipscanner_config.py\n')

try:
    readJson()
    readSDKConfig()
    if not vector_config_ip or not vector_serial or not vector_mac:
        raise Exception('Could not find ip/serial/mac')
except:
    print("Loaded configs, but there was a mismatch or error")
    if not vector_config_ip and not vector_serial and not vector_sdk_ip:
        # prompt for data to write config if it does not exist yet
        print('SDK Config and scanner_config files not found.\n\nAn ip address must be registered to continue:\n\n1. Plug in the USB cord of Vector\'s charger for power.\n2. Start up Vector by pressing the button on his back once.\n3. Put your Vector on his charger.\n4. Raise his arm above his head and bring it down again.\n5. Enter the displayed ip address (XXX.XXX.XXX.XXX): ')
        enter_ip()
    
        print('6. Enter the displayed serial number (8 characters): ')
        enter_serial()
    
    saveJson()
    sys.exit()

current_ip_mac = get_mac_address(ip=vector_config_ip, network_request=True)

if current_ip_mac == vector_mac:
    print("Nothing to do")
    saveJson()
    write_config(vector_serial, ip=vector_config_ip, clear=False)
    sys.exit()
elif not vector_sdk_ip == vector_config_ip:
    sdk_ip_mac = get_mac_address(ip=vector_sdk_ip, network_request=True)
    if sdk_ip_mac == vector_mac:
        print("vector sdk ip is correct")
        vector_config_ip = vector_sdk_ip
        saveJson()
        sys.exit()

print("No good IP found, searching...")

vector_ip = ''
def ipscan(ip, q, ip_range):
    global vector_ip, have_ip
    if vector_ip == '':
         ip_address = ip_range + '.' + str(ip)

         try:
             # Ping each possible host
             ping = Popen(['ping', '-c', '3', ip_address, '-W', '1000'], stdout=PIPE)
             output = ping.communicate()[0]
             hostalive = ping.returncode 
             if hostalive == 0: 
                 # Display mac address of found hosts
                 mac = get_mac(ip_address)
                 print(ip_address + ' ' + mac)
                 if vector_mac == mac:
                     vector_ip = ip_address
                     q.queue.clear()
                     have_ip.acquire()
                     have_ip.notify_all()
                     print("Found Vector")
                     have_ip.release()

         except Exception as e:
             print(ip_address + ' thread failed ' + e)     

print_lock = threading.Lock()
q = Queue()
have_ip = threading.Condition()
# The threader thread pulls an worker from the queue and processes it
def threader(ip_range, q):
    while True:
        worker = q.get()
        ipscan(worker, q, ip_range)
        q.task_done()

# Check what time the scan started
t1 = datetime.now()

# Creating threads to make the ip scanning go faster
try:
    ranges_found = []
    print("-" * 60)
    for ifaceName in interfaces():
        if 'lo' in ifaceName:
            continue
        addrs = ifaddresses(ifaceName)
        my_ip = addrs[AF_INET][0]['addr']
        ip_range = re.search(r"([^.]*.[^.]*.[^.]*)", my_ip).groups()[0]
        if ip_range not in ranges_found:
            ranges_found.append(ip_range)
        else:
            continue
        print("Scanning remote hosts at: " + ip_range + ".(1-" + str(ip_range_max) + "), please wait.")
        # allowed number of threads
        for x in range(30):
            t = threading.Thread(target=threader, args=(ip_range, q))
            t.daemon = True
            t.start()
    
        start = time.time()
    
        # ip numbers being checked.
        for worker in range(1,ip_range_max):
            q.put(worker)

    print("-" * 60)
    have_ip.acquire()
    while vector_ip == '' and not q.empty():
        have_ip.wait()
    have_ip.release()
except KeyboardInterrupt:
    print("You pressed Ctrl+C")
    sys.exit()
except Exception as e:
    print(e)
    pass

# Checking the time again
t2 = datetime.now()

# Calculates the difference in time, to see how long it took to run the script
total =  t2 - t1

# Printing the time to screen
print("-" * 60)
print('Scanning Completed in:', total)
print("-" * 60)
if vector_ip != '':
    print("\nVector detected at " + vector_ip + "\n")
    # Assigning the new ip address to the config file using Anki's configure.py 
    if vector_ip != vector_config_ip:
        vector_config_ip = vector_ip
        saveJson()
        write_config(vector_serial, ip=vector_ip, clear=False)
    else:
        print("Vector ip unchanged, no configuration update needed\n")
else:
    print("\nVector not found" + "\n")

