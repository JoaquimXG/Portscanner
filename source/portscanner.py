#!/bin/python

# Modules
import scapy.all as scapy

# Local Includes
from arguments import args
from host_discovery import *


#for testing purposes
import time
from random import random


if __name__ == '__main__':
    found_host = None 
    open_ports = 0
    print (args)

    #parsing variables
    IP = socket.gethostbyname(args.Host)
    print ("[*] Target IP address : %s" % IP)

    #Parsing ports for host discovery
    if (args.synping) or (args.ackping):
        discover_ports = args.synping if args.synping else args.ackping
        try:
            discover_ports = map(int,discover_ports.split(','))
        except:
            pass
    else: discover_ports=None
        

    if discoverhost(IP,discover_ports,args.verbose) == True:
        print("[+] Host {} is up".format(IP))
    else:
        print("[-] Host {} seems to be down".format(IP))
    

    exit()



# #printing results for closed ports
#     if found == None:
#         print ("all %d ports closed" %closedcount)
#     elif found == True:
#         if (closedcount>0):
#             print ("%d closed ports not shown" %closedcount)

