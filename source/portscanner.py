#!/bin/python

# Modules
import scapy.all as scapy

# Local Includes
from arguments import args
from host_discovery import *
from target_generator import generate_targets


#for testing purposes
import time
from random import random


if __name__ == '__main__':
    found_host = None 
    open_ports = 0
    print (args)

    #parsing targets
    targets_dict = generate_targets(args.Host)
#     print(targets_dict)
    targets_dict["arp"]=["192.168.56.101","192.168.56.100"]
    targets_dict["not_arp"]=["192.168.56.101","192.168.56.102"]
    print(targets_dict)

    #Parsing ports for host discovery
    if (args.synping) or (args.ackping):
        discover_ports = args.synping if args.synping else args.ackping
        try:
            discover_ports = map(int,discover_ports.split(','))
        except:
            pass
    else: discover_ports=None
    


    if discoverhost(targets_dict,discover_ports,args.verbose) == True:
        print("[+] at least found one host")


# this only works for an individual host
#         print("[+] Host {} is up".format(IP))
#     else:
#         print("[-] Host {} seems to be down".format(IP))
    

    exit()



# #printing results for closed ports
#     if found == None:
#         print ("all %d ports closed" %closedcount)
#     elif found == True:
#         if (closedcount>0):
#             print ("%d closed ports not shown" %closedcount)

