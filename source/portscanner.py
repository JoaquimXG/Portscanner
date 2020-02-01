#!/bin/python3

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
    is_up = []

    #parsing targets
    arp_targets,general_targets= generate_targets(args.Host)

    print(args)

    #Parsing ports for host discovery
    if (args.synping) or (args.ackping):
        discover_ports = args.synping if args.synping else args.ackping
        try:
            discover_ports = list(map(int,discover_ports.split(',')))
        except:
            pass
    else: discover_ports=None

    is_up=discoverhost(arp_targets,general_targets,discover_ports,args.verbose)
    if is_up ==[]:
        print("[-] No hosts found")
    else:
        for host in is_up:
            print("[+] {} is up".format(host))

    exit()
