#!/bin/python

import socket
import threading
import scapy.all as scapy

#for testing purposes
import time
from random import random
from arguments import args

lock = threading.Lock() #for locking threads to print/change shared variables
closedcount =0 #counting the number of closed ports that are found

def synping(IP,ports,verbosity=0):
    print("[-] Running SYN/half-open host discovery on port(s) {}".format(ports))

    p = scapy.IP(dst=IP)/scapy.TCP(dport=ports,flags='S')
    answered, unanswered= scapy.sr(p,timeout=0.2,retry=1,verbose=verbosity)
    
    for sent, recieved in answered:
        tcp_layer=recieved.getlayer('TCP')
        if tcp_layer.flags.value == 0x12:
            if verbosity == True:
                print("[+] Host found on port: ", tcp_layer.sport,"port open")
            found_host=True
        elif tcp_layer.flags.value == 0x14:
            if verbosity == True:
                print("[+] Host found on port: {} - port closed".format(tcp_layer.sport))
            found_host=True
        else:
            print ("unknown response retry scan")
        
        if found_host==True:
            return True 

    return False 


def discoverhost(IP,ports,verbosity):
    if (args.synping):
        return synping(IP,ports,verbosity)

    elif (args.ackping):
        return ackping(IP,ports,verbosity)

    elif (args.arpping):
        return arpping(IP,verbosity)
    
    else:
        print("run defaults")
        synping(IP,443,verbosity)
        ackping(IP,80,verbosity)

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

