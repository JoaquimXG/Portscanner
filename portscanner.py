#!/bin/python

from argparse import ArgumentParser
import socket
import threading
import scapy.all as scapy

#for testing purposes
import time
from random import random

lock = threading.Lock() #for locking threads to print/change shared variables
found = None #bool for whether any ports are found to be open TO-DO move to local scope?
closedcount =0 #counting the number of closed ports that are found

def connectscan(IP,port):
    print("unused")
#     socket.setdefaulttimeout(1)
#     try:
#         portsocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
#         portsocket.connect((IP,int(port)))
#         lock.acquire()
#         print ('[+] %s open' % port)
#         global found
#         found = True
#     except Exception as e:
#         lock.acquire()
#         global closedcount
#         closedcount+=1
#         if (options.verbose == True):
#             print('[-] port %s closed : %s' % (port,e))
#     finally:
#         lock.release()
#         portsocket.close()
#
# def synscan(IP,port):
#     print("to be developed")


def hostscan(IP,ports):#parses scan choice
    print("unused")
#     threads = []
#     if (options.connectscan==True):
#         for port in ports:
#             tcon = threading.Thread(target=connectscan,args=(IP,port))
#             threads.append(tcon)
#             tcon.start()
#         for thread in threads:
#             thread.join()
#
#     if (options.synscan==True):
#         for port in ports:
#             tsyn = threading.Thread(target=synscan,args=(IP,port))
#             tsyn.start()
#         tsyn.join()

if __name__ == '__main__':
    parser = ArgumentParser()
    usage = "usage: %prog [options] target-IP's"
#     parser=ArgumentParser(usage=usage)
    #general options
    parser.add_argument("-p", "--ports",dest="ports",metavar="[ports]", help="comma seperated list of ports for scanning")
    parser.add_argument("-v", "--verbose",dest="verbose",action="store_true", help="print additional information")
    #Host Discovery
    parser.add_argument("-PS","--syn-ping",metavar="[ports]",dest="synping",help="SYN ping probe to resolve host")
    parser.add_argument("-PA","--ACK-ping",metavar="[ports]",dest="ackping",help="ACK ping probe to resolve host")
    parser.add_argument("-PR","--arp-ping",metavar="[ports]",dest="arpping",help="ARP ping probe to resolve host")
#     parser.add_argument("--PE","--icmp-echo",dest="icmpecho",action="store_true",help="ICMP ECHO probe to resolve host")
#     parser.add_argument("--PP","--icmp-time",dest="icmptime",action="store_true",help="ICMP Time probe to resolve host")
#     parser.add_argument("--PM","--icmp-mask",dest="icmpmask",action="store_true",help="ICMP Mask probe to resolve host")
    #scan types
    parser.add_argument("-sT", dest="connectscan",action="store_true", help="only attempt a full connect scan")
    parser.add_argument("-sS", dest="synscan",action="store_true",help="only attempt a syn scan")
    (options, args) = parser.parse_args()

    #parsing variables
    IP = socket.gethostbyname(args[0])
    print ("[*] Target IP address : %s" % IP)
    if options.ports:
        ports = [i for i in options.ports.split(",")]
    else:
        ports = [i for i in range(0,1000)]


    print (options,args)


#     discoverhost(IP)

    exit()


#launching points
#     hostscan(IP,ports)

# #printing results for closed ports
#     if found == None:
#         print ("all %d ports closed" %closedcount)
#     elif found == True:
#         if (closedcount>0):
#             print ("%d closed ports not shown" %closedcount)

