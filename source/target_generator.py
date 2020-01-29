#!/bin/python

import re
import ipaddress
import subprocess


#using the target input from the main script/user input
#generate a two arrays of targets 
#one array that can be trageted using ARP 
#one that can't
#dictionary containing both lists is returned

def generate_targets(host):

    #generate and parse ifconfig output
    #to get list of host network addresses including subnet
    ip_addr_output = subprocess.check_output(["ip","-o","addr"]).decode()
    host_ip_list = re.findall("inet ([0-9\./]*) ",ip_addr_output)

    targets={"arp":[],"not_arp":[]}
    interfaces_to_arp=[]
    targets_are_subnet,targets_are_supernet = False,False

    #attempt to parse target input 
    try:
        target_net=ipaddress.ip_network(unicode(host),strict=False)
    except:
        print("target range invalid")
        print("please provide target range in the format x.x.x.x[/x]")


    #iterate through interface addresses of the source(host)
    #check if the target range is a subnet or supernet of any interface
    #if the target range is a supernet of any interface
    #add that interface to a list incase there are other interfaces also covered
    for host_addr in host_ip_list:
        host_addr = ipaddress.ip_network(host_addr,strict=False)

        if target_net.subnet_of(host_addr):
            targets_are_subnet = True

        elif target_net.supernet_of(host_addr):
            targets_are_supernet=True
            interfaces_to_arp.append(host_addr)

    #check the results of the previous loop
    #add any targets that can be reached with ARP
    #to an arp_targets array
    #the remaining targets are added to a not_arp_targets array
    if targets_are_subnet == True:
        for addr in target_net.hosts():
            targets["arp"].append(str(addr))

    elif targets_are_supernet == True:
        print("supernet")
        for interface in interfaces_to_arp:
            for addr in interface.hosts():
                targets["arp"].append(str(addr))

        for addr in target_net.hosts():
            if str(addr) not in targets["arp"]:
                targets["not_arp"].append(str(addr))
    else:
        for addr in target_net.hosts():
            targets["not_arp"].append(str(addr))

    return targets
