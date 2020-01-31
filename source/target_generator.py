#!/bin/python3

import re
import ipaddress
import subprocess
import scapy.all as scapy

#local includes
from classes import interface#,target

def get_single_target(target_ip,interfaces,g_targets,a_targets):
    for interface in interfaces:
        if target_ip in ipaddress.ip_network(interface.IP,strict=False):
            a_targets.append((interface,[str(target_ip)]))
            break
        
    else:
        g_targets.append(str(target_ip)) 

    return


def generate_targets(host):
    global interface,target
    general_targets,arp_targets = [],[]

    ip_addr_output = subprocess.check_output(["ip","-o","addr"]).decode()
    host_ip_list = re.findall(": (.+?)[ ]*inet ([0-9\./]*) ",ip_addr_output)
    interfaces=[]
    for res in host_ip_list:
        hw_addr=scapy.get_if_hwaddr(res[0])
        interfaces.append(interface(
            str(res[1]),
            hw_addr,
            str(res[0])
            ))

    #attempt to parse target input 
    if '/' in str(host):
        try:
            target_net=ipaddress.ip_network(str(host),strict=False)
        except:
            print("[-] Target range invalid")
            print("[-] Please provide target range in the format x.x.x.x[/x]")
            exit()
    else:
        target_ip=ipaddress.ip_address(str(host))
        get_single_target(
                target_ip,
                interfaces,
                general_targets,
                arp_targets)
        return arp_targets,general_targets

    #iterate through interfaces
    #check if the target range is a subnet or supernet of any interface
    #if the target range is a supernet of any interface
    #add that interface to a list incase there are other interfaces also covered
    targets_are_subnet,targets_are_supernet = False,False
    interfaces_to_arp=[]
    for interface in interfaces:
        interface_subnet = ipaddress.ip_network(interface.IP,strict=False)

        if target_net.subnet_of(interface_subnet):
            targets_are_subnet = True
            interfaces_to_arp.append(interface)

        elif target_net.supernet_of(interface_subnet):
            targets_are_supernet=True
            interfaces_to_arp.append(interface)

    #check the results of the previous loop
    #add any targets that can be reached with ARP
    #to an arp_targets array 
    #the remaining targets are added to a general_targets array
    if targets_are_subnet == True:
        arp_targets.append((interfaces_to_arp.pop(),[]))
        for addr in target_net.hosts():
            arp_targets[0][1].append(str(addr))


    elif targets_are_supernet == True:
        arp_only=[]
        for i,interface in enumerate(interfaces_to_arp):
            arp_targets.append((interface,[]))
            interface_subnet = ipaddress.ip_network(
                    interface.IP,strict=False)
            for addr in interface_subnet.hosts():
                arp_targets[i][1].append(str(addr))
                arp_only.append(str(addr))

        for addr in target_net.hosts():
            if str(addr) not in arp_only:
                general_targets.append(str(addr)) 

    else:
        for addr in target_net.hosts():
            general_targets.append(str(addr))

    return arp_targets,general_targets
