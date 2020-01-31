# Modules
import scapy.all as scapy

# Local Includes
from arguments import args


def icmpping(targets,verbose):

    if targets ==[]:
        return None

    is_up=[]
    
    if args.icmpecho:
        print("[-] Running ICMP-Echo  host discovery")
        p = scapy.IP(dst=targets)/scapy.ICMP(type="echo-request")
    
    elif args.icmptime:
        print("[-] Running ICMP-Timestamp host discovery")
        p = scapy.IP(dst=targets)/scapy.ICMP(type="timestamp-request")

    elif args.icmpmask:
        print("[-] Running ICMP-Address-Mask host discovery")
        p = scapy.IP(dst=targets)/scapy.ICMP(type="address-mask-request")
    
    else:
        print("[-] Running ICMP-Echo + ICMP-Timestamp Host discovery")
        p = scapy.IP(dst=targets)
        p = p/scapy.ICMP(seq=1,id=100,type=["echo-request","timestamp-request"])

    ans,unans = scapy.sr(p,timeout=0.5,retry=1,verbose=verbose)

    for sent,received in ans:
        for i,target_ip in enumerate(targets):
            if received.src == target_ip:
                is_up.append(targets.pop(i))
                if verbose == True:
                    print("[+] {} is up".format(target_ip))
        
    return is_up 

def arpping(targets,verbose):
    if targets == []:
        return None

    print("[-] Running ARP host discovery")

    is_up = []
    for interface in targets:
        p = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        p = p/scapy.ARP(pdst=interface[1])
        iface = interface[0].name 

        ans, unans = scapy.srp(p,timeout=0.2,verbose=verbose,iface=iface)
        for (sent,received) in ans:
            for i,target_ip in enumerate(interface[1]):
                if target_ip == received.psrc:
                    is_up.append(interface[1].pop(i))
                    if verbose == True:
                        print("[+] {} is up".format(target_ip))
                
    return is_up 

def ackping(targets,ports,verbose):
    if targets == []:
        return None

    is_up=[]
    print("[-] Running ACK host discovery on port(s) {}".format(ports))
    
    p = scapy.IP(dst=targets)/scapy.TCP(dport=ports,flags='A')
    answered, unanswered= scapy.sr(p,timeout=0.5,retry=1,verbose=verbose)

    for sent,received in answered:
        for i,target_ip in enumerate(targets):
            if target_ip == received.src:
                is_up.append(targets.pop(i))
                if verbose == True:
                    print("[+] {} is up".format(target_ip))

    return is_up 


def synping(targets,ports,verbose):
    if targets == []:
        return None

    is_up = []
    print("[-] Running SYN/half-open host discovery on port(s) {}".format(ports))

    p = scapy.IP(dst=targets)
    p = p/scapy.TCP(dport=ports,flags='S')
   
    answered, unanswered= scapy.sr(p,timeout=1,retry=1,verbose=verbose)
    for sent, received in answered:
        for i,target_ip in enumerate(targets):
            if target_ip == received.src:
                is_up.append(targets.pop(i))
                if verbose == True:
                    print("[+] {} is up".format(target_ip))

    return is_up 


def discoverhost(arp_targets,general_targets,ports,verbose):
    is_up = []

#     if (args.synping):
#         return synping(#targets,ports,verbose)
# 
#     elif (args.ackping):
#         return ackping(#targets,ports,verbose)
# 
#     elif (args.arpping):
#         return arpping(#targets,verbose)
# 
#     elif args.icmptime or args.icmpecho or args.icmpmask:
#         return icmpping(#targets,verbose)
 
#     else:
    if True:
        res = arpping(arp_targets,verbose)
        if res:
          is_up.extend(res) 

        res = synping(general_targets,443,verbose)
        if res:
            is_up.extend(res)

        res = ackping(general_targets,80,verbose)
        if res:
            is_up.extend(res)

        res = icmpping(general_targets,verbose)
        if res:
            is_up.extend(res)

    return is_up
