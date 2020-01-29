# Modules
import scapy.all as scapy

# Local Includes
from arguments import args

def icmpping(IP,verbosity,run_defaults=False):
    
    print(IP)
    if args.icmpecho:
        print("[-] Running ICMP-Echo  host discovery")
        p = scapy.IP(dst=IP)/scapy.ICMP(type="echo-request")
    
    elif args.icmptime:
        print("[-] Running ICMP-Timestamp host discovery")
        p = scapy.IP(dst=IP)/scapy.ICMP(type="timestamp-request")

    elif args.icmpmask:
        print("[-] Running ICMP-Address-Mask host discovery")
        p = scapy.IP(dst=IP)/scapy.ICMP(type="address-mask-request")
    
    else:
        print("[-] Running ICMP-Echo + ICMP-Timestamp Host discovery")
        p = scapy.IP(dst=IP)/scapy.ICMP(type=["echo-request","timestamp-request"])

    print(p.summary)

    ans,unans = scapy.sr(p,timeout=0.1,retry=1,verbose=verbosity)

    for sent,received in ans:
        if received:
            print("[+] Received ICMP response")
            return True

    return False

def arpping(IP,verbosity):
    print("[-] Running ARP host discovery")
    hw_addr_dict={}
    for name in (scapy.get_if_list()):
        hw_addr_dict[scapy.get_if_hwaddr(name)]=name
    
    p = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=IP)
    iface = hw_addr_dict.get(p.src)

    ans, unans = scapy.srp(p,timeout=0.1,verbose=verbosity,iface=iface)

    ans.summary()
    unans.summary()
    for sent, received in ans:
        if received:
            print("[+] Received ARP response")
            return True

    return False

def ackping(IP,ports,verbosity):
    print("[-] Running ACK host discovery on port(s) {}".format(ports))
    
    p = scapy.IP(dst=IP)/scapy.TCP(dport=ports,flags='A')
    answered, unanswered= scapy.sr(p,timeout=0.2,retry=1,verbose=verbosity)

    for sent,received in answered:
        if received.haslayer('TCP'):
            tcp=received.getlayer('TCP')
            print(
            "[+] Host found on port: {} - port unfiltered".format(tcp.sport)
            )
            return True

    return False


def synping(IP,ports,verbosity):
    print("[-] Running SYN/half-open host discovery on port(s) {}".format(ports))

    p = scapy.IP(dst=IP)/scapy.TCP(dport=ports,flags='S')
    answered, unanswered= scapy.sr(p,timeout=0.2,retry=1,verbose=verbosity)
    
    for sent, received in answered:
        tcp_layer=received.getlayer('TCP')

        if tcp_layer.flags.value == 0x12:
            print("[+] Host found on port: {} - port open".format(tcp_layer.sport))
            return True

        elif tcp_layer.flags.value == 0x14:
            print("[+] Host found on port: {} - port closed".format(tcp_layer.sport))
            return True

    return False 


def discoverhost(targets_dict,ports,verbosity):
    
    #this is likely far from ideal
    IP = targets_dict["arp"] + targets_dict["not_arp"]

    if (args.synping):
        return synping(IP,ports,verbosity)

    elif (args.ackping):
        return ackping(IP,ports,verbosity)

    elif (args.arpping):
        return arpping(IP,verbosity)

    elif args.icmptime or args.icmpecho or args.icmpmask:
        return icmpping(IP,verbosity)
 
    else:
        arpping(targets_dict["arp"],verbosity)
#         synping(targets_dict["not_arp"],443,verbosity)
#         ackping(targets_dict["not_arp"],80,verbosity)
#         icmpping(targets_dict["not_arp"],verbosity,run_defaults=True)
