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

def arpping(targets,verbosity):
    if targets == []:
        return False
    is_up = []
    print("[-] Running ARP host discovery")
    
    for interface in targets:
        p = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        p = p/scapy.ARP(pdst=[t.IP for t in interface[1]])
        iface = interface[0].name 

        ans, unans = scapy.srp(p,timeout=0.2,verbose=verbosity,iface=iface)
        for (sent,received) in ans:
            for i,ip in enumerate(interface[1]):
                if ip.IP == received.psrc:
                    print("[+] Received ARP response from {}".format(ip.IP))
                    is_up.append(interface[1].pop(i))
                
    return is_up 

def ackping(IP,ports,verbosity):
    print("[-] Running ACK host discovery on port(s) {}".format(ports))
    
    p = scapy.IP(dst=IP)/scapy.TCP(dport=ports,flags='A')
    answered, unanswered= scapy.sr(p,timeout=0.5,retry=1,verbose=verbosity)

    for sent,received in answered:
        if received.haslayer('TCP'):
            tcp=received.getlayer('TCP')
            print(
            "[+] Host found on port: {} - port unfiltered".format(tcp.sport)
            )
            return True

    return False


def synping(targets,ports,verbosity):
    if targets == []:
        return False

    print("[-] Running SYN/half-open host discovery on port(s) {}".format(ports))

    p = scapy.IP(dst=[target.IP for target in targets] )
    p = p/scapy.TCP(dport=ports,flags='S')
    answered, unanswered= scapy.sr(p,timeout=0.2,retry=1,verbose=verbosity)
   
    #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!11
    for sent, received in answered:
        tcp_layer=received.getlayer('TCP')

        if tcp_layer.flags.value == 0x12:
            print("[+] Host found on port: {} - port open".format(tcp_layer.sport))
            return True

        elif tcp_layer.flags.value == 0x14:
            print("[+] Host found on port: {} - port closed".format(tcp_layer.sport))
            return True

    return False 


def discoverhost(arp_targets,general_targets,ports,verbosity):
    is_up = []

    if (args.synping):
        return synping(IP,ports,verbosity)

    elif (args.ackping):
        return ackping(IP,ports,verbosity)

    elif (args.arpping):
        return arpping(IP,verbosity)

    elif args.icmptime or args.icmpecho or args.icmpmask:
        return icmpping(IP,verbosity)
 
    else:
        is_up.extend(arpping(arp_targets,verbosity))
#         synping(general_targets,443,verbosity)
#         ackping(general_targets,80,verbosity)
#         icmpping(general_targets,verbosity,run_defaults=True)

    return is_up
