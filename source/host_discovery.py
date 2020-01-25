# Modules
import scapy.all as scapy

# Local Includes
from arguments import args

def arpping(IP,verbosity):
    print("[-] Running ARP host discovery")
    hw_addr_dict={}
    for name in (scapy.get_if_list()):
        hw_addr_dict[scapy.get_if_hwaddr(name)]=name
    
    p = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst="192.168.56.101")
    iface = hw_addr_dict.get(p.src)
    ans, unans = scapy.srp(p,timeout=0.1,verbose=verbosity,iface=iface)

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
            if verbosity == True:
                print(
                    "[+] Host found on port: {} - port open".format(tcp_layer.sport)
                    )
            return True

        elif tcp_layer.flags.value == 0x14:
            if verbosity == True:
                print(
                "[+] Host found on port: {} - port closed".format(tcp_layer.sport)
                )
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
