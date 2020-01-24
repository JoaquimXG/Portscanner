# Modules
import scapy.all as scapy

# Local Includes
from arguments import args

def ackping(IP,ports,verbosity=0):
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


def synping(IP,ports,verbosity=0):
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
