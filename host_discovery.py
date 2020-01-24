# Modules
import scapy.all as scapy

# Local Includes
from arguments import args


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
