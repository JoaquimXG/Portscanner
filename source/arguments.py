#!/bin/python

from argparse import ArgumentParser

parser = ArgumentParser()

#general options
parser.add_argument(
    "Host",
     help="The target host to be scanned"
)
parser.add_argument(
    "-p",
     "--ports",
    dest="ports",
    metavar="ports",
     help="comma seperated list of ports for scanning"
)
parser.add_argument(
    "-v",
     "--verbose",
    dest="verbose",
    action="store_true",
     help="print additional information"
)

#Host Discovery
parser.add_argument(
    "-PS",
    "--syn-ping",
    nargs="?",
    default=None,
    const=443,
    dest="synping",
    metavar="ports",
    help="SYN ping probe to resolve host"
)
parser.add_argument(
    "-PA",
    "--ACK-ping",
    nargs="?",
    default=None,
    const=80,
    dest="ackping",
    metavar="ports",
    help="ACK ping probe to resolve host"
)
parser.add_argument(
    "-PR",
    "--arp-ping",
    action="store_true",
    dest="arpping",
    help="ARP ping probe to resolve host"
)

parser.add_argument(
    "-PE",
    "--icmp-echo",
    dest="icmpecho",
    action="store_true",
    help="ICMP ECHO probe to resolve host"
)
parser.add_argument(
    "-PP",
    "--icmp-time",
    dest="icmptime",
    action="store_true",
    help="ICMP Time probe to resolve host"
)
parser.add_argument(
    "-PM",
    "--icmp-mask",
    dest="icmpmask",
    action="store_true",
    help="ICMP Mask probe to resolve host"
)
#scan types
#     parser.add_argument(
#     "-sT",
#      dest="connectscan",
#     action="store_true",
#      help="only attempt a full connect scan"
# )
#     parser.add_argument(
#     "-sS",
#      dest="synscan",
#     action="store_true",
#     help="only attempt a syn scan"
# )
args = parser.parse_args()
