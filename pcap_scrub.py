#!/usr/bin/env python
#---------------------
# file - pcap_scrub.py
# --------------------
import argparse
import os
import dpkt
import time
from dpkt.ip import IP, IP_PROTO_UDP
from dpkt.udp import UDP

def parse_arguments( ):
    parser = argparse.ArgumentParser(description='Process a PCAP file for anonymization')
    parser.add_argument("-p", "--port", type=str, help="specify application layer port you wish to remove")
    parser.add_argument("-P", "--application-protocol", type=str, help="specify application layer protocol you wish to remove")
    parser.add_argument("-s", "--srcport", type=int, help="specify the source port of the application layer protocol you wish to remove")
    parser.add_argument("-d", "--destport", type=int, help="specify the destination port of the application layer protocol you wish to remove")
    parser.add_argument('target', metavar='pcap', type=str, help='the actual pcap file you wish to process')

    return parser.parse_args( )

def process_pcap( arguments ):
    directory    = os.path.dirname( arguments.target )
    base_pcap    = os.path.basename( arguments.target )
    (name,ext)   = os.path.splitext( base_pcap )
    if "-" in name:
        name = name.split("-")[0]
    cleaned_pcap = os.path.join( directory,name+".cleaned." + str(time.time()) + ".pcap" )
 
    # https://programtalk.com/python-examples/dpkt.pcap.Writer/
    writer       = open( cleaned_pcap, "wb" )
    pcap_writer  = dpkt.pcap.Writer( writer )

    if arguments.application_protocol:
        arguments.application_protocol = arguments.application_protocol.split(",")

    if arguments.port:
        arguments.port = arguments.port.split(",")

    with open( arguments.target, "rb" ) as file_object:
        pcap_reader        = dpkt.pcap.Reader( file_object )
        for ts, buf in pcap_reader:
            ethernet_layer = dpkt.ethernet.Ethernet(buf)
            # Make sure the Ethernet frame contains an IP packet
            if not isinstance(ethernet_layer.data, dpkt.ip.IP):
                if arguments.application_protocol and "cdp" in arguments.application_protocol:
                    if ( ethernet_layer.data.__class__.__name__.lower() == "cdp" ):
                        print( "found a CDP frame to remove" )
                        continue
            else:        
                ip_layer           = ethernet_layer.data
                application_layer  = ip_layer.data

                if type(ip_layer.data) == UDP:
                    is_udp = True
                    is_tcp = False
                else:
                    is_udp = False
                    is_tcp = True

                try:
                    source_port    = application_layer.sport
                except:
                    source_port    = 0

                try:
                    dest_port      = application_layer.dport
                except:
                    dest_port      = 0

                #if dest_port == 80 and len(application_layer.data) > 0:
                #    try:
                #        http_layer = dpkt.http.Request(application_layer.data)
                #   except:
                #       pass

                if arguments.application_protocol and len(arguments.application_protocol)>0:
                    if is_udp and source_port == 138 and dest_port == 138:
                            if "browser" in arguments.application_protocol:
                                print("found a BROWSER protocol frame to remove")
                                continue
                    elif is_tcp and source_port == 110 or dest_port == 110:
                            if "pop" in arguments.application_protocol:
                                print("found a POP protocol frame to remove")
                                continue
                    elif is_tcp and source_port == 389 or dest_port == 389:
                            if "ldap" in arguments.application_protocol:
                                print("found an LDAP protocol frame to remove")
                                continue            

                if arguments.port:
                    if source_port in arguments.port or dest_port in arguments.port:
                        print( "omitting a frame based on the port specifier list {}".format(arguments.port) )
                        continue

            pcap_writer.writepkt( buf )
            writer.flush()

if __name__ == "__main__":
    arguments = parse_arguments( )
    process_pcap( arguments )