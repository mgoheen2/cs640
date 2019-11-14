#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time

from switchyard.lib.packet.util import *
from switchyard.lib.userlib import *

class Router(object):
    def __init__(self, net):
        self.net = net
		
        #retrieve interfaces for router
        #TODO is this necessary? Or just retrieve once router has started?
        self.my_interfaces = self.net.interfaces()
        myArpTable = ArpTable()  #initialize ARP table

    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        while True:
            gotpkt = True
            try:
                timestamp,input_port,packet = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            if gotpkt:
                log_debug("Got a packet: {}".format(str(packet)))
                log_debug (" *** Received packet {} on {}".format(packet, input_port))
				
                #check if it is an ARP request
                arp_header = packet.get_header(Arp)
				
                #if not an arp packet, drop it
                if arp_header is None:
                    log_debug(" *** Not an ARP packet, drop it.")
                    continue
				
                #retrieve targetprotoaddr from the ARP header
                targetprotoaddr = arp_header.targetprotoaddr
                log_debug(" *** Target IP address is: {}".format(targetprotoaddr))
				
                #retrieve interface for target address
                try:
                    interface_in_router = self.net.interface_by_ipaddr(targetprotoaddr)
                except KeyError:
                    log_debug("Target IP address is not in router, dropping packet.")
                    continue

                log_debug(" *** Target interface is: {} - assigned to an interface in this router.".format(interface_in_router))	
				
                #if this is an ARP request and we have a 
                if arp_header.operation == ArpOperation.Request:
                    log_debug(" *** Received an ARP request.")  
											 
                    #create and send an ARP reply message
                    #reply leaves on interface in router, sending back to ARP request sender
                    arp_reply_packet = create_ip_arp_reply(interface_in_router.ethaddr, arp_header.senderhwaddr, arp_header.targetprotoaddr, arp_header.senderprotoaddr)                        
                    log_debug(" *** Created ARP reply packet back on input port: {}".format(input_port))
                    self.net.send_packet(input_port,arp_reply_packet)
                    log_debug(" *** Sent ARP reply packet.")
                    continue
				
                #if this is an ARP reply and we have a matching interface  - update table
                #TODO the standard test doesn't test this at all.
                elif arp.operation == ArpOperation.Reply:
                    log_debug(" *** Received an ARP reply.")

                    #store a mapping of the ARP in your router    
                    myArpTable.updateTable(senderprotoaddr, senderhwaddr)
				

def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()


#ArpTable objects will store a list of ArpTableEntry objects to support ARP tables
class ArpTable:
    def __init__(self):
        self.tableEntries = list()

    #retrieve MAC address given an IP address
    def getMac(self, ipAddrToCheck):
        for tableEntry in self.tableEntries:
            if tableEntry.ipAddr == ipAddrToCheck: return tableEntry.macAddr

    #upon receiving new mapping, add to ARP table
    def updateTable(self,ipAddrToAdd, macAddrToAdd):

        #if the ipAddr is in the table, update MAC and return
        for tableEntry in self.tableEntries:
            if tableEntry[0].ipAddr == ipAddrToAdd:
                tableEntry.macAddr = macAddrToAdd
                return

        #otherwise add the IP / MAC address pair to the table
        self.tableEntries.append(ArpTableEntry(ipAddToAdd, macAddrToAdd,timestamp))


#ArpTableEntry objects will store IP address (protoaddr) and MAC (senderhwaddraddr) and timestamp
class ArpTableEntry:
    def __init__(self,ipAddr,macAddr,timestamp):
        self.ipAddr = ipAddr
        self.macAddr = macAddr
        return
