#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time

from switchyard.lib.packet.util import *
from switchyard.lib.userlib import *
from dynamicroutingmessage import *

class Router(object):
    def __init__(self, net):
        self.net = net
		
        #retrieve interfaces for router
        self.my_interfaces = self.net.interfaces()
        self.myArpTable = ArpTable()  #initialize ARP table
        self.myFwdTable = ForwardingTable(self.my_interfaces) #initialize forwarding table
        self.outgoingQueue = OutgoingQueue(net) #initialize queue for packets awaiting ARP responses

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
				

                #if not a packet we care about, skipping further handling
                if self.shouldHandlePacket(packet) is True:
                    #pulling out headers for convenience
                    packet_headers = self.grabPacketHeaders(packet)

                    if packet_headers.get('DynamicRoutingMessage') is not None:
                        self.handleDRMPacket(packet,input_port)

                    #handle request Arp packet
                    if packet_headers.get('Arp') is not None: 
                        self.handleIncomingArpPacket(packet_headers.get('Arp'),input_port,packet)

                    #handle IPv4 packet
                    if packet_headers.get('IPv4') is not None: self.handleIpv4Packet(packet)

                #check outgoing queue to see if we got the address, need to do this even if we are going to drop the packet for queue decay
                self.updateOutgoingQueue(packet,input_port)
            
            else:
                #resend stale requests
                self.outgoingQueue.queueDecay()

    def grabPacketHeaders(self, packet):
        temp_headers = packet.headers()
        tempDict = dict()
        for type in temp_headers:
            tempDict.update([(type,packet.get_header_by_name(type))])
        return tempDict
				
            
    def shouldHandlePacket(self, packet):			
         #if not an arp request or IPv4 packet, don't handle it
        if packet.has_header(Arp) and packet.get_header(Arp).operation == ArpOperation.Request:
            return True
        if packet.has_header(IPv4):
            return True
        if packet.has_header(DynamicRoutingMessage):
            return True
        log_debug(" *** Not a packet we care about, drop it.")
        return False
    
    def handleDRMPacket(self, packet,input_port):
        header = packet.get_header(DynamicRoutingMessage)
        self.myFwdTable.updateTable(header.advertised_prefix,header.advertised_mask,header.next_hop,input_port,time.time())
        return

    def handleIncomingArpPacket(self, packet_header,input_port,packet):
        #retrieve targetprotoaddr from the ARP header
        targetprotoaddr = packet_header.targetprotoaddr
        log_debug(" *** Target IP address is: {}".format(targetprotoaddr))
        
        #retrieve interface for target address
        try:
            interface_in_router = self.net.interface_by_ipaddr(targetprotoaddr)
        except KeyError:
            log_debug("Target IP address is not in router, forwarding")
            #check if it's in my forwarding table, drop if it's not for now
            tableEntry = self.myFwdTable.checkIfInTable(packet)
            if tableEntry is None:
                return
            #check if it's in my Arp table
            log_debug("check if in arp table")
            mac = self.myArpTable.getMac(targetprotoaddr)
            if mac is None: 
                log_debug("mac is none")
                #if not in Arp table already
                #put it on the queue
                self.sendArpRequest(packet,tableEntry)
            else:
                log_debug("mac is not none")
                #if in arp table forward packet on its way
                self.forwardPacket(packet,mac,tableEntry.outgoingInterface)
            return

        log_debug(" *** Target interface is: {} - assigned to an interface in this router.".format(interface_in_router))

        #add mapping to ArpTable
        self.myArpTable.updateTable(packet_header.senderprotoaddr, packet_header.senderhwaddr,time.time())

        log_debug(" *** Received an ARP request.")  
                                    
        #create and send an ARP reply message
        #reply leaves on interface in router, sending back to ARP request sender
        arp_reply_packet = create_ip_arp_reply(interface_in_router.ethaddr, packet_header.senderhwaddr, packet_header.targetprotoaddr, packet_header.senderprotoaddr)                        
        log_debug(" *** Created ARP reply packet back on input port: {}".format(input_port))
        self.net.send_packet(input_port,arp_reply_packet)
        log_debug(" *** Sent ARP reply packet.")
        return
        
    
    #handle IPv4 packets
    def handleIpv4Packet(self, packet):
        #decrement header
        packet.get_header(IPv4).ttl-=1

        iPaddress = packet.get_header(IPv4).dst
        #check if its directed to me, for now we just do nothing with them
        for interface in self.my_interfaces:
            if iPaddress == interface.ipaddr:
                return

        #check if it's in my forwarding table, drop if it's not for now
        tableEntry = self.myFwdTable.checkIfInTable(iPaddress)
        if tableEntry is None:
            return

        #check if it's in my Arp table
        mac = self.myArpTable.getMac(packet.get_header(IPv4).dst)
        if mac is None: 
            #if not in Arp table already
            #put it on the queue
            self.sendArpRequest(packet,tableEntry)
        else:
            #if in arp table forward packet on its way
            self.forwardPacket(packet,mac,tableEntry.outgoingInterface)
        return

    def sendArpRequest(self,packet,tableEntry):
        #add request to queue
        arpPacket=self.outgoingQueue.addPacket(packet,tableEntry)
        #if request isn't already in motion start the process by sending the first packet
        if arpPacket is not None: self.net.send_packet(tableEntry.outgoingInterface,arpPacket)
        return

    def forwardPacket(self,packet,mac,interface):
        if packet.has_header(IPv4):
            #construct header
            tempHeader = Ethernet()
            tempHeader.src=mac
            tempHeader.dst=packet.get_header(Ethernet).dst
            packet[0] = tempHeader
            #send packet on its merry way
            self.net.send_packet(interface,packet)
            return
        if packet.has_header(Arp):
            header = packet.get_header(Arp)
            arpPacket = create_ip_arp_request(header.senderhwaddr,header.senderprotoaddr,header.targetprotoaddr)
            self.net.send_packet(interface,arpPacket)
            return


    def updateOutgoingQueue(self, packet, interface):
        
        if packet is not None:
            # if this is an ARP reply send packet out
            # remove from queue 
            # and we have a matching interface  - update table

            #update Arp table for future sends
            arp_header = packet.get_header(Arp)
            if arp_header is not None and arp_header.operation == ArpOperation.Reply:
                sendList = list()
                log_debug(" *** Received an ARP reply.")

                #store a mapping of the ARP in your router 
                self.myArpTable.updateTable(arp_header.senderprotoaddr, arp_header.senderhwaddr,time.time())

                #gather list of packets waiting on that address
                sendList = self.outgoingQueue.removeEntries(arp_header.senderprotoaddr)
                for tempPacket in sendList:
                    self.forwardPacket(tempPacket,arp_header.targethwaddr,interface)
                log_debug(" *** Forwarded packets along")

        #resend stale requests
        self.outgoingQueue.queueDecay()
   
        return

				

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
    def updateTable(self,ipAddrToAdd, macAddrToAdd,timestamp): 

        #if the ipAddr is in the table, update MAC and return
        for tableEntry in self.tableEntries:
            if tableEntry.ipAddr == ipAddrToAdd:
                tableEntry.macAddr = macAddrToAdd
                return

        #otherwise add the IP / MAC address pair to the table
        self.tableEntries.append(ArpTableEntry(ipAddrToAdd, macAddrToAdd,timestamp))
        

#ArpTableEntry objects will store IP address (protoaddr) and MAC (senderhwaddraddr) and timestamp
class ArpTableEntry:
    def __init__(self,ipAddr,macAddr,timestamp):
        self.ipAddr = ipAddr
        self.macAddr = macAddr
        self.timestamp = timestamp
        return

#ForwardingTable 
class ForwardingTable:
    def __init__(self, my_interfaces):
        self._tableEntries = list()
        self._createInitialTable(my_interfaces)
        self.maxDynamicSize = 5

    def updateTable(self,prefix,netMask,nextHop,outgoingInterface,fifoState):
        tempEntry = self.checkIfInTable(IPv4Network(prefix.exploded+"/"+netMask.exploded))

        #if it's not in the table already
        if tempEntry is None:
            #add it
            self._tableEntries.append(FwdTableEntry(prefix,netMask,outgoingInterface,nextHop,fifoState))
            log_debug("*** Updated table Entry")
            #remove oldest if necessary
            dynamicList = [dynamicList for dynamicList in self._tableEntries if dynamicList.fifoState != "PERMANENT"]
            if len(dynamicList) > 5:
                self._tableEntries.remove(min(dynamicList, key=lambda x: x.fifoState))  
        else:
            tempEntry.updateEntry(prefix,netMask,nextHop,outgoingInterface)
            log_debug("*** Updated table Entry")
        return
    
    def checkIfInTable(self,ipAddress):
        netAddr = IPv4Network('0.0.0.0/1')
        finalEntry = None
        for entry in self._tableEntries:
            tempNetAddr = IPv4Network(entry.prefix.exploded+"/"+entry.netMask.exploded)
            if ipAddress in tempNetAddr and tempNetAddr.prefixlen > netAddr.prefixlen:
                netAddr = tempNetAddr
                finalEntry = entry

        #returns none if not in table
        return finalEntry
    
    def _createInitialTable(self,my_interfaces):
        #we can assume the structure and location of forwarding_table.txt
        file = open("forwarding_table.txt", "r")
        templist = file.readlines()
        for templine in templist:
            line = templine.split()
            self.updateTable(IPv4Address(line[0]),IPv4Address(line[1]),IPv4Address(line[2]),line[3],time.time())

        #things directly off my interfaces
        for interface in my_interfaces:
            self.updateTable(interface.ipinterface.network.network_address,interface.netmask,None,interface.name,"PERMANENT")
            
#ForwardingTableEntry
class FwdTableEntry:
    def __init__(self,prefix,netMask,outgoingInterface,nextHop,timestamp):     
        self.prefix = prefix
        self.netMask = netMask
        self.outgoingInterface = outgoingInterface 
        self.nextHop = nextHop
        self.fifoState = timestamp

    def updateEntry(self,prefix,netMask,outgoingInterface,nextHop):
        self.prefix = prefix
        self.netMask = netMask
        self.outgoingInterface = outgoingInterface
        self.nextHop = nextHop

#let's keep track of outgoing queue
class OutgoingQueue:
    def __init__(self,net):
        self._queue = list()
        self.net = net
    
    def queueDecay(self):
        #updates info in queue 
        #resends Arp if necessary
        for tempEntry in self._queue:
            if time.time() - tempEntry.timestamp > 1.0:
                tempEntry.tries += 1
                if tempEntry.tries > 3:
                    #drop packets after 3 tries
                    self._queue.remove(tempEntry)
                    return
                #resend Arp
                interface = self.net.interface_by_macaddr(tempEntry.arp.get_header(Arp).senderhwaddr).name
                self.net.send_packet(interface,tempEntry.arp)
                tempEntry.timestamp=time.time() 
        return

    def addPacket(self, packet,tableEntry):
        #check if we already have Arps on the wire for target IP
        #just add it to the list of waiting
        for tempEntry in self._queue:
            if tempEntry.targetIp == packet.get_header(IPv4).dst:
                tempEntry.packetList.append(packet)
                return
            elif tempEntry.targetIp == tableEntry.nextHop:
                tempEntry.packetList.append(packet)
                return

        intf = self.net.interface_by_name(tableEntry.outgoingInterface)
        #if there isn't an Arp cycle going create a new queuEntry and Arp packet
        #if there's a next hop send it that way
        if tableEntry.nextHop is None:
            arp = create_ip_arp_request(intf.ethaddr,intf.ipaddr,packet.get_header(IPv4).dst)
        else:
            arp = create_ip_arp_request(intf.ethaddr,intf.ipaddr,tableEntry.nextHop)

        self._queue.append(QueueEntry(packet,arp,time.time()))
        return arp
    
    def removeEntries(self,targetIp):
        sendList = list()
        for tempEntry in self._queue:
            if tempEntry.targetIp == targetIp:
                for packet in tempEntry.packetList:
                    sendList.append(packet)
                self._queue.remove(tempEntry)
        return sendList


class QueueEntry:
    def __init__(self,packet,arp,timestamp):
        self.packetList = list()
        self.packetList.append(packet)
        self.timestamp = timestamp
        self.tries = 1
        self.arp = arp
        self.targetIp = arp.get_header(Arp).targetprotoaddr
    



