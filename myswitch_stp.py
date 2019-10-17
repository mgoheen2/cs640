'''
Ethernet learning switch in Python.
Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *
from SpanningTreeMessage import *
import time
import sys


STPBROADCASTTIME = 2.0
TIMEOUT= 10.0
BROADCAST = EthAddr('FF:FF:FF:FF:FF:FF')


def main(net):
    timeKeeper = TimeKeeper()
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]
    myAddressTable = AddressTable()
    myId = min(mymacs)
    rootInfoTable = RootInfoTable(myId)
    

    while True:
        #TODO: generate and flood out STP Packets every 2 seconds until no longer root
        
        if isStillRoot(timeKeeper,myId,rootInfoTable) and timeKeeper.timeSinceLastSTPBroadcast >= STPBROADCASTTIME:
            timeKeeper.resetCycleTime()
            packet = createSTP(myId)
            broadcast(my_interfaces,packet,net, None)

        try:
            timeKeeper.timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        #Handle an STP packet coming in by checking header
        #If STP, update info, update header, send on its way
        if isSTPPacket(packet):
            timeKeeper.resetSTPITime() #reset timer
            updateSTPInfo(packet,input_port,rootInfoTable,myId) #update root information, blocklist
            updateSTPHeader(packet,myId) #Update header
            forwardPacket(my_interfaces,packet,net,rootInfoTable.blockedPorts,input_port) #push out
            continue

        log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))
        if packet[0].dst in mymacs: #If addressed to me, do nothing
            log_debug("Packet intended for me") 
        elif packet[0].dst == BROADCAST: #If Broadcast, broadcast TODO: do broadcasts go out on blocked port?
            broadcast(my_interfaces,packet,net,input_port)
        else:
            myAddressTable.updateTable(packet,input_port,timeKeeper.timestamp) #update forwarding table
            out_port = myAddressTable.getPort(packet) #check table for address
            if out_port is not None: 
                
                log_debug("Sending packet {} to {}".format(packet,out_port))
                net.send_packet(out_port,packet) #don't need to flood out if we know where we're going
                
            else:
                forwardPacket(my_interfaces,packet,net,rootInfoTable.blockedPorts,input_port) #flood out if we don't know where to go

        #if you haven't gotten an STP packet in TIMEOUT, congratulations you're now root again
        if isStillRoot(timeKeeper,myId,rootInfoTable) == False:
            rootInfoTable = RootInfoTable(myId)
        timeKeeper.calcTimeSinceSTPB() # calculate time since last broadcast

    net.shutdown()

def broadcast(interfaces,packet,net,input_port):
    for intf in interfaces:
        if input_port != intf.name:
            log_debug ("Flooding packet {} to {}".format(packet, intf.name))
            net.send_packet(intf.name, packet) 

def forwardPacket(interfaces,packet,net,blockedPorts,input_port):
    #TODO: implement me
    #handle STP broadcast chain 
    for intf in interfaces:
        if intf.name not in blockedPorts and input_port != intf.name:
            log_debug ("Flooding packet {} to {}".format(packet, intf.name))
            net.send_packet(intf.name, packet) 
    return

def isStillRoot(timeKeeper,myId,rootInfoTable):
    if rootInfoTable.RootSwitchId == myId:
        return True
    timeKeeper.calcTimeSinceSTPI()
    if timeKeeper.timeSinceLastSTPIncoming > TIMEOUT:
        return False
    return True

def isSTPPacket(packet):
    #TODO: Is this how we're supposed to implement this?
    if isinstance(packet,SpanningTreeMessage):
        return True
    return False

def createSTP(myId):
    #TODO: anything else needed?
    packet = Packet()
    packet += Ethernet()
    packet[0].src = myId
    packet[0].dst = BROADCAST
    packet[0].ethertype = 0x8809
    packet += SpanningTreeMessage(root_id=myId, switch_id=myId)
    return packet

def updateSTPHeader(stpPacket,myId):
    stpPacket[1].hops_to_root(stpPacket[0].hops_to_root.hops_to_root+1)#how to do this better
    stpPacket[1].switch_id(myId)
    #TODO: anything else needed?

def updateSTPInfo(packet,input_port,rootInfoTable,myId):
    #TODO this definitely needs QAd, directions are confusing
    packetRoot = packet[1].root
    if input_port == rootInfoTable.rootInterface and packetRoot < rootInfoTable.rootSwitchId:
        rootInfoTable.rootSwitchId = packetRoot
    elif packetRoot > rootInfoTable.rootSwitchId:
        rootInfoTable.removeFromBlocklist(input_port)
    elif packetRoot == rootInfoTable.rootSwitchId:
        
        tempHops = packet[1].hops_to_root() + 1
        if tempHops < rootInfoTable.hopsFromRoot or (tempHops==rootInfoTable.hopsFromRoot and rootInfoTable.RootSwitchId > packet[0].switch_id()):
            rootInfoTable.removeFromBlocklist(input_port)
            rootInfoTable.addToBlocklist(rootInfoTable.rootInterface)
            rootInfoTable.rootInterface = input_port
    else:
        rootInfoTable.addToBlocklist(input_port)
        




class AddressTable:
    def __init__(self):
        self.tableEntries = list()

    def getPort(self, packet):
        for tableEntry in self.tableEntries:
            if tableEntry.address==packet[0].dst and not tableEntry.isExpired():
                return tableEntry.port

    def dropStale(self):
        for tableEntry in self.tableEntries:
            if tableEntry.isExpired():
                self.tableEntries.remove(tableEntry)
    
    def updateTable(self,packet,input_port,timestamp):
        for tableEntry in self.tableEntries:
            if packet[0].src == tableEntry.address:
                tableEntry.port = input_port
                tableEntry.timestamp = timestamp
                return
        self.tableEntries.append(AddressNode(packet,input_port,timestamp))
        #don't have to search list for oldest timestamp since its FIFO
        if len(self.tableEntries) > 5:
            self.tableEntries.pop(0)
        self.dropStale()
    
    


class AddressNode:
    def __init__(self,packet,input_port,timestamp):
        self.port = input_port
        self.address = packet[0].src
        self.timestamp = timestamp
        self.next = None
    def isExpired(self):
        #TODO: implement
        return

class RootInfoTable:
    def __init__(self,myId):
        self.rootInterface = None
        self.RootSwitchId = myId
        self.blockedPorts = list
        self.hopsFromRoot = 0
    
    def removeFromBlocklist(self, port):
        if self.blockedPorts.count(port) > 0:
             self.blockedPorts.remove(port)

    def addToBlocklist(self, port):
        if self.blockedPorts.count(port) == 0:
            self.blockedPorts.append(port)

class TimeKeeper:
    def __init__(self):
        self.cycletime = time.perf_counter()
        self.temptime = time.perf_counter()
        self.timeSinceLastSTPBroadcast = 999.99
        self.timeSinceLastSTPIncoming = 0.0
        self.packet_timestamp = 0.0


    def calcTimeSinceSTPB(self):
        self.timeSinceLastSTPBroadcast = self.cycletime - self.temptime
    
    def calcTimeSinceSTPI(self):
        self.timeSinceLastSTPIncoming = self.timestamp - self.timeSinceLastSTPIncoming

    def resetCycleTime(self):
        self.cycletime= self.temptime
    
    def resetSTPITime(self):
        self.timeSinceLastSTPIncoming = 0.0

