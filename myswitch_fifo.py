'''
Ethernet learning switch in Python.
Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *

TIMEOUT= 30
BROADCAST = EthAddr('FF:FF:FF:FF:FF:FF')

def main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]
    myAddressTable = AddressTable()

    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return


        log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))
        if packet[0].dst in mymacs:
            log_debug("Packet intended for me") 
        elif packet[0].dst == BROADCAST:
            broadcast(my_interfaces,packet,net,input_port)
        else:
            myAddressTable.updateTable(packet,input_port,timestamp)
            out_port = myAddressTable.getPort(packet)
            if out_port is not None:
                log_debug("Sending packet {} to {}".format(packet,out_port))
                net.send_packet(out_port,packet)
                #TODO: name vs ethernet address?
            else:
                broadcast(my_interfaces,packet,net,input_port)  
        

    net.shutdown()

def broadcast(interfaces,packet,net,input_port):
    for intf in interfaces:
        if input_port != intf.name:
            log_debug ("Flooding packet {} to {}".format(packet, intf.name))
            net.send_packet(intf.name, packet) 

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