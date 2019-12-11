#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from random import randint
import time


def switchy_main(net):
    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]

    print(my_intf)

    #parse blaster_params.txt file to determine blaster behavior; assume file structure and location
    log_debug("Reading file.")
    file = open("blaster_params.txt", "r")
    firstLine = file.readline()
    splitLine = firstLine.split()  #default is whitespace
    
    #parse out lines in the file #TODO - do I need to validate these
    log_debug("Parsing file.")
    if splitLine[0] == "-b": blastee_IP = splitLine[1]
    if splitLine[2] == "-n": total_to_send = int(splitLine[3])
    if splitLine[4] == "-l": length = int(splitLine[5])
    if splitLine[6] == "-w": sender_window = int(splitLine[7])
    if splitLine[8] == "-rtt": RTT = float(splitLine[9]) #TODO+1 cast correctly?
    if splitLine[10] == "-r": recv_timeout = float(splitLine[11])
    if splitLine[12] == "-alpha": alpha = float(splitLine[13])
    log_debug("Parse check: {} is alpha.".format(alpha))

    #initialize variables and sending window table
    estRTT = RTT
    t_out = 2 * estRTT
    sent_count = 0    
    goodput_Bytes = 0
    num_ret = 0
    reTx_Bytes = 0
    num_tos = 0
    min_rtt = None # -1 #initialize to 
    max_rtt = None 
    swTable = SendingWindowTable(sender_window)
    
    #stay in loop while blaster agent is running    
    while True:
        gotpkt = True
        try:
            log_debug("Attempting to receive packet")
            timestamp,dev,pkt = net.recv_packet(timeout=(recv_timeout/1000))
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("Packet received.")

            #test parsing packet. TODO clean up this chunk.
            #log_debug("Number headers: {}".format(pkt.num_headers()))
            #log_debug("Header 3 is : {}".format(papktcket[3]))
            seq_num_bytes = pkt[3].to_bytes()[:4] #first 4 bytes is seq number
            packet_sequence_number = int.from_bytes(seq_num_bytes, byteorder='big')
            log_debug("ACK message seq num is {}".format(packet_sequence_number))
            
            #if we already ACK this packet, ignore this packet and continue
            if swTable.packetEntryIndexNumber(packet_sequence_number) == -1: continue
            
            #ACK for unACKed packet - retrieve the RTT for the packet and then remove from the table
            ackTime = time.perf_counter() #TODO or use timestamp from receviing packet
            packet_rtt = ackTime - swTable.sentTimeForPacket(packet_sequence_number)
            swTable.removeFromPacketList(pkt, packet_sequence_number)
                
            #ACK for unACKed packet - do estRTT and timeout calculations
            estRTT = ((1-alpha)* estRTT) + (alpha * (packet_rtt))
            t_out = 2 * estRTT
            if (min_rtt == None) or (packet_rtt < min_rtt): min_rtt = packet_rtt
            if (max_rtt == None) or (packet_rtt > max_rtt): max_rtt = packet_rtt
                        
            #if final ACK - do final calculations and print out stats to screen
            if swTable.LHS == total_to_send:
                total_time = ackTime - first_packet_start_time
                throughput = (goodput_Bytes + reTx_Bytes) / total_time
                goodput = goodput_Bytes / total_time
                print_output(total_time, num_ret, num_tos, throughput, goodput, estRTT, t_out, min_rtt, max_rtt)
                break #all done!
            
        else:
            log_debug("Didn't receive a packet. Evaluate if blast has new packet to send.")
            if swTable.canSendAnotherPacket() == True: 
                
                if sent_count < total_to_send:
                    log_debug("Sending a new packet.")
                
                    #track statistics
                    if sent_count == 0: first_packet_start_time = time.perf_counter() #for first packet
                    goodput_Bytes += length

                    #create and send packet
                    sent_count += 1
                    packet = create_packet(blastee_IP, length, sent_count)
                    log_debug("Packet created: {}".format(packet))
                    net.send_packet(net.interface_by_name('blaster-eth0'), packet)

                    #add to unACKd packets table which also increments RHS. sent_count is seq number.
                    swTable.addToPacketList(packet, sent_count)

                    #try to receive again
                    continue

                else:
                    log_debug("Packet can be sent based on Sending Window, but no new packets to send.")

            log_debug("Check unACKd packets to see if any timed out.")
            packetToRetransmitIndex = swTable.timedOutPacketIndex(t_out/1000) #t_out from file is in ms
            if packetToRetransmitIndex >=0:

                log_debug("We have a timed out packet. Attempt retransmit.")
                
                #track retransmit statistics
                num_ret += 1
                reTx_Bytes += length
                #TODO - this is a coarse timeout? not sure! Maybe only count if first_packet_start_time is not None?
                #num_tos += 1

                #retrieve and resend packet
                log_debug("Retrieving and sending unACKd packet.")
                packetToRetransmit = swTable.sent_packets_list[packetToRetransmitIndex].packet
                net.send_packet(net.interface_by_name('blaster-eth0'), packetToRetransmit)

                #try to receive again
                continue


    net.shutdown()

#create_packet will create packet for sending
def create_packet(blastee_IP, length, sent_count):
    
    pkt = Ethernet() + IPv4() + UDP()
    pkt[0].src = "10:00:00:00:00:01" #Ethernet - blaster source and blastee dst, based on start_mininet topography
    pkt[0].dst = "20:00:00:00:00:01" #TODO Is this OK to do? with IP, I get that from the file, but not with Layer 2?
    pkt[1].protocol = IPProtocol.UDP  #IP - protocol, blaster source and blastee dst
    pkt[1].src = '192.168.100.1' #based on start_mininet topography
    pkt[1].dst = blastee_IP
    pkt[2].src = 4444  #UDP - arbitrary values, not used
    pkt[2].dst = 5555

    #encode custom packet header - sequence number - 4 bytes (32 bit), length - 2 bytes (16 bit)
    pkt += RawPacketContents(sent_count.to_bytes(4, byteorder='big') + length.to_bytes(2, byteorder='big'))

    #encode variable length payload - last portion of a packet is considered payload
    pkt += RawPacketContents(length.to_bytes(length, byteorder ='big'))

    return pkt

#print_output prints transmission statistics
def print_output(total_time, num_ret, num_tos, throughput, goodput, estRTT, t_out, min_rtt, max_rtt):
    print("Total TX time (s): " + str(total_time))
    print("Number of reTX: " + str(num_ret))
    print("Number of coarse TOs: " + str(num_tos))
    print("Throughput (Bps): " + str(throughput))
    print("Goodput (Bps): " + str(goodput))
    print("Final estRTT(ms): " + str(estRTT))
    print("Final TO(ms): " + str(TO))
    print("Min RTT(ms):" + str(min_rtt))
    print("Max RTT(ms):" + str(max_rtt))
        
#sentPacketEntry objects will store info about packets that are in the sender window awaiting ACK
#TODO Double check whether this is byte oriented.
class sentPacketEntry:
    def __init__(self, packet, packet_sequence_number):
        self.packet = packet
        self.packet_sequence_number = packet_sequence_number
        self.time_sent = time.perf_counter()
        #TODO should we just parse the packet_sequence_number from the packet? or unncessarily complicated?

#SendingWindowTable will track unACKd packets and provide sending window calculations
class SendingWindowTable:
    def __init__(self,sender_window):
        self.sent_packets_list = list()
        self.SW = sender_window  #count
        self.LHS = 1
        self.RHS = 1

    #called after packet is sent - will add packet if necessary (first time) and time stamp
    #TODO do I need both packet and sequence number? Or pull out sequence number from packet?
    def addToPacketList(self, packet, packet_sequence_number):
        
        #if packet isn't already in table, create sentPacket object, add to table with time, increment RHS
        if self.packetEntryIndexNumber(packet_sequence_number) == -1:
            self.sent_packets_list.append(sentPacketEntry(packet, packet_sequence_number))
            self.RHS += 1
           
    #removeFromPacketList when we receive an ACK - remove from table and update LHS
    #TODO do I need both packet and sequence number? Or pull out sequence number from packet?
    #TODO should I remove packet? do we need to validate bytes in packet, or just seq no?
    def removeFromPacketList(self, packet, packet_sequence_number):
        
        #if packet is in table, remove it and update LHS
        index = self.packetEntryIndexNumber(packet_sequence_number)
        if index >= 0:
             self.sent_packets_list.pop(index)
             self.recalculateLHS()

    #packetEntryIndexNumber returns -1 if packet is not in table, otherwise returns index position
    def packetEntryIndexNumber(self, packet_sequence_number):

        for packetEntry in self.sent_packets_list:
            if packetEntry.packet_sequence_number == packet_sequence_number:
                return self.sent_packets_list.index(packetEntry)
        
        return -1

    #returns time a packet was sent; use for calculating RTT
    def sentTimeForPacket(self, packet_sequence_number):
        
        #find packet in table, then find time sent
        index = self.packetEntryIndexNumber(packet_sequence_number)
        return self.sent_packets_list[index].time_sent
             
    #canSend checks if sending window and current in flight un'ACKd packets allow for sending
    def canSendAnotherPacket(self):
        
        log_debug("Checking sending window. SW = {}, LHS = {}, RHS = {}".format(self.SW, self.LHS, self.RHS))
        if (self.RHS - self.LHS) < self.SW: 
            log_debug("Yes, can send another packet.")
            return True
        else: return False
        
    def recalculateLHS(self):

        #set up initial value
        lowest_sequence_number = self.RHS

        #check each packet in table to find lowest sequence number
        for packetEntry in self.sent_packets_list:
            table_sequence_number = packetEntry.packet_sequence_number
            if (table_sequence_number < lowest_sequence_number) or (lowest_sequence_number == 0):
                lowest_sequence_number = table_sequence_number
        
        #update LHS based on lowest value from table
        self.LHS = lowest_sequence_number    

    #timedOutPacketIndex identifies the first packet in table that has timed out
    def timedOutPacketIndex(self, timeout):

        current_time = time.perf_counter()
        for packetEntry in self.sent_packets_list:
            if current_time > (packetEntry.time_sent + + float(timeout)):
                return self.sent_packets_list.index(packetEntry)
        
        return -1
