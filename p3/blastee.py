#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from threading import *
import time

def switchy_main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]

    while True:
        gotpkt = True
        try:
            timestamp,dev,pkt = net.recv_packet()
            log_debug("Device is {}".format(dev))
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("I got a packet from {}".format(dev))
            log_debug("Pkt: {}".format(pkt))
            responsePayload = deconstructPacket(pkt)
            ackPacket = Ethernet() + IPv4(protocol=IPProtocol.UDP) + UDP() + RawPacketContents(responsePayload)
            ackPacket[UDP].src = 4444
            ackPacket[UDP].dst = 5555

            net.send_packet(dev,ackPacket)
            


    net.shutdown()

def deconstructPacket(packet):
    header=packet.get_header(RawPacketContents)
    payload=header.data
    #TODO: how do I do this


    return responsePayload