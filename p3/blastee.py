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
            responseHeader,responsePayload = deconstructPacket(pkt)
            ackPacket = Ethernet() + IPv4(protocol=IPProtocol.UDP) + UDP()
            ackPacket[0].src = '20:00:00:00:00:01'  # Ethernet - blaster source and blastee dst, based on start_mininet topography
            ackPacket[0].dst = '40:00:00:00:00:01'
            ackPacket[1].src = '192.168.200.1' # based on start_mininet topography
            ackPacket[1].dst = '192.168.100.1'
            ackPacket += RawPacketContents(responseHeader)
            ackPacket += RawPacketContents(responsePayload)
            ackPacket[3].src = 4444
            ackPacket[3].dst = 5555

            net.send_packet(dev,ackPacket)
            


    net.shutdown()

def deconstructPacket(packet):
    #packet headers will always be in the same order
    header=packet[4]
    payload=packet[5]

    #making sure header is correct size
    responseHeader= int.from_bytes(header.data, byteorder = 'big').to_bytes(4, byteorder = 'big')

    #making sure payload is correct size
    responsePayload = int.from_bytes(payload.data, byteorder = 'big').to_bytes(8, byteorder = 'big')

    return responseHeader,responsePayload