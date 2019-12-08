#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from threading import *
import random
import time

def drop(percent):
    return random.randrange(100) < percent

def delay(mean, std):
    delay =random.gauss(mean, std)
    print(delay)
    if delay > 0:
        time.sleep(delay/1000)

def switchy_main(net):

    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]
    percent,random_seed,std,mean=paramExtraction()
    random.seed(random_seed) #Extract random seed from params file


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
            log_debug("I got a packet {}".format(pkt))

        if dev == "middlebox-eth0":
            log_debug("Received from blaster")
            '''
            Received data packet
            Should I drop it?
            '''
            if not drop(percent):
                delay (mean,std)
                #need to change out packet header info
            '''
            If not, modify headers, add a delay & send to blastee
            '''
                net.send_packet("middlebox-eth1", pkt)
        elif dev == "middlebox-eth1":
            log_debug("Received from blastee")
            '''
            Received ACK
            Modify headers & send to blaster. Not dropping ACK packets!
            Don't add any delay as well
            net.send_packet("middlebox-eth0", pkt)
            '''

            net.send_packet("middlebox-eth0", pkt)

        else:
            log_debug("Oops :))")

    net.shutdown()

def paramExtraction():
    file = open("middlebox_params.txt", "r")
    templist = file.readlines()
    for templine in templist:
        line = templine.split('-')
        for char in line:
            if 'p ' in char:
                probability = char.split('p ')[1]
            elif 's ' in char:
                seed = char.split('s ')[1]

            elif 'dstd ' in char:
                dstd = char.split('dstd ')[1]

            elif 'dm ' in char:
                dm = char.split('dm ')[1]
    return probability,seed,dstd,dm

def createHeader(dev,packet):
    #construct header
    tempHeader = Ethernet()
    if dev == "middlebox-eth0":
        tempHeader.src = mymacs[1]#TODO:double check
    else:
        tempHeader.src = mymacs[0]#TODO: double check
    tempHeader.dst=packet.get_header(Ethernet).dst
    packet[0] = tempHeader
    return