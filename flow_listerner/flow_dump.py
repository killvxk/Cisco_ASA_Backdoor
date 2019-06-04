#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2017/9/5 18:38
# @Author  : weizinan
# @File    : flow_dump.py

import binascii
import traceback
from utils import *
import chardet
import codecs
from datetime import datetime
from ctypes import *
from scapy.layers.inet import *

class ProtoHdr(Structure):
    _fields_ = [
        ("key", c_char * 20),
        ("type", c_ubyte),
        ("payload_len", c_ushort)
    ]

class ProtoFrag(Structure):
    _fields_ = [
        ("type", c_ubyte),
        ("sequence", c_uint),
        ("id", c_ushort),
        ("fin_flag", c_ubyte),
        ("payload_len", c_ushort)
    ]

class ProtoRedirFlow(Structure):
    _fields_ = [
        ("cap_id", c_uint),
        ("sequence", c_uint),
        ("payload_len", c_ushort)
    ]

class FlowDump(object):
    def __init__(self, authKey, capId, dumpFilePath):
        super(FlowDump, self).__init__()

        self.authKey               = authKey
        self.capId                 = capId
        self.keyLen                = len(self.authKey)
        self.dumpFilePath          = dumpFilePath
        self.fragDict              = {}
        '''
        {
            "sequence" : {
                "timestamp" : int,
                "frag_list" : []
            }
        }
        '''

        self.dumpFile              = open(self.dumpFilePath, "wt")

    ##########################################################################
    def _format_payload(self, rawPayload):
        formatPayloadList = []
        isChinese = False

        for idx, ch in enumerate(rawPayload):
            if (ord(ch) >= 32 and ord(ch) <= 126) or (ch in ["\n", "\t", "\r"]):
                formatPayloadList.append(ch)
            else:
                formatPayloadList.append("\\x" + binascii.b2a_hex(ch))

        return "".join(formatPayloadList)

    '''
     elif ord(ch) > 128:
         if isChinese is True:
             formatPayloadList.append(ch)
             isChinese = False
         else:
             if idx + 1 < len(rawPayload):
                 if ord(rawPayload[idx + 1]) > 128:
                     isChinese = True
                     formatPayloadList.append(ch)
                 else:
                     formatPayloadList.append("\\x" + binascii.b2a_hex(ch))
             else:
                 formatPayloadList.append("\\x" + binascii.b2a_hex(ch))
     '''

    ##########################################################################
    def _flow_handler(self, flowPkt):
        protoRedirFlow = ProtoRedirFlow()
        # 重定向报文
        memmove(addressof(protoRedirFlow), flowPkt, sizeof(ProtoRedirFlow))
        rawRedirPayload = flowPkt[sizeof(ProtoRedirFlow):]
        if protoRedirFlow.cap_id != self.capId:
            return

        parsePkt = Ether(rawRedirPayload)
        if parsePkt.haslayer(IP):
            if parsePkt.haslayer(TCP):
                appPayload = str(parsePkt[TCP].payload)
                proto = "tcp"
            elif parsePkt.haslayer(UDP):
                appPayload = str(parsePkt[UDP].payload)
                proto = "udp"
            else:
                appPayload = str(parsePkt[IP].payload)
                proto = "ip"

            '''
            charType = chardet.detect(appPayload)["encoding"]
            toCharset = "utf-8"
            if charType is not None:
                gl_Logger.info("Charset: " + charType)
                try:
                    encodeRedirFlow = appPayload.decode(charType).encode(toCharset)
                except Exception, e:
                    try:
                        encodeRedirFlow = appPayload.decode("ascii").encode(toCharset)
                    except:
                        #gl_Logger.warning("Decoding failed. Exception: " + str(e))
                        encodeRedirFlow = appPayload
            else:
                try:
                    encodeRedirFlow = appPayload.encode(toCharset)
                except Exception, e:
                    try:
                        encodeRedirFlow = appPayload.decode("ascii").encode(toCharset)
                    except:
                        #gl_Logger.warning("Encoding failed. Exception: " + str(e))
                        encodeRedirFlow = appPayload
            appPayload = encodeRedirFlow
            '''
            if len(appPayload) <= 0:
                return
            if proto == "tcp":
                gl_Logger.info("TCP\t%s:%s\t->\t%s:%s\tPayload Length: %d" % (str(parsePkt[IP].src),
                                                                              str(parsePkt[TCP].sport),
                                                                              str(parsePkt[IP].dst),
                                                                              str(parsePkt[TCP].dport),
                                                                              len(appPayload)
                                                                              )
                               )
                self.dumpFile.write("TCP %s:%s -> %s:%s\n" % (str(parsePkt[IP].src), str(parsePkt[TCP].sport),
                                                               str(parsePkt[IP].dst), str(parsePkt[TCP].dport)
                                                               )
                                    )
            if proto == "udp":
                gl_Logger.info("UDP\t%s:%s\t->\t%s:%s\tPayload Length: %d" % (str(parsePkt[IP].src),
                                                                              str(parsePkt[UDP].sport),
                                                                              str(parsePkt[IP].dst),
                                                                              str(parsePkt[UDP].dport),
                                                                              len(appPayload)
                                                                              )
                               )
                self.dumpFile.write("UDP %s:%s -> %s:%s\n" % (str(parsePkt[IP].src), str(parsePkt[UDP].sport),
                                                               str(parsePkt[IP].dst), str(parsePkt[UDP].dport)
                                                               )
                                    )
            if proto == "ip":
                gl_Logger.info("IP\t%s\t->\t%s\tPayload Length: %d" % (str(parsePkt[IP].src),
                                                                       str(parsePkt[IP].dst),
                                                                       len(appPayload)
                                                                       )
                               )
                self.dumpFile.write("IP %s:%s -> %s:%s\n" % (str(parsePkt[IP].src), str(parsePkt[UDP].sport),
                                                              str(parsePkt[IP].dst), str(parsePkt[UDP].dport)
                                                              )
                                    )
            self.dumpFile.write("Timestamp: %s\n" % datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'))
            self.dumpFile.write("Payload length: %d\n\n" % len(appPayload))
            self.dumpFile.write(self._format_payload(appPayload))
            self.dumpFile.write("\n-----------------------------------------------------\n")
            self.dumpFile.flush()
        else:
            gl_Logger.warning("Fragment reassemble error.")

    ##########################################################################
    def _frag_reassemble(self, fragPkt):
        protoFrag = ProtoFrag()
        memmove(addressof(protoFrag), fragPkt, sizeof(ProtoFrag))
        if protoFrag.type != 2:
            return
        # 是重定向流量
        fragSeq = str(protoFrag.sequence)
        if self.fragDict.has_key(fragSeq) is True:
            self.fragDict[fragSeq]["frag_list"].append(fragPkt[sizeof(ProtoFrag):])
        else:
            self.fragDict[fragSeq] = {}
            self.fragDict[fragSeq]["timestamp"] = time.time()
            self.fragDict[fragSeq]["frag_list"] = []
            self.fragDict[fragSeq]["frag_list"].append(fragPkt[sizeof(ProtoFrag):])
        if protoFrag.fin_flag != 0:
            flowPkt = "".join(self.fragDict[fragSeq]["frag_list"])
            self._flow_handler(flowPkt)
            self.fragDict.pop(fragSeq)

    ##########################################################################
    def packet_handler(self, pkt):
        protoHdr = ProtoHdr()

        try:
            if pkt.haslayer(UDP):
                udpPayload = str(pkt[UDP].payload)
                if len(udpPayload) >= sizeof(ProtoHdr) + sizeof(ProtoFrag):
                    memmove(addressof(protoHdr), udpPayload, sizeof(ProtoHdr))
                    if protoHdr.key == self.authKey and protoHdr.type == 3:
                        # 是一组分片报文
                        self._frag_reassemble(udpPayload[sizeof(ProtoHdr):])
            elif pkt.haslayer(IP):
                ipPayload = str(pkt[IP].payload)
                if len(ipPayload) >= sizeof(ProtoHdr) + sizeof(ProtoFrag):
                    memmove(addressof(protoHdr), ipPayload, sizeof(ProtoHdr))
                    if protoHdr.key == self.authKey and protoHdr.type == 3:
                        # 是一组分片报文
                        self._frag_reassemble(ipPayload[sizeof(ProtoHdr):])
        except Exception, e:
            print "Packet handler error. Exception: " + str(e)
            traceback.print_exc(limit=1)

    ##########################################################################
    def start(self):
        while True:
            time.sleep(1)