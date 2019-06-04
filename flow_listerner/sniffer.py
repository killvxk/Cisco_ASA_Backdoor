#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2017/9/5 14:26
# @Author  : weizinan
# @File    : sniffer.py

import threading
import time
from scapy.all import *

class Sniffer(threading.Thread):
    def __init__(self, iface="eth0", filter=None, stopFilter=None, timeout=None):
        super(Sniffer, self).__init__()

        self.iface            = iface
        self.active           = True
        self.stopFlag         = False
        self.filter           = filter
        self.stopFilter       = stopFilter
        self.timeout          = timeout

    ##########################################################################
    def packet_handler_callback(self, pkt):
        pass

    ##########################################################################
    def run(self):
        while self.active:
            try:
                recv_packet = sniff(iface=self.iface, filter=self.filter, store=0, prn=self.packet_handler_callback,
                                    stop_filter=self.stopFilter, timeout=self.timeout)
            except Exception, e:
                print "Sniffer start error. Exception: " + str(e)
                return -1

        self.stopFilter = True

    ##########################################################################
    def stop(self):
        self.active = False
        while self.stopFilter is False:
            time.sleep(0.001)
        return