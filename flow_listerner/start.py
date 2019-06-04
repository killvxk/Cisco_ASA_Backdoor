#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2017/9/5 14:24
# @Author  : weizinan
# @File    : start.py

import sniffer
import signal
import os
import getopt
import sys
import flow_dump
from utils import *
from scapy.layers.inet import *

def sigint_handler(sig, frame):
    gl_Logger.info("Recv sigint signal, the process will exit.")
    os.kill(0 - os.getpid(), signal.SIGKILL)

if __name__ == '__main__':
    options      = [("","")]
    iface        = "eth0"
    capId        = 1
    dumpFile     = None
    try:
        options, args = getopt.getopt(sys.argv[1:], "i:n:o:")
    except Exception, e:
        print "Command error."
        os._exit(-1)
    for op, val in options:
        if op == "-i":
            iface = val
        elif op == "-n":
            capId = int(val)
        elif op == "-o":
            dumpFile = val
        else:
            print "Command error."
            os._exit(-1)
    if dumpFile is None:
        print "Command error."
        os._exit(-1)

    signal.signal(signal.SIGINT, sigint_handler)
    dump = flow_dump.FlowDump("Wayne_7437", capId, dumpFile)
    flowSniff = sniffer.Sniffer(iface=iface)
    flowSniff.packet_handler_callback = dump.packet_handler
    flowSniff.start()
    dump.start()
