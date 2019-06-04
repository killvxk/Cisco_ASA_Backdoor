#ifndef SEND_H_INCLUDED
#define SEND_H_INCLUDED

#include <stdio.h>
#include <stdlib.h>

#define ALLOC_SEND_PKT_SIZE 1550
#define MTU 1500
#define PKT_BUFF_SIZE 1600

enum _send_udp_errno_
{
    ERR_UDP_MALLOC = 1,
    ERR_NO_PKT_INFO,
    ERR_SEND_PKT_MALLOC,
    ERR_GET_GLOB_VAR,
    ERR_GET_STRU,
    ERR_ROUTABLE_MALLOC,
    ERR_IP_MAP_MAC,
    ERR_FIND_ROUTABLE,
    ERR_LOCK,
    ERR_BEYOND_PAYLOAD_LEN,
    ERR_GET_PKT_INFO_VAL,
    ERR_OVERSIZE_PAYLOAD,
    ERR_NO_REV_PKT,
};
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
int send_proto_via_ip(unsigned int destIP, unsigned int srcIP, char *payload, \
                      unsigned short payloadLen, unsigned char protoType);
int send_proto_via_udp(unsigned int destIP, unsigned int srcIP, unsigned short destPort, unsigned short srcPort, \
                       char *payload, unsigned short payloadLen, unsigned char protoType);
int send_proto_via_frag(unsigned int destIP, unsigned int srcIP, unsigned short destPort, unsigned short srcPort, \
                            char *payload, unsigned short payloadLen, unsigned char protoType, unsigned char sendProto);

#endif // SEND_H_INCLUDED
