#ifndef COMMUN_H_INCLUDED
#define COMMUN_H_INCLUDED

#define AUTH_KEY "Wayne_7437"
#define MTU 1500
#define PKT_BUFF_SIZE 1600

#define Linux

#ifdef Windows
#include <windows.h>
#include <winsock2.h>
#endif // Windows

#ifdef Linux
#define SOCKET int
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif // Linux

//////////////////////////////////////////////////////////////////////////////////
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
    unsigned int ip_src;           /*source address(源地址)*/
    unsigned int ip_dst;           /*destination address(目的地址)*/
} IP_HEADER;

typedef struct _TCP_Header_
{
    unsigned short int sport;    /*source port (源端口号)*/
    unsigned short int dport;    /*destination port(目的端口号)*/
    unsigned int th_seq;         /*sequence number(包的序列号)*/
    unsigned int th_ack;         /*acknowledgement number(确认应答号)*/
    unsigned char th_x:4;        /*unused(未使用)*/
    unsigned char th_off:4;      /*data offset(数据偏移量)*/
    unsigned char Flags;         /*标志全*/
    unsigned short int th_win;   /*windows(窗口)*/
    unsigned short int th_sum;   /*checksum(校验和)*/
    unsigned short int th_urp;   /*urgent pointer(紧急指针)*/
} TCP_HEADER;

typedef struct _UDP_Header_
{
    unsigned short int sport;
    unsigned short int dport;
    unsigned short int length;
    unsigned short int checksum;
} UDP_HEADER;

/////////////////////////////////////////////////////////////////////////////////////
SOCKET create_udp_socket();
struct sockaddr_in bind_udp_dest_addr(char *destIP, int destPort);
int send_control_proto_via_udp(SOCKET soc, struct sockaddr_in destAddr, char *destIP, \
                               unsigned short destPort, char *pPayload, unsigned short payloadLen);
int set_redirect_flow();

#endif // COMMUN_H_INCLUDED
