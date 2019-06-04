#ifndef GLOBAL_H_INCLUDED
#define GLOBAL_H_INCLUDED

#include "protocol.h"
#include "link_list.h"
#include "send.h"
#include "redir_flow.h"

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
    unsigned short sport;
    unsigned short dport;
    unsigned short length;
    unsigned short checksum;
} UDP_HEADER;

/////////////////////////////////////////////////////////////////////////////
typedef struct _Global_Variable_
{
    unsigned int init_flag;          //结构体初始化标识
    unsigned int exist_vlan_tag;     //是否存在VLAN TAG

    //redirect flow
    int redir_rule_count;            //总规则计数
    unsigned int redir_sequence;     //流量重定向数据包序列号
    CAP_RULE *p_cap_rule_arr;        //流量重定向规则数组
    int cap_rule_arr_len;            //规则数组长度
    int cap_rule_max_id;             //最大的ID编号

    //packet addr
    char *recv_packet;
    char *pkt_info;

    //parse recv packet
    unsigned short pkt_len;      //eth length
    unsigned short payload_len;
    ETH_HEADER *p_eth_hdr;
    unsigned int *p_vlan_tag;
    IP_HEADER *p_ip_hdr;
    UDP_HEADER *p_udp_hdr;
    TCP_HEADER *p_tcp_hdr;
    PROTO_HDR *p_proto_hdr;
    CONTROL_CMD *p_control_cmd;
    char *p_payload;

    //session
    unsigned char s_proto;
    unsigned int s_src_ip;
    unsigned int s_dest_ip;
    unsigned short s_src_port;
    unsigned short s_dest_port;

    //redirect recv packet list
    LIST_NODE *p_redir_pkt_list;
    int pkt_list_len;
    int recv_pkt_count;
    int redir_count;

    //master info
    unsigned int master_ip;
    unsigned short master_port;

    //send pkt fragment
    unsigned int frag_sequence;

    //backup path auth code
    int en_auth_code_size;
    char backup_en_auth_code[20];
    int login_auth_code_size;
    char backup_login_auth_code[20];
}GLOBAL_VAR;

/////////////////////////////////////////////////////////////////////////////
GLOBAL_VAR *get_local_global_var_addr();
char *ex_strcat(char *pDstAddr, char *pSrcAddr);
int ex_strcmp(char *mStr, char *pStr);
char *ex_memcpy(char *pDstAddr, char *pSrcAddr, unsigned int len);
char *ex_memset(char *pAddr, char ch, unsigned int len);
int ex_memcmp(char *p1, char *p2, unsigned int len);
int ex_mprotect(char *pAddr, int size, int flags);
unsigned short conv_byte_order_short(unsigned short n);
char *get_auth_key(char *pKey);
void *asa_realloc(void *pBuff, int oldSize, int newSize);
int debug_num(int val);

#endif // GLOBAL_H_INCLUDED
