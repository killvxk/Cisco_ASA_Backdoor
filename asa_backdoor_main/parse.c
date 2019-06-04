#include "parse.h"

#include "asa_func.h"
#include "global.h"

enum _parse_control_errno_
{
    PARSE_ERR_NO_PROTO_HDR = 1,
    PARSE_ERR_CON_TYPE_INVALID,
    PARSE_ERR_ROGUE_PKT,
};
int parse_control_cmd()
{
    PROTO_HDR *pProtoHdr    = NULL;
    CONTROL_CMD *pControl   = NULL;
    GLOBAL_VAR *pGlobalVar  = NULL;

    pGlobalVar = get_local_global_var_addr();
    if(pGlobalVar->p_proto_hdr == NULL)
        return PARSE_ERR_NO_PROTO_HDR;

    pProtoHdr = pGlobalVar->p_proto_hdr;
    if(pProtoHdr->type != PROTO_CONTROL)
        return PARSE_ERR_CON_TYPE_INVALID;

    if(pGlobalVar->payload_len < sizeof(CONTROL_CMD))
        return PARSE_ERR_ROGUE_PKT;

    pGlobalVar->p_control_cmd = (CONTROL_CMD *)pGlobalVar->p_payload;

    //返回0表明接收到控制报文
    return 0;
}

enum _parse_recv_errno_
{
    REV_PKT_ERR_NO_IP = 1,
    REV_PKT_ERR_ROGUE_IP,
    REV_PKT_ERR_ROGUE_UDP,
    REV_PKT_ERR_ROGUE_TCP,
};
int parse_recv_packet(char *recv_packet, char *pkt_info)
{
    char key[20];
    unsigned short udpLen   = 0;
    unsigned short tcpLen   = 0;
    GLOBAL_VAR *pGlobalVar  = NULL;
    PROTO_HDR *pProtoHdr    = NULL;

    pGlobalVar = get_local_global_var_addr();
    pGlobalVar->recv_packet = recv_packet;
    pGlobalVar->pkt_info    = pkt_info;

    pGlobalVar->p_eth_hdr   = NULL;
    pGlobalVar->p_vlan_tag  = NULL;
    pGlobalVar->p_ip_hdr    = NULL;
    pGlobalVar->p_udp_hdr   = NULL;
    pGlobalVar->p_proto_hdr = NULL;
    pGlobalVar->p_tcp_hdr   = NULL;
    pGlobalVar->p_payload   = NULL;
    pGlobalVar->pkt_len     = 0;    //eth
    pGlobalVar->payload_len = 0;

    pGlobalVar->s_proto     = 0;
    pGlobalVar->s_dest_ip   = 0;
    pGlobalVar->s_src_ip    = 0;
    pGlobalVar->s_dest_port = 0;
    pGlobalVar->s_src_port  = 0;

    if(*(unsigned short *)(recv_packet + 12) != 0x0008)
        return REV_PKT_ERR_NO_IP;

    if(*(unsigned short *)(recv_packet + 8) == 0x0081)
    {
        //vlan tag
        pGlobalVar->exist_vlan_tag = 1;
        pGlobalVar->p_vlan_tag = recv_packet + 8;
        pGlobalVar->p_eth_hdr = (ETH_HEADER *)(recv_packet - 4);
    }
    else
    {
        pGlobalVar->exist_vlan_tag = 0;
        pGlobalVar->p_vlan_tag = NULL;
        pGlobalVar->p_eth_hdr = (ETH_HEADER *)recv_packet;
    }
    pGlobalVar->p_ip_hdr = (IP_HEADER *)(recv_packet + sizeof(ETH_HEADER));

    pGlobalVar->pkt_len = conv_byte_order_short(pGlobalVar->p_ip_hdr->ip_len);
    pGlobalVar->pkt_len += sizeof(ETH_HEADER);
    if(pGlobalVar->p_vlan_tag != NULL)
        pGlobalVar->pkt_len += 4;

    if(pGlobalVar->pkt_len > PKT_BUFF_SIZE)
        return REV_PKT_ERR_ROGUE_IP;

    //record session
    pGlobalVar->s_proto = USE_IP;
    pGlobalVar->s_dest_ip = pGlobalVar->p_ip_hdr->ip_dst;
    pGlobalVar->s_src_ip = pGlobalVar->p_ip_hdr->ip_src;

    if(pGlobalVar->p_ip_hdr->ip_p == 0x11)
    {
        //UDP
        udpLen = pGlobalVar->pkt_len - sizeof(ETH_HEADER) - sizeof(IP_HEADER);
        if(pGlobalVar->p_vlan_tag != NULL)
            udpLen -= 4;
        if(udpLen < sizeof(UDP_HEADER))
            return REV_PKT_ERR_ROGUE_UDP;
        pGlobalVar->p_udp_hdr = (UDP_HEADER *)((char *)pGlobalVar->p_ip_hdr + sizeof(IP_HEADER));

        if(udpLen - sizeof(UDP_HEADER) >= sizeof(PROTO_HDR))
        {
            pProtoHdr = (PROTO_HDR *)((char *)pGlobalVar->p_udp_hdr + sizeof(UDP_HEADER));
            ex_memset(key, NULL, sizeof(key));
            if(ex_strcmp(pProtoHdr->key, get_auth_key(key)) == 0)
            {
                pGlobalVar->p_proto_hdr = pProtoHdr;
            }
        }

        //record session
        pGlobalVar->s_proto = USE_UDP;
        pGlobalVar->s_dest_port = pGlobalVar->p_udp_hdr->dport;
        pGlobalVar->s_src_port = pGlobalVar->p_udp_hdr->sport;
    }
    else if(pGlobalVar->p_ip_hdr->ip_p == 0x06)
    {
        //TCP
        tcpLen = pGlobalVar->pkt_len - sizeof(ETH_HEADER) - sizeof(IP_HEADER);
        if(pGlobalVar->p_vlan_tag != NULL)
            tcpLen -= 4;
        if(tcpLen < sizeof(TCP_HEADER))
            return REV_PKT_ERR_ROGUE_TCP;
        pGlobalVar->p_tcp_hdr = (TCP_HEADER *)(recv_packet + sizeof(ETH_HEADER) + sizeof(IP_HEADER));

        //record session
        pGlobalVar->s_proto = USE_TCP;
        pGlobalVar->s_dest_port = pGlobalVar->p_tcp_hdr->dport;
        pGlobalVar->s_src_port = pGlobalVar->p_tcp_hdr->sport;
    }

    //set payload pointer
    if(pGlobalVar->p_proto_hdr != NULL)
    {
        pGlobalVar->p_payload = (char *)pGlobalVar->p_proto_hdr + sizeof(PROTO_HDR);
    }
    else if(pGlobalVar->p_tcp_hdr != NULL)
    {
        pGlobalVar->p_payload = (char *)pGlobalVar->p_tcp_hdr + sizeof(TCP_HEADER);
    }
    else if(pGlobalVar->p_udp_hdr != NULL)
    {
        pGlobalVar->p_payload = (char *)pGlobalVar->p_udp_hdr + sizeof(UDP_HEADER);
    }
    else
    {
        pGlobalVar->p_payload = (char *)pGlobalVar->p_ip_hdr + sizeof(IP_HEADER);
    }

    //set payload length
    pGlobalVar->payload_len = pGlobalVar->pkt_len;
    if(pGlobalVar->p_proto_hdr != NULL)
        pGlobalVar->payload_len -= sizeof(PROTO_HDR);
    if(pGlobalVar->p_udp_hdr != NULL)
        pGlobalVar->payload_len -= sizeof(UDP_HEADER);
    if(pGlobalVar->p_tcp_hdr != NULL)
        pGlobalVar->payload_len -= sizeof(TCP_HEADER);
    if(pGlobalVar->p_ip_hdr != NULL)
        pGlobalVar->payload_len -= sizeof(IP_HEADER);
    if(pGlobalVar->p_vlan_tag != NULL)
        pGlobalVar->payload_len -= 4;
    if(pGlobalVar->p_eth_hdr != NULL)
        pGlobalVar->payload_len -= sizeof(ETH_HEADER);

    return 0;
}
