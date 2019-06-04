#include <stdio.h>
#include <stdlib.h>

#include "redir_flow.h"
#include "asa_func.h"
#include "protocol.h"
#include "send.h"
#include "global.h"
#include "link_list.h"

enum _send_redirect_pkt_errno_
{
    REDIR_ERR_SHORT_LEN_PKT = 1,
};
static int send_redir_packet(char *pPkt, unsigned short pktLen, unsigned int destIP, unsigned int srcIP,
                             unsigned short destPort, unsigned short srcPort, unsigned char sendProto,
                             unsigned int capId)
{
    char buff[PKT_BUFF_SIZE];
    GLOBAL_VAR *pGlobalVarAddr = NULL;
    REDIR_HDR redirHdr;
    int retVal = 0;

    if(pktLen == 0)
        return REDIR_ERR_SHORT_LEN_PKT;

    pGlobalVarAddr = get_local_global_var_addr();
    if(pGlobalVarAddr->redir_sequence > 4293918720)
        pGlobalVarAddr->redir_sequence = 0;
    pGlobalVarAddr->redir_sequence++;

    //init redirect packet
    ex_memset(buff, NULL, sizeof(buff));
    ex_memset(&redirHdr, NULL, sizeof(redirHdr));

    redirHdr.cap_id = capId;
    redirHdr.sequence = pGlobalVarAddr->redir_sequence;
    redirHdr.payload_len = pktLen;

    //wrap
    ex_memcpy(buff, &redirHdr, sizeof(redirHdr));
    ex_memcpy(buff + sizeof(redirHdr), pPkt, pktLen);

    //send redirect flow
    retVal = send_proto_via_frag(destIP, srcIP, destPort, srcPort, buff, \
                                 sizeof(redirHdr) + pktLen, FRAG_PROTO_REDIR_FLOW, sendProto);

    return retVal;
}

enum _set_redir_errno_
{
    SET_REDIR_ERR_ALLOC = 1,
};
int set_redir_flow(CAP_RULE capRule)
{
    GLOBAL_VAR *pGlobalVar = NULL;
    int idx = 0;
    int ruleId = 0;

    pGlobalVar = get_local_global_var_addr();

    if(pGlobalVar->p_cap_rule_arr == NULL)
    {
        //创建重定向规则链表
        pGlobalVar->p_cap_rule_arr = (CAP_RULE *)asa_malloc(sizeof(CAP_RULE) * ALLOC_CAP_RULE_ARR_LEN);
        if(pGlobalVar->p_cap_rule_arr == NULL)
            return SET_REDIR_ERR_ALLOC;
        ex_memset(pGlobalVar->p_cap_rule_arr, NULL, sizeof(CAP_RULE) * ALLOC_CAP_RULE_ARR_LEN);
        pGlobalVar->cap_rule_arr_len = ALLOC_CAP_RULE_ARR_LEN;
    }
    else
    {
        if(pGlobalVar->redir_rule_count == pGlobalVar->cap_rule_arr_len)
        {
            //数组位已用尽
            pGlobalVar->p_cap_rule_arr = asa_realloc(pGlobalVar->p_cap_rule_arr, \
                                         sizeof(CAP_RULE) * pGlobalVar->cap_rule_arr_len, \
                                         sizeof(CAP_RULE) * (pGlobalVar->cap_rule_arr_len + \
                                                 ALLOC_CAP_RULE_ARR_LEN));
            if(pGlobalVar->p_cap_rule_arr == NULL)
            {
                pGlobalVar->redir_rule_count = 0;
                pGlobalVar->cap_rule_arr_len = 0;
                return SET_REDIR_ERR_ALLOC;
            }
            pGlobalVar->cap_rule_arr_len += ALLOC_CAP_RULE_ARR_LEN;
        }
    }

    for(idx = 0; idx <= pGlobalVar->cap_rule_arr_len; idx++)
    {
        if(pGlobalVar->p_cap_rule_arr[idx].id == 0)
        {
            pGlobalVar->p_cap_rule_arr[idx] = capRule;
            pGlobalVar->p_cap_rule_arr[idx].id = idx + 1;
            ruleId = idx + 1;
            if(idx + 1 > pGlobalVar->cap_rule_max_id)
            {
                pGlobalVar->cap_rule_max_id = idx + 1;
            }
            break;
        }
    }
    pGlobalVar->redir_rule_count++;

    return ruleId;
}

static int match_ip_via_mask(unsigned int ip, unsigned int subIP, unsigned int mask)
{
    return (ip & mask) == (subIP & mask) ? 1 : 0;
}

enum _match_acl_retno_
{
    ACL_MATCH = 1,
    ACL_MISMATCH,
    ACL_NO_IP,
    ACL_IS_ICMP,
};
static int match_flow_via_acl(const CAP_RULE *pCapRule)
{
    GLOBAL_VAR *pGlobalVar = NULL;

    pGlobalVar = get_local_global_var_addr();

    if(pGlobalVar->p_ip_hdr == NULL)
        return ACL_NO_IP;
    if(pGlobalVar->p_ip_hdr->ip_p == 0x01)
        return ACL_IS_ICMP;

    //匹配五元组
    if(match_ip_via_mask(pGlobalVar->p_ip_hdr->ip_dst, pCapRule->dest_ip, pCapRule->dest_mask) && \
            match_ip_via_mask(pGlobalVar->p_ip_hdr->ip_src, pCapRule->src_ip, pCapRule->src_mask))
    {
        if(pCapRule->proto == CAP_PROTO_IP)
        {
            //匹配IP报文
            return ACL_MATCH;
        }
        else if(pCapRule->proto == CAP_PROTO_TCP)
        {
            //匹配TCP报文
            if(pGlobalVar->p_tcp_hdr == NULL)
                return ACL_MISMATCH;

            if(pCapRule->dest_port != 0)
            {
                if(pCapRule->dest_port != pGlobalVar->p_tcp_hdr->dport)
                    return ACL_MISMATCH;
            }
            if(pCapRule->src_port != 0)
            {
                if(pCapRule->src_port != pGlobalVar->p_tcp_hdr->sport)
                    return ACL_MISMATCH;
            }
            return ACL_MATCH;
        }
        else if(pCapRule->proto == CAP_PROTO_UDP)
        {
            //匹配UDP报文
            if(pGlobalVar->p_udp_hdr == NULL)
                return ACL_MISMATCH;

            if(pCapRule->dest_port != 0)
            {
                if(pCapRule->dest_port != pGlobalVar->p_udp_hdr->dport)
                    return ACL_MISMATCH;
            }
            if(pCapRule->src_port != 0)
            {
                if(pCapRule->src_port != pGlobalVar->p_udp_hdr->sport)
                    return ACL_MISMATCH;
            }
            return ACL_MATCH;
        }
        else
        {
            return ACL_MISMATCH;
        }
    }

    return ACL_MISMATCH;
}

REDIR_PKT *add_pkt_to_redir_list(char *pktBuff, unsigned short pktLen)
{
    REDIR_PKT *pRedirPkt = NULL;
    GLOBAL_VAR *pGlobalVar = NULL;

    pGlobalVar = get_local_global_var_addr();
    if(pGlobalVar->p_ip_hdr == NULL)
        return NULL;

    /////////////////////////////////////////////////////////////////////////////////
    //加入重定向列表
    pRedirPkt = asa_malloc(sizeof(REDIR_PKT));
    if(pRedirPkt == NULL)
        return NULL;       //内存紧急状态
    ex_memset(pRedirPkt, 0x00, sizeof(REDIR_PKT));

    pRedirPkt->p_rule_id_arr = asa_malloc(sizeof(unsigned int) * ALLOC_ID_ARR_LEN);
    if(pRedirPkt->p_rule_id_arr == NULL)
    {
        asa_free(pRedirPkt);
        return NULL;
    }
    ex_memset(pRedirPkt->p_rule_id_arr, 0x00, sizeof(unsigned int) * ALLOC_ID_ARR_LEN);

    if(pktLen >= PKT_BUFF_SIZE)
    {
        ex_memcpy(pRedirPkt->pkt_buff, pktBuff, PKT_BUFF_SIZE);
        pRedirPkt->pkt_len = PKT_BUFF_SIZE;
    }
    else
    {
        ex_memcpy(pRedirPkt->pkt_buff, pktBuff, pktLen);
        pRedirPkt->pkt_len = pGlobalVar->pkt_len;
    }

    ////////////////////////////////////////////////////////////////////////////////
    if(pGlobalVar->p_redir_pkt_list == NULL)
    {
        pGlobalVar->p_redir_pkt_list = create_link_list(pRedirPkt);
        if(pGlobalVar->p_redir_pkt_list == NULL)
        {
            asa_free(pRedirPkt->p_rule_id_arr);
            asa_free(pRedirPkt);
            return NULL;       //内存紧急状态
        }
    }
    else
    {
        if(append_list_node(pGlobalVar->p_redir_pkt_list, pRedirPkt) == NULL)
        {
            asa_free(pRedirPkt->p_rule_id_arr);
            asa_free(pRedirPkt);
            return NULL;       //内存紧急状态
        }
    }

    pGlobalVar->pkt_list_len++;

    return pRedirPkt;
}

enum _redir_flow_retno_
{
    REDIR_RET_SUCC = 0,
    REDIR_RET_NO_IP,
    REDIR_RET_MISMATCH,
    REDIR_RET_SEND_FAILED,
    REDIR_RET_NO_ACL,
    REDIR_RET_MEM_EMER,
    REDIR_RET_IN_INTERVAL,
};
int redirect_flow()
{
    GLOBAL_VAR *pGlobalVar = NULL;
    LIST_NODE *pRedirPktNode = NULL;
    LIST_NODE *pTmp = NULL;
    CAP_RULE *pCapRule = NULL;
    int matchStat = 0;
    int retVal = REDIR_RET_MISMATCH;
    REDIR_PKT *pRedirPkt = NULL;
    int memEmergency = 0;
    int idx, ruleIdx;
    int clearCount = 0;
    int thresholdPercent = 0;
    int redirCount = 0;

    pGlobalVar = get_local_global_var_addr();
    if(pGlobalVar->p_cap_rule_arr == NULL)
        return REDIR_RET_NO_ACL;

    //通过ACL匹配新接收到的报文
    for(pRedirPkt=NULL, pCapRule=pGlobalVar->p_cap_rule_arr, idx=0; \
            idx < pGlobalVar->cap_rule_max_id; ++idx, ++pCapRule)
    {
        //匹配ACL
        matchStat = match_flow_via_acl(pCapRule);
        if(matchStat == ACL_NO_IP)
        {
            retVal = REDIR_RET_NO_IP;
            break;
        }
        else if(matchStat == ACL_MATCH)
        {
            //将命中ACL的报文加入重定向列表
            if(pRedirPkt == NULL)
            {
                pRedirPkt = add_pkt_to_redir_list((char *)pGlobalVar->p_eth_hdr, pGlobalVar->pkt_len);
                if(pRedirPkt == NULL)
                {
                    memEmergency = 1;   //内存紧急状态
                    goto emergency;
                }
            }

            //将命中的规则ID记录到待发送的报文中
            if(pRedirPkt->id_elem_count != 0 && pRedirPkt->id_elem_count % ALLOC_ID_ARR_LEN == 0)
            {
                //数组空余位已用尽
                pRedirPkt->p_rule_id_arr = asa_realloc(pRedirPkt->p_rule_id_arr, \
                                                       pRedirPkt->id_elem_count * sizeof(unsigned int), \
                                                       (pRedirPkt->id_elem_count + ALLOC_ID_ARR_LEN) * sizeof(unsigned int));
                if(pRedirPkt->p_rule_id_arr == NULL)
                {
                    memEmergency = 1;   //内存紧急状态
                    goto emergency;
                }
            }
            pRedirPkt->p_rule_id_arr[pRedirPkt->id_elem_count] = pCapRule->id;
            ++pRedirPkt->id_elem_count;
            ++pRedirPkt->redir_rule_count;
        }
    }
    /*
        //控制重定向间隔
        if(pGlobalVar->redir_count <= 0)
        {
            if(pGlobalVar->recv_pkt_count < REDIR_INTERVAL_PKT_THRESHOLD)
            {
                pGlobalVar->recv_pkt_count++;
                return REDIR_RET_IN_INTERVAL;
            }
            else
            {
                pGlobalVar->recv_pkt_count = 0;
                pGlobalVar->redir_count = REDIR_COUNT_THRESHOLD;
            }
        }
        else
        {
            pGlobalVar->redir_count--;
        }
    */
    //发送重定向报文
    for(pRedirPktNode=pGlobalVar->p_redir_pkt_list; pRedirPktNode != NULL; )
    {
        //待发送的报文链表
        pRedirPkt = (REDIR_PKT *)pRedirPktNode->p_elem_addr;
        for(idx=0; idx < pRedirPkt->id_elem_count; ++idx)
        {
            //匹配重定向规则ID
            if(pRedirPkt->p_rule_id_arr[idx] != 0)
            {
                ruleIdx = pRedirPkt->p_rule_id_arr[idx] - 1;
                if(pGlobalVar->p_cap_rule_arr[ruleIdx].id != 0)
                {
                    //此报文命中当前规则，需要向此规则重定向报文。
                    pCapRule = &pGlobalVar->p_cap_rule_arr[ruleIdx];
                    retVal = send_redir_packet(pRedirPkt->pkt_buff, pRedirPkt->pkt_len, \
                                               pCapRule->send_dest_ip, pCapRule->send_src_ip, \
                                               pCapRule->send_dest_port, pCapRule->send_src_port, \
                                               pCapRule->send_proto,
                                               pCapRule->id);
                    pRedirPkt->call_count++;
                    if(retVal == 0)
                    {
                        //报文发送成功
                        //将当前重定向的规则ID从报文中删除
                        pRedirPkt->p_rule_id_arr[idx] = 0;
                        pRedirPkt->redir_rule_count--;
                    }
                }
                else
                {
                    pRedirPkt->p_rule_id_arr[idx] = 0;
                    pRedirPkt->redir_rule_count--;
                }
            }
        }

        //检测当前报文是否需要删除
        if(pRedirPkt->redir_rule_count <= 0 || pRedirPkt->call_count >= PKT_CALL_THRESHOLD)
        {
            //此数据包已在所有接口上转发完成或需要强制清理
            if(pRedirPkt->p_rule_id_arr != NULL)
                asa_free(pRedirPkt->p_rule_id_arr);
            pTmp = delete_list_node_and_elem(pRedirPktNode);
            if(pRedirPktNode == pGlobalVar->p_redir_pkt_list)
            {
                //删除的是头节点
                pGlobalVar->p_redir_pkt_list = pTmp;
            }
            pRedirPktNode = pTmp;
            pGlobalVar->pkt_list_len--;
        }
        else
        {
            pRedirPktNode = pRedirPktNode->next;
        }
    }

emergency:
    //存数到达阈值，清理pkt list
    if(memEmergency != 0 || pGlobalVar->pkt_list_len >= STORAGE_PKT_THRESHOLD)
    {
        if(pGlobalVar->pkt_list_len >= STORAGE_PKT_THRESHOLD)
        {
            //存储的报文数量到达阈值则进行清理。
            if(PKT_CLEAR_PERCENTAGE <= 0 || PKT_CLEAR_PERCENTAGE > 10)
                thresholdPercent = 3;
            else
                thresholdPercent = PKT_CLEAR_PERCENTAGE;

            clearCount = STORAGE_PKT_THRESHOLD / 10 * thresholdPercent;
        }

        for(pRedirPktNode=pGlobalVar->p_redir_pkt_list; pRedirPktNode != NULL; )
        {
            pRedirPkt = (REDIR_PKT *)pRedirPktNode->p_elem_addr;
            if(memEmergency != 0)
            {
                //内存紧急，销毁所有报文
                if(pRedirPkt->p_rule_id_arr != NULL)
                    asa_free(pRedirPkt->p_rule_id_arr);
                pRedirPktNode=pRedirPktNode->next;
                continue;
            }
            else if(clearCount > 0)
            {
                //到达阈值清理报文
                if(pRedirPkt->p_rule_id_arr != NULL)
                    asa_free(pRedirPkt->p_rule_id_arr);
                pTmp = delete_list_node_and_elem(pRedirPktNode);
                if(pRedirPktNode == pGlobalVar->p_redir_pkt_list)
                {
                    //删除的是头节点
                    pGlobalVar->p_redir_pkt_list = pTmp;
                }
                pRedirPktNode = pTmp;
                pGlobalVar->pkt_list_len--;
                clearCount--;
                continue;
            }
            else
            {
                break;
            }
        }
        if(memEmergency != 0)
        {
            //内存紧急，销毁所有重定向流量。
            destory_link_list_and_elem(pGlobalVar->p_redir_pkt_list);
            pGlobalVar->pkt_list_len = 0;
            pGlobalVar->p_redir_pkt_list = NULL;
            retVal = REDIR_RET_MEM_EMER;
        }
    }

    return retVal;
}










