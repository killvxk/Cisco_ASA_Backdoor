#ifndef REDIR_FLOW_H_INCLUDED
#define REDIR_FLOW_H_INCLUDED

#include "protocol.h"
#include "link_list.h"
#include "send.h"

#define ALLOC_ID_ARR_LEN 1
#define ALLOC_CAP_RULE_ARR_LEN 1
#define STORAGE_PKT_THRESHOLD 2000
#define PKT_CLEAR_PERCENTAGE 5
#define PKT_CALL_THRESHOLD 1000
#define REDIR_INTERVAL_PKT_THRESHOLD 3000
#define REDIR_COUNT_THRESHOLD 10

typedef struct _Redirect_Pkt_Info_Node_
{
    unsigned int call_count;         //此报文被调用次数
    unsigned short pkt_len;          //报文长度
    char pkt_buff[PKT_BUFF_SIZE];
    unsigned int id_elem_count;      //已存放的规则ID元素个数
    unsigned int *p_rule_id_arr;     //记录发送过的规则ID
    int redir_rule_count;            //需要重定向的规则计数
}REDIR_PKT;

//////////////////////////////////////////////////////
int set_redir_flow(CAP_RULE capRule);
int redirect_flow();

#endif // REDIR_FLOW_H_INCLUDED
