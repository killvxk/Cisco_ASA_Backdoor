#include <stdio.h>
#include <stdlib.h>

#include "asa_func.h"
#include "send.h"
#include "global.h"
#include "protocol.h"
#include "parse.h"
#include "control_interface.h"

int main(char *recv_packet, char *pkt_info)
{
    if(recv_packet == NULL || pkt_info == NULL)
        return -1;

    //解析接收到的报文
    if(parse_recv_packet(recv_packet, pkt_info) != 0)
    {
        //解析出错则不执行接下来的流程。
        return -1;
    }

    if(parse_control_cmd() == 0)
    {
        //接收到控制命令，此流量不需重定向
        exec_control_cmd();     //执行命令
        return 0;
    }

    redirect_flow();

    return 0;
}
