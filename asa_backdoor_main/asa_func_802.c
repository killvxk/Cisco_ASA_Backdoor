#include "asa_func.h"

#if ASA_VER == 802
int entry_func(char *recv_packet, char *pkt_info)
{
    int retVal = 0;

    retVal = main(recv_packet, pkt_info);

    return retVal;
}

/*----------------------------------------ASA Functions--------------------------------------------------*/
void *asa_malloc(int size)
{
    __asm__(
        "movl 8(%ebp), %eax\n\t"
        "push %eax\n\t"
        "movl $0x892DCE0, %eax\n\t"
        "call %eax\n\t"
        "add $4, %esp"
    );
    return;
}

void asa_free(void *pBuff)
{
    __asm__(
        "movl 8(%ebp), %eax\n\t"
        "push %eax\n\t"
        "movl $0x90A2E40, %eax\n\t"
        "call %eax\n\t"
        "add $4, %esp"
    );
    return;
}

int asa_memcopy(void *destAddr, void *srcAddr, int length)
{
    __asm__(
        "movl 16(%ebp), %eax\n\t"
        "push %eax\n\t"
        "movl 12(%ebp), %eax\n\t"
        "push %eax\n\t"
        "movl 8(%ebp), %eax\n\t"
        "push %eax\n\t"
        "movl $0x90A33C0, %eax\n\t"
        "call %eax\n\t"
        "add $12, %esp"
    );
    return;
}

char *asa_alloc_send_pkt(unsigned int len)
{
    __asm__(
        "movl 8(%ebp), %eax\n\t"
        "push %eax\n\t"
        "xor %ecx, %ecx\n\t"
        "xor %edx, %edx\n\t"
        "movl $0x892F690, %eax\n\t"
        "call %eax\n\t"
        "add $4, %esp"
    );
    return;
}

void asa_free_send_pkt(ASA_SEND_PKT **pBuff)
{
    __asm__(
        "movl 8(%ebp), %eax\n\t"
        "push %eax\n\t"
        "movl $0x892DE70, %eax\n\t"
        "call %eax\n\t"
        "add $4, %esp"
    );
    return;
}

int get_can_send_val(char *recv_packet, char *pkt_info)
{
    /*
    return：-1不能send数据包  else：可以send
    */
    int result;
    int v3;

    result = -1;
    if(pkt_info)
    {
        v3 = *(int *)(pkt_info + 12);
        if(v3)
            result = *(int *)(v3 + 40);
    }
    return result;
}

int asa_dec_lock(int a1)
{
    __asm__(
        "movl 8(%ebp), %eax\n\t"
        "push %eax\n\t"
        "movl $0x87D7C90, %eax\n\t"
        "call %eax\n\t"
        "add $4, %esp"
    );
    return;
}

char *asa_about_thread_vcid(int a1)
{
    __asm__(
        "movl 8(%ebp), %eax\n\t"
        "push %eax\n\t"
        "movl $0x8473E60, %eax\n\t"
        "call %eax\n\t"
        "add $4, %esp"
    );
    return;
}

int asa_find_router_table(unsigned int ip, char *pRouterTable)
{
    /*
    desc: 查找到达IP的路由表
    return: 成功返回1
    */
    __asm__(
        "movl 12(%ebp), %eax\n\t"
        "push %eax\n\t"
        "movl 8(%ebp), %eax\n\t"
        "push %eax\n\t"
        "movl $0x86FB020, %eax\n\t"
        "call %eax\n\t"
        "add $8, %esp"
    );
    return;
}

char *asa_find_mac_with_ip(unsigned int destIP, char *pRouterTable, unsigned int nextIP, char *v6)
{
    /*
    destIP：目的IP
    pRouterTable：路由表指针
    nextIP：下一跳IP
    desc: 在路由表中查找IP对应的MAC地址
    return: 返回存放MAC地址的结构体
    */
    __asm__(
        "movl 20(%ebp), %eax\n\t"
        "push %eax\n\t"
        "movl 16(%ebp), %eax\n\t"
        "push %eax\n\t"
        "movl 12(%ebp), %ecx\n\t"
        "movl 8(%ebp), %edx\n\t"
        "movl $0x84643C0, %eax\n\t"
        "call %eax\n\t"
        "add $8, %esp"
    );
    return;
}

int asa_add_ip_packet(ASA_SEND_PKT *pSendPkt)
{
    /*
    desc: 在SEND_PKT结构中填充IP数据包
    */
    __asm__(
        "movl 8(%ebp), %eax\n\t"
        "push %eax\n\t"
        "movl $0x8463430, %eax\n\t"
        "call %eax\n\t"
        "add $4, %esp"
    );
    return;
}

int asa_add_router_mac(ASA_SEND_PKT *pSendPkt, char *pMac, unsigned short proto)
{
    /*
    desc: 在SEND_PKT结构中填充下一跳的MAC地址
    pMac: MAC地址指针
    proto: Eth上层协议类型
    */
    __asm__(
        "movl 16(%ebp), %eax\n\t"
        "push %eax\n\t"
        "movl 12(%ebp), %eax\n\t"
        "push %eax\n\t"
        "movl 8(%ebp), %eax\n\t"
        "push %eax\n\t"
        "movl $0x8462890, %eax\n\t"
        "call %eax\n\t"
        "add $12, %esp"
    );
    return;
}

int asa_send(char *a1, ASA_SEND_PKT *pSendPkt)
{
    __asm__(
        "movl 12(%ebp), %eax\n\t"
        "push %eax\n\t"
        "movl 8(%ebp), %ebx\n\t"
        "movl 4(%ebx), %eax\n\t"
        "push %eax\n\t"
        "add $12, %eax\n\n"
        "movl (%eax), %eax\n\t"
        "call %eax\n\t"
        "add $8, %esp"
    );
    return;
}

int asa_get_en_auth_addr()
{
    //返回enable认证函数起始地址
    return 0x906ED20;
}

int asa_get_login_auth_addr()
{
    //返回登录认证函数起始地址
    return 0x8065A30;
}

int asa_printf(char *str)
{
    __asm__(
            "movl 8(%ebp), %eax\n\t"
            "push %eax\n\t"
            "movl $0x90B7D20, %eax\n\t"
            "call %eax\n\t"
            "add $4, %esp"
            );
    return;
}

char *get_dec_lock_addr()
{
    return (char *)0x99A9E20;
}

char *get_send_func_addr_var(char *a1, int a2, int a3)
{
    char *result;
    char *v4;
    unsigned int v5;
    char *v6;
    int loopCount = 0;

    __asm__(
        "movl $0x95E1850, %eax\n\t"
        "movl %ds:(%eax), %ebx\n\t"
        "movl %ebx, -8(%ebp)\n\t"
    );

    result = 0;
    if (v4)
    {
        do
        {
            v5 = 0;
            if ( a2 > 0 )
            {
                v6 = &v4[a3];
                do
                {
                    if ( *(char *)(a1 + v5) != *v6 )
                        break;
                    ++v6;
                    ++v5;
                }
                while ( v5 < a2 );
            }
            if ( v5 == a2 )
                return v4;
            v4 = *(char **)v4;
        }
        while ( v4 != 0x95E1850 && v4 != 0 && loopCount < 1000);
        result = 0;
    }
    return result;
}

#endif // ASA_VER
