#include "asa_func.h"

#if ASA_VER == 805

/*----------------------------------------ASA Functions--------------------------------------------------*/
void *asa_malloc(int size)
{
    __asm__(
        "movl 8(%ebp), %eax\n\t"
        "push %eax\n\t"
        "movl $0x89E68E0, %eax\n\t"
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
        "movl $0x91B6EE0, %eax\n\t"
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
        "movl $0x91B7460, %eax\n\t"
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
        "movl $0x89E7450, %eax\n\t"
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
        "movl $0x89E6A70, %eax\n\t"
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
        "movl $0x887C060, %eax\n\t"
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
        "movl $0x84E5100, %eax\n\t"
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
        "movl $0x8799030, %eax\n\t"
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
        "movl $0x84D49C0, %eax\n\t"
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
        "movl $0x84D3EF0, %eax\n\t"
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
        "movl $0x84D3370, %eax\n\t"
        "call %eax\n\t"
        "add $12, %esp"
    );
    return;
}

int asa_send(char *a1, ASA_SEND_PKT *pSendPkt)
{
    int sendAddr = -1;

    __asm__(
        "movl 12(%ebp), %eax\n\t"
        "push %eax\n\t"
        "movl 8(%ebp), %ebx\n\t"
        "movl 1(%ebx), %eax\n\t"
        "push %eax\n\t"
        "add $12, %eax\n\n"
        "movl (%eax), %eax\n\t"
        "movl %eax, -4(%ebp)\n\t"
    );

    __asm__(
        "movl -4(%ebp), %eax\n\t"
        "call %eax\n\t"
        "add $8, %esp"
    );
    return;
}

int asa_get_en_auth_addr()
{
    //返回enable认证函数起始地址
    return 0x9182040;
}

int asa_get_login_auth_addr()
{
    //返回登录认证函数起始地址
    return 0x8066B80;
}

int asa_printf(char *str)
{
    __asm__(
        "movl 8(%ebp), %eax\n\t"
        "push %eax\n\t"
        "movl $0x91CD350, %eax\n\t"
        "call %eax\n\t"
        "add $4, %esp"
    );
    return;
}

char *get_dec_lock_addr()
{
    return (char *)0x9B96BA0;
}

char *get_send_func_addr_var(char *a1, int a2, int a3)
{
    char *result; // eax@1
    char *v4; // ecx@1
    unsigned int v5; // esi@4
    char *v6; // [sp+0h] [bp-Ch]@5

    result = 0;
    v4 = (char *)158783784;
    if ( *v4 )
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
        while ( v4 != (char *)158783784 && v4 != 0 );
        result = 0;
    }
    return result;
}

#endif // ASA_VER
