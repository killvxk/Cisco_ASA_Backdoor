#include <stdio.h>
#include <stdlib.h>

#include "global.h"
#include "redir_flow.h"

char *get_current_addr()
{
    __asm__(
        "movl 4(%ebp), %eax"
    );
    return;
}

int init_local_global_var(GLOBAL_VAR *pAddr)
{
    char msg[] = {'I', '\'', 'v', 'e', ' ', 'c', 'o', 'm', 'e', ' ', 'i', 'n', '.', '\n', NULL};
    ex_memset(pAddr, 0x00, sizeof(GLOBAL_VAR));

    asa_printf(msg);
    //debug_num(12345);

    return 0;
}

GLOBAL_VAR *get_local_global_var_addr()
{
    char *pCurrAddr = NULL;
    GLOBAL_VAR *pGlobalVarAddr = NULL;

    pCurrAddr = get_current_addr();
    pGlobalVarAddr = pCurrAddr + 1000000;

    if(pGlobalVarAddr->init_flag != 0x11229977)
    {
        //初始化全局变量
        init_local_global_var(pGlobalVarAddr);
        pGlobalVarAddr->init_flag = 0x11229977;
    }

    return pGlobalVarAddr;
}

char *ex_memset(char *pAddr, char ch, unsigned int len)
{
    int idx;

    for(idx=0; idx < len; idx++)
        pAddr[idx] = ch;

    return pAddr;
}

int ex_mprotect(char *pAddr, int size, int flags)
{
    __asm__(
            "movl $0x7D, %eax\n\t"
            "movl 8(%ebp), %ebx\n\t"   //addr
            "movl 12(%ebp), %ecx\n\t"  //len
            "movl 16(%ebp), %edx\n\t"  //flags
            "int $0x80"
            );
    return;
}

unsigned short conv_byte_order_short(unsigned short n)
{
    char swap = 0x00;

    swap = ((char *)&n)[0];
    ((char *)&n)[0] = ((char *)&n)[1];
    ((char *)&n)[1] = swap;

    return n;
}

char *ex_strcat(char *pDstAddr, char *pSrcAddr)
{
    int idx;

    for(idx=0; pSrcAddr[idx] != NULL; idx++)
        pDstAddr[idx] = pSrcAddr[idx];

    return pDstAddr;
}

char *ex_memcpy(char *pDstAddr, char *pSrcAddr, unsigned int len)
{
    int idx;

    for(idx=0; idx < len; idx++)
        pDstAddr[idx] = pSrcAddr[idx];

    return pDstAddr;
}

int ex_strcmp(char *mStr, char *pStr)
{
    int idx;

    for(idx=0; mStr[idx] != NULL && pStr[idx] != NULL; idx++)
        if(mStr[idx] != pStr[idx])
            break;

    if(mStr[idx] != NULL || pStr[idx] != NULL)
        return -1;

    return 0;
}

int ex_memcmp(char *p1, char *p2, unsigned int len)
{
    int idx;

    for(idx=0; idx < len; idx++)
        if(p1[idx] != p2[idx])
            return -1;

    return 0;
}

char *get_auth_key(char *pKey)
{
    char authKey[] = {'W', 'a', 'y', 'n', 'e', '_', '7', '4', '3', '7', 0x00};
    int idx;

    for(idx=0; authKey[idx] != 0x00; idx++)
        pKey[idx] = authKey[idx];
    pKey[idx] = 0x00;

    return pKey;
}

void *asa_realloc(void *pBuff, int oldSize, int newSize)
{
    char *pNewBuff = NULL;

    if(pBuff == NULL)
        return NULL;

    pNewBuff = asa_malloc(newSize);
    if(pNewBuff == NULL)
    {
        asa_free(pBuff);
        return NULL;
    }
    ex_memset(pNewBuff, 0x00, newSize);

    ex_memcpy(pNewBuff, pBuff, oldSize);
    asa_free(pBuff);

    return (void *)pNewBuff;
}

int debug_num(int val)
{
    char numStr[20];
    char swap;
    int len = 0;
    int idx = 0;
    int needSigned = 0;
    unsigned int rem = 0;

    ex_memset(numStr, 0x00, sizeof(numStr));

    if(val < 0)
    {
        needSigned = 1;
        val = 0 - val;
    }
    if(val == 0)
    {
        numStr[idx++] = '0';
    }

    for(; val != 0; val /= 10)
    {
        rem = val % 10;
        numStr[idx++] = rem + '0';
    }
    if(needSigned != 0)
    {
        numStr[idx++] = '-';
    }

    for(len = idx, idx = 0; idx < len/2; idx++)
    {
        swap = numStr[idx];
        numStr[idx] = numStr[len - idx - 1];
        numStr[len - idx - 1] = swap;
    }
    numStr[len] = '\n';
    asa_printf(numStr);

    return 0;
}
