#ifndef ASA_FUNC_H_INCLUDED
#define ASA_FUNC_H_INCLUDED

#define ASA_VER 804


typedef struct struc_ip_info
{
    unsigned int shost;
    unsigned int dhost;
    char flags;
    char proto_type;
    unsigned short payload_len;
} ASA_IP_INFO;

#if ASA_VER == 804 || ASA_VER ==805
typedef struct struc_send_pkt
{
    char undef_str_1[30];
    char src_mac[6];
    char dst_mac[6];
    char eth_type[2];
    char reserved[4];
    char *p_ip_packet;
    //52 bytes
    char *p_Buff;          //最初指向ASA_IP_INFO
    char *p_eth_packet;
    //60 bytes
    ASA_IP_INFO *p_ip_info;  //指向偏移320 bytes的地址
    //64 bytes
    /*
    char undef_str_4[738];
    //802 bytes
    char eth_header[14];
    char vlan_tag[4];
    char ip_header[20];
    char udp_header[8];
    */
} ASA_SEND_PKT;
#endif // ASA_VER

/////////////////////////////////////////////////////////////////////////////////////////
void *asa_malloc(int size);
void asa_free(void *pBuff);
int asa_memcopy(void *destAddr, void *srcAddr, int length);
char *asa_alloc_send_pkt(unsigned int len);
void asa_free_send_pkt(ASA_SEND_PKT **pBuff);
int asa_find_router_table(unsigned int ip, char *pRouterTable);
char *asa_find_mac_with_ip(unsigned int destIP, char *pRouterTable, unsigned int nextIP, char *v6);
int asa_add_ip_packet(ASA_SEND_PKT *pSendPkt);
int asa_add_router_mac(ASA_SEND_PKT *pSendPkt, char *pMac, unsigned short proto);
int asa_send(char *a1, ASA_SEND_PKT *pSendPkt);
int asa_get_en_auth_addr();
int asa_get_login_auth_addr();
int asa_printf(char *str);
int get_can_send_val(char *recv_packet, char *pkt_info);
int asa_dec_lock(int a1);
char *asa_about_thread_vcid(int a1);
char *get_dec_lock_addr();
char *get_send_func_addr_var(char *a1, int a2, int a3);
int main(char *recv_packet, char *pkt_info);

#endif // ASA_FUNC_H_INCLUDED
