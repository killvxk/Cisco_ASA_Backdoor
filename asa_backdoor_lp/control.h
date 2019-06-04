#ifndef CONTROL_H_INCLUDED
#define CONTROL_H_INCLUDED

#include "commun.h"

typedef struct
{
    char dest_ip[20];
    unsigned short dest_port;
    SOCKET soc;
    struct sockaddr_in dest_addr;
} HOST_ADDR;

/////////////////////////////////////////////////////////////////////////////
int fetch_backdoor_status();
int free_memory();
int fetch_backdoor_status();
int set_redirect_flow();
int write_to_memory();
int read_from_memory();
int enable_auth();
int disable_auth();
void clean_stdin();

#endif // CONTROL_H_INCLUDED
