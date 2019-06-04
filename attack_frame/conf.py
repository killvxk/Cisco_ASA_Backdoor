# -*- coding:utf-8 -*-
#!/usr/bin/python

from cui import *

class GlobalConf(CUI):
    def __init__(self):
        super(GlobalConf, self).__init__()

        self.iface            = "eth0"
        self.targetIP         = ""
        self.targetPort       = None
        self.targetVer        = ""
        self.sCodeOutPath     = ""
        self.sCodeFilePath    = ""

    def input_target_addr_info(self, isInit=False):
        print ""
        self.iface = raw_input("[?] Interface[eth0]: ")
        if len(self.iface) < 1:
            self.iface = "eth0"
        self.targetIP = raw_input("[?] Target IP: ")
        if isInit is False:
            self.targetPort = int(raw_input("[?] Target Port: "))

        print ""
        print "[+] Set Interface    -> " + self.iface
        print "[+] Set Target IP    -> " + self.targetIP
        if isInit is False:
            print "[+] Set Target Port  -> " + str(self.targetPort)

        return

    def choose_target_ver(self):
        self.show_support_vers()

        choose = raw_input("[?] Target Version [%s]: " % self.targetVer)
        if choose == "1":
            self.targetVer = "802"
        elif choose == "2":
            self.targetVer = "804"
        elif choose == "3":
            self.targetVer = "805"
        elif choose == "4":
            self.targetVer = "821"
        elif choose.lower() == "q":
            return False
        return True

    def input_shellcode_output_path(self):
        path = raw_input("[?] Shellcode Output Path [%s]: " % self.sCodeOutPath)
        if len(path) > 0:
            self.sCodeOutPath = path
        return

    def input_shellcoe_file_path(self):
        path = raw_input("[?] Shellcode File Path [%s]: " % self.sCodeFilePath)
        if len(path) > 0:
            self.sCodeFilePath = path
        return

    def verify_exploit_param(self):
        print "\nConfirm Setting:"
        print "[*] Target IP       -> " + self.targetIP
        print "[*] Target Port     -> " + str(self.targetPort)
        print "[*] Target Version  -> " + self.targetVer
        print "[*] Shellcode File  -> " + self.sCodeFilePath
        print ""

        choose = raw_input("[?] Execute Exploit?[Y/N]: ")
        if choose.lower() == "y":
            return True
        else:
            return False

    def verify_implant_param(self):
        print "\nConfirm Setting:"
        print "[*] Target IP       -> " + self.targetIP
        print "[*] Target Port     -> " + str(self.targetPort)
        print "[*] Target Version  -> " + self.targetVer
        print ""

        choose = raw_input("[?] Execute Implant?[Y/N]: ")
        if choose.lower() == "y":
            return True
        else:
            return False

gl_Conf = GlobalConf()
