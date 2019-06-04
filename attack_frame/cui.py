# -*- coding:utf-8 -*-
#!/usr/bin/python

class CUI(object):
    def __init__(self):
        super(CUI, self).__init__()

    @staticmethod
    def show_main_interface():
        print \
'''
Exploit
===================

  1. SNMP Exploit
  2. IKE Exploit

Shellcode
===================

  3. Output Shellcode Ver 1.1

Backdoor
===================

  4. Backdoor Implant Ver 1.1
  
Touch
===================

  5. SNMP touch
  6. IKE touch

Controller 
===================

  7. AC
  
Others
===================

  C. Global Config
  H. Display Menu
  Q. Exit
'''

    @staticmethod
    def show_support_vers():
        print \
'''
Support Version
===================

  1.  Ver 802
  2.  Ver 804
  3.  Ver 805
  4.  Ver 821
  5.  Ver 822
  6.  Ver 824
  7.  Ver 824
  8.  Ver 825
  9.  Ver 831
  10. Ver 832
  11. Ver 841
  12. Ver 842
  13. Ver 845
  
  Q.Back
'''