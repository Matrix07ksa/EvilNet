#################
#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Code By hejap Zairy Matrix515
import socket
import os
import subprocess 
from Modules import intro
from Modules import Wifi_attack 
from Modules import arp_spoof
from Modules import scan
from Modules import Broto_force_protcol
from Modules import Mac_Flooding
from Modules import Vlan_hopping


if  os.getuid() != 0 :
        print("Please use Root") 
        exit()
if __name__ == "__main__":
    
    intro.main()
    _loop = 1 
    while _loop :
        try : 
            if intro.Number == str(1) or "show scan" in  intro.Number:
                
                scan.nmap3_Scan()
            elif intro.Number  == str(2) or "show wifi" in intro.Number:
                Wifi_attack.Wifi()
            elif intro.Number == str(3) or "show arp" in intro.Number:
                arp_spoof.main()
            elif intro.Number == str(4) or "show brute" in intro.Number :
                Broto_force_protcol.Brute_Force()
            elif intro.Number == str(5)  or "show vlan"  in intro.Number :
                    Vlan_hopping.Attack_Vlan()
            elif intro.Number == str(6)  or "show mac flood"  in intro.Number :
                    Mac_Flooding.Mac_Attack()
            elif intro.Number == str(0) or "exit" in intro.Number :
                _loop = 0
    
            else :
                intro.main();

        except : 
            _loop = 0
    
