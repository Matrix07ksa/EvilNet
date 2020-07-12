import nmap3 
from colored import fg, bg, attr
import colored
import socket as sock
from  Modules import intro

class nmap3_Scan() :
    def __init__(self):
        self.angry1 = colored.fg("green") + colored.attr("bold")
        self.angry = colored.fg("white") + colored.attr("bold")
        print(f"""{self.angry1}
        1 - Os 
        2 - Top PORT
        3-  Xmas Scan
        4 - Fin Scan 
        5 - Dns brute 
        6 - UDP Scan
        7 - TCP Scan 
        99 - back   
        """)
        
        self.number = str(input("[?]>>"))
        if self.number == str(1) or "use os" in self.number : 
             self.Host = str(input("%s[*] Host >>"%(self.angry1)))
             self.Timing = int(input("[*] Timing >>"))
             self.OS(self.Host,self.Timing)
        if self.number == str(2) or "use top port" in self.number  :
             self.Host = str(input("%s[*] Host >>"%(self.angry1)))
             self.Timing = int(input("[*] Timing >>"))
             if self.Timing == None:    
                 self.Top_port(self.Host)
             else:
                 self.Top_port(self.Host,self.Timing)
        if self.number == str(3) or "use xmas" in self.number :
             self.Host = str(input("%s[*] Host >>"%(self.angry1)))
             self.Timing = int(input("[*] Timing >>"))
             if self.Timing == None:    
                 self.Xmas_Scan(self.Host)
             else:
                 self.Xmas_Scan(self.Host,self.Timing)
        if self.number == str(4) or "use fin" in self.number :
             self.Host = str(input("%s[*] Host >>"%(self.angry1)))
             self.Timing = int(input("[*] Timing >>"))
             if self.Timing == None:    
                 self.Fin_Scan(self.Host)
             else:
                 self.Fin_Scan(self.Host,self.Timing)

        if self.number == str(5) or "use brute dns" in self.number :
             self.Host = str(input("%s[*] Domain >>"%(self.angry1)))
             self.Dns_Brute(self.Host)
        if self.number == str(6) or "use udp" in self.number :
             self.Host = str(input("%s[*] Host >>"%(self.angry1)))
             self.Timing = int(input("[*] Timing >>"))
             if self.Timing == None:    
                 self.UDP_Scan(self.Host)
             else:
                 self.UDP_Scan(self.Host,self.Timing)
        if self.number == str(7) or "use tcp" in self.number :
             self.Host = str(input("%s[*] Host >>"%(self.angry1)))
             self.Timing = int(input("[*] Timing >>"))
             if self.Timing == None:    
                 self.TCP_Scan(self.Host)
             else:
                 self.TCP_Scan(self.Host,self.Timing)

        if self.number == str(99) or   "back" in self.number :
             intro.main()
        
        
    def OS(self,Host,Timing=4):
        self.Host = Host 
        self.Timing = Timing
        try : 
            print("Loading ........................................")
            HOST_lib = nmap3.Nmap() 
            System=HOST_lib.nmap_os_detection(str(self.Host),args=f"-T{self.Timing} -vv")
            for i in System:
                print(f"System:{i['name']} CPE : {i['cpe']} ")
        except :
            pass
    def Top_port (self,Host,Timing=4):
        print("Loading ........................................")

        self.Host = sock.gethostbyname(self.Host)
        HOST_lib = nmap3.Nmap() 
        System = HOST_lib.scan_top_ports(self.Host,self.Timing)
        for z in System[self.Host]:
            print(z['portid'],z['service']['name'],z['state'])

    def Dns_Brute(self,Host,Timing=4):
        print("Loading ........................................")

        HOST_lib  = nmap3.NmapHostDiscovery()
        System = HOST_lib.nmap_dns_brute_script(self.Host)
        for output in System:
            print(" "+output['address']," "+output['hostname']+self.angry) 
    def Xmas_Scan (self,Host,Timing=4):
        print("Loading ........................................")
        self.Host = sock.gethostbyname(self.Host)
        HOST_lib = nmap3.NmapHostDiscovery()
        System=HOST_lib.nmap_portscan_only(str(self.Host),args=f" -sX -T{self.Timing} -vv")
        for z in System[self.Host]:
            print(z['portid'],z['service']['name'],z['state']+self.angry)
    def Fin_Scan(self,Host,Timing=4):
        print("Loading ........................................")
        self.Host = sock.gethostbyname(self.Host)
        HOST_lib = nmap3.NmapHostDiscovery()
        System=HOST_lib.nmap_portscan_only(str(self.Host),args=f" -sF -T{self.Timing} -vv")
        for z in System[self.Host]:
            print(z['portid'],z['service']['name'],z['state']+self.angry)
    def UDP_Scan(self,Host,Timing=4):


        print("Loading ........................................")
        self.Host = sock.gethostbyname(self.Host)
        HOST_lib = nmap3.NmapScanTechniques()
        System=HOST_lib.nmap_udp_scan(str(self.Host),args=f"-T{self.Timing} -vv")
        for z in System[self.Host]:
            print(z['portid'],z['service']['name'],z['state']+self.angry)
    def TCP_Scan(self,Host,Timing=4):
          
        print("Loading ........................................")
        self.Host = sock.gethostbyname(self.Host)
        HOST_lib = nmap3.NmapScanTechniques()
        System=HOST_lib.nmap_tcp_scan(str(self.Host),args=f"-T{self.Timing} -vv")
        for z in System[self.Host]:
            print(z['portid'],z['service']['name'],z['state']+self.angry)
      
