from colored import fg, bg, attr
import colored
import  sys 
import time
def write(strings):

    for c in strings + '\n':
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(0.40 / 100)

def main ():
    
    angry = colored.fg("white") + colored.attr("bold")
    angry1 = colored.fg("green") + colored.attr("bold")
    
    
    print("""%s%s
    
_____________
||         ||            _______
||0x Matrix||           | _____ |
||  Evil   ||           ||_____||
||___Net___||           |  ___  |
|  + + + +  |           | |___| |
    _|_|_   \           |       |
   (_____)   \          |       |
              \    ___  |       |
       ______  \__/   \_|       |
      |   _  |      _/  |       |
      |  ( ) |     /    |_______|
      |___|__|    /         KSA
           \_____/
%s
"""%(fg('red'), attr('bold'), attr('reset')))
    write(f"""
    {colored.attr("bold")}
    \rAuthor\t\t: Matrix (https://github.com/Matrix07ksa/)
    \rCodeName\t: Hejap Zairy 
    \rVersion\t\t: 1.0V
    \rTeam\t\t: %s0xSaudi\n"""%(angry1))
    print("""%s
    \r\r1 - Scanning Network 
    \r\r2 - Wifi Attack 
    \r\r3 - Arp Attack 
    \r\r4 - Brute Force PN
    \r\r5 - Vlan Hoping Attack
    \r\r6 - Mac Flooding
  %s  \r\r0 - exit
%s
    """%(angry,fg("green"),attr('reset')))

    global Number
    Number = str(input("%s[?]>>"%(colored.attr("bold"))))
