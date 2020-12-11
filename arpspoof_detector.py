import scapy.all as scapy
import argparse

def get_interface():
    parse = argparse.ArgumentParser()
    parse.add_argument("-i", "--interface", dest="interface", help="Enter interface")
    options = parse.parse_args()
    return options

def get_mac_address(target_ip):
    arp_request = scapy.ARP(pdst=target_ip)
    make_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = make_broadcast / arp_request
    requests_answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return requests_answered[0][1].hwsrc

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            actual_mac_address = get_mac_address(packet[scapy.ARP].psrc)
            response_mac_address = packet[scapy.ARP].hwsrc
            if actual_mac_address != response_mac_address:
                print("You are experiencing an ARP Spoofing Attack... Check your network connection!")
        except IndexError:
            pass

options = get_interface()
sniff(options.interface)