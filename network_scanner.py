import scapy.all as scapy
import argparse

def get_args():
    parse = argparse.ArgumentParser()
    parse.add_argument("-i", "--ipaddress", dest="ipaddress", help="Enter IP Address or IP Address range" )
    options = parse.parse_args()
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    make_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = make_broadcast/arp_request
    requests_answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    connected_devices = []
    for entry in requests_answered:
        devices_dict = {"ip": entry[1].psrc, "mac": entry[1].hwsrc}
        connected_devices.append(devices_dict)
    return connected_devices

def print_results(connected_devices):
    print("IP Address\t\t\tMAC Address")
    print("------------------------------------------------------------")
    for devices in connected_devices:
        print(devices["ip"] + "\t\t\t" + devices["mac"])

options = get_args()
results = scan(options.ipaddress)
print_results(results)