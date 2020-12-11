import netfilterqueue
import scapy.all as scapy

def process_packet(packet):
    scapy_packet =

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()