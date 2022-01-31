import argparse
import scapy.all as scapy

parser = argparse.ArgumentParser()
parser.add_argument("--interface")
parser.add_argument("--victim-ip")
parser.add_argument("--victim-ethernet")
parser.add_argument("--reflector-ip")
parser.add_argument("--reflector-ethernet")
args = parser.parse_args()

interface = args.interface
victim_ip = args.victim_ip
victim_eth = args.victim_ethernet
reflector_ip = args.reflector_ip
reflector_eth = args.reflector_ethernet

print("\n**********GIVEN************")
print(f"Interface\t{interface}")
print(f"Victim\t\tIP: {victim_ip}\t\tETH: {victim_eth}")
print(f"Reflector\tIP: {reflector_ip}\t\tETH: {reflector_eth}")

iface_ip = scapy.get_if_addr(interface)
iface_mac = scapy.getmacbyip(iface_ip)
print("\n**********SYSTEM************")
print(f"Interface details:\tMAC: {iface_mac}\tIP: {iface_ip}\n")

# ARP RESPONSES
WHO_HAS = 1
IS_AT = 2
BROADCAST = 'ff:ff:ff:ff:ff:ff'


ip_mac_map = {
    victim_ip: victim_eth,
    reflector_ip: reflector_eth
}


def reply_arp(packet, psrc):
    arp = scapy.ARP(psrc=psrc, pdst=packet[scapy.ARP].psrc, op=IS_AT, hwsrc=ip_mac_map[psrc], hwdst=BROADCAST)
    scapy.send(arp)


def refactor_checksum(packet):
    # remove checksums TODO: rebuild?
    del packet[scapy.IP].chksum
    if scapy.TCP in packet:
        del packet[scapy.TCP].chksum
    if scapy.UDP in packet:
        del packet[scapy.UDP].chksum


def build_ip_packet(packet, dst_ip):
    ip = packet.getlayer(scapy.IP)
    ip[scapy.IP].dst = packet[scapy.IP].src
    ip[scapy.IP].src = reflector_ip if dst_ip == victim_ip else victim_ip  # invert the source
    refactor_checksum(ip)
    return ip


def reply_ip(packet):
    if packet[scapy.IP].dst == victim_ip:
        packet = build_ip_packet(packet, victim_ip)
        scapy.send(packet)

    elif packet[scapy.IP].dst == reflector_ip:
        packet = build_ip_packet(packet, reflector_ip)
        scapy.send(packet)


def packet_handler(packet):
    if scapy.ARP in packet and packet[scapy.ARP].pdst in [victim_ip, reflector_ip]:
        reply_arp(packet, psrc=packet[scapy.ARP].pdst)
    elif scapy.IP in packet:
        reply_ip(packet)


def go_spoof():
    scapy.sniff(iface=interface, prn=packet_handler, store=0, count=0)


if __name__ == "__main__":
    go_spoof()

