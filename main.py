from scapy.all import sniff, get_if_list

INTERFACE = [
    iface for iface in get_if_list()
    if iface != "lo"
]

def packet_received(packet):
    print(packet.summary())

print(f"Monitoring {INTERFACE}...")

sniff(
    iface=INTERFACE,
    prn=packet_received,
    store=False
)
