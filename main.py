import socket
import struct
import time
from collections import defaultdict, deque
from datetime import datetime

from scapy.all import IP, TCP, ICMP, ARP


HOST = "127.0.0.1"
PORT = 9999

WINDOW = 5

SYN_LIMIT = 20
ICMP_LIMIT = 20
ARP_LIMIT = 5


syn_tracker = defaultdict(deque)
icmp_tracker = defaultdict(deque)
arp_tracker = defaultdict(deque)

blocked_ips = set()
blocked_macs = set()

total_packets = 0
blocked_packets = 0


def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    line = f"{timestamp} | {message}"

    print(line, flush=True)

    with open("firewall.log", "a", encoding="utf-8") as file:
        file.write(line + "\n")


def cleanup(tracker, source):
    now = time.time()

    while tracker[source]:

        if now - tracker[source][0] > WINDOW:
            tracker[source].popleft()

        else:
            break


def block_ip(ip, reason):

    if ip not in blocked_ips:

        blocked_ips.add(ip)

        log(
            f"[BLOCK-IP] {ip} | {reason}"
        )


def block_mac(mac, reason):

    if mac not in blocked_macs:

        blocked_macs.add(mac)

        log(
            f"[BLOCK-MAC] {mac} | {reason}"
        )


# -----------------------------
# LAYER 3 - SYN FLOOD
# -----------------------------

def detect_syn(packet):

    if not packet.haslayer(IP):
        return

    if not packet.haslayer(TCP):
        return

    tcp = packet[TCP]

    syn = bool(tcp.flags & 0x02)
    ack = bool(tcp.flags & 0x10)

    if syn and not ack:

        source_ip = packet[IP].src

        syn_tracker[source_ip].append(time.time())

        cleanup(
            syn_tracker,
            source_ip
        )

        count = len(
            syn_tracker[source_ip]
        )

        print(
            f"[SYN] {source_ip} -> "
            f"{packet[IP].dst} "
            f"count={count}",
            flush=True
        )

        if count > SYN_LIMIT:

            block_ip(
                source_ip,
                f"SYN flood: {count} packets/{WINDOW}s"
            )


# -----------------------------
# LAYER 3 - ICMP FLOOD
# -----------------------------

def detect_icmp(packet):

    if not packet.haslayer(IP):
        return

    if not packet.haslayer(ICMP):
        return

    source_ip = packet[IP].src

    icmp_tracker[source_ip].append(
        time.time()
    )

    cleanup(
        icmp_tracker,
        source_ip
    )

    count = len(
        icmp_tracker[source_ip]
    )

    print(
        f"[ICMP] {source_ip} -> "
        f"{packet[IP].dst} "
        f"count={count}",
        flush=True
    )

    if count > ICMP_LIMIT:

        block_ip(
            source_ip,
            f"ICMP flood: {count} packets/{WINDOW}s"
        )


# -----------------------------
# LAYER 2 - ARP FLOOD
# -----------------------------

def detect_arp(packet):

    if not packet.haslayer(ARP):
        return

    source_mac = packet[ARP].hwsrc

    arp_tracker[source_mac].append(
        time.time()
    )

    cleanup(
        arp_tracker,
        source_mac
    )

    count = len(
        arp_tracker[source_mac]
    )

    print(
        f"[ARP] {source_mac} "
        f"count={count}",
        flush=True
    )

    if count > ARP_LIMIT:

        block_mac(
            source_mac,
            f"ARP flood: {count} packets/{WINDOW}s"
        )


# -----------------------------
# PACKET INSPECTION
# -----------------------------

def inspect_packet(packet):

    global total_packets
    global blocked_packets

    total_packets += 1

    # Check existing IP block

    if packet.haslayer(IP):

        source_ip = packet[IP].src

        if source_ip in blocked_ips:

            blocked_packets += 1

            print(
                f"[DROP] IP {source_ip}",
                flush=True
            )

            return


    # Check existing MAC block

    if packet.haslayer(ARP):

        source_mac = packet[ARP].hwsrc

        if source_mac in blocked_macs:

            blocked_packets += 1

            print(
                f"[DROP] MAC {source_mac}",
                flush=True
            )

            return


    # Detection

    detect_syn(packet)

    detect_icmp(packet)

    detect_arp(packet)


# -----------------------------
# RECEIVE EXACT NUMBER OF BYTES
# -----------------------------

def recv_exact(connection, size):

    data = b""

    while len(data) < size:

        chunk = connection.recv(
            size - len(data)
        )

        if not chunk:
            return None

        data += chunk

    return data


# -----------------------------
# CLIENT HANDLER
# -----------------------------

def handle_client(connection):

    print(
        "[+] Attacker connected",
        flush=True
    )

    while True:

        header = recv_exact(
            connection,
            5
        )

        if header is None:
            break

        packet_type = header[0]

        packet_size = struct.unpack(
            "!I",
            header[1:5]
        )[0]

        raw_packet = recv_exact(
            connection,
            packet_size
        )

        if raw_packet is None:
            break


        # Reconstruct Scapy packet

        if packet_type == 1:

            packet = IP(raw_packet)

        elif packet_type == 2:

            packet = ARP(raw_packet)

        else:

            print(
                "[!] Unknown packet type",
                flush=True
            )

            continue


        print(
            f"\n[PACKET] {packet.summary()}",
            flush=True
        )

        inspect_packet(packet)


    connection.close()

    print(
        "[-] Attacker disconnected",
        flush=True
    )


# -----------------------------
# FIREWALL SERVER
# -----------------------------

def main():

    print("=" * 60)
    print("       SCAPY EDUCATIONAL FIREWALL LAB")
    print("=" * 60)

    print()

    print(
        f"Listening only on "
        f"{HOST}:{PORT}"
    )

    print()

    print("Detection:")

    print(
        f"  SYN  > {SYN_LIMIT}/{WINDOW}s"
    )

    print(
        f"  ICMP > {ICMP_LIMIT}/{WINDOW}s"
    )

    print(
        f"  ARP  > {ARP_LIMIT}/{WINDOW}s"
    )

    print()

    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    server.bind(
        (HOST, PORT)
    )

    server.listen(1)

    print(
        "[+] Firewall is running"
    )

    print(
        "[+] LAB ONLY"
    )

    print(
        "[+] Waiting for attacker..."
    )

    print()

    log("[START] Firewall Lab started")


    try:

        while True:

            connection, address = server.accept()

            handle_client(
                connection
            )


    except KeyboardInterrupt:

        print()

        print(
            "[!] Firewall stopped"
        )

        log(
            f"[STOP] packets={total_packets} "
            f"blocked={blocked_packets}"
        )


    finally:

        server.close()


if __name__ == "__main__":
    main()
