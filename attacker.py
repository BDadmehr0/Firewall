import socket
import struct
import time

from scapy.all import IP, TCP, ICMP, ARP


HOST = "127.0.0.1"
PORT = 9999


ATTACKER_IP = "10.10.10.50"
TARGET_IP = "10.10.10.100"

ATTACKER_MAC = "02:00:00:00:00:50"


def send_packet(connection, packet_type, packet):

    raw = bytes(packet)

    header = struct.pack(
        "!BI",
        packet_type,
        len(raw)
    )

    connection.sendall(
        header + raw
    )


# -----------------------------
# SYN LAB
# -----------------------------

def syn_test(connection):

    print()
    print("=" * 50)
    print("SYN FLOOD LAB")
    print("=" * 50)

    for i in range(30):

        packet = (
            IP(
                src=ATTACKER_IP,
                dst=TARGET_IP
            )
            /
            TCP(
                sport=10000 + i,
                dport=80,
                flags="S"
            )
        )

        send_packet(
            connection,
            1,
            packet
        )

        print(
            f"[ATTACKER] SYN #{i + 1}"
        )

        time.sleep(0.05)


# -----------------------------
# ICMP LAB
# -----------------------------

def icmp_test(connection):

    print()
    print("=" * 50)
    print("ICMP FLOOD LAB")
    print("=" * 50)

    for i in range(30):

        packet = (
            IP(
                src=ATTACKER_IP,
                dst=TARGET_IP
            )
            /
            ICMP()
        )

        send_packet(
            connection,
            1,
            packet
        )

        print(
            f"[ATTACKER] ICMP #{i + 1}"
        )

        time.sleep(0.05)


# -----------------------------
# ARP LAB
# -----------------------------

def arp_test(connection):

    print()
    print("=" * 50)
    print("ARP FLOOD LAB")
    print("=" * 50)

    for i in range(1000):

        packet = ARP(
            op=1,
            hwsrc=ATTACKER_MAC,
            psrc=ATTACKER_IP,
            pdst=TARGET_IP
        )

        send_packet(
            connection,
            2,
            packet
        )

        print(
            f"[ATTACKER] ARP #{i + 1}"
        )

        time.sleep(0.05)


# -----------------------------
# MAIN
# -----------------------------

def main():

    print("=" * 60)
    print("       SCAPY ATTACK LAB")
    print("=" * 60)

    print()
    print("Target:")
    print(
        f"{TARGET_IP}"
    )

    print()

    connection = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    connection.connect(
        (HOST, PORT)
    )

    print(
        "[+] Connected to firewall lab"
    )

    print()

    print(
        "1. SYN test"
    )

    print(
        "2. ICMP test"
    )

    print(
        "3. ARP test"
    )

    print(
        "4. Run all"
    )

    choice = input(
        "\nSelect: "
    )


    if choice == "1":

        syn_test(connection)


    elif choice == "2":

        icmp_test(connection)


    elif choice == "3":

        arp_test(connection)


    elif choice == "4":

        syn_test(connection)

        time.sleep(1)

        icmp_test(connection)

        time.sleep(1)

        arp_test(connection)


    else:

        print(
            "[!] Invalid choice"
        )


    connection.close()

    print()
    print(
        "[+] Lab finished"
    )


if __name__ == "__main__":
    main()