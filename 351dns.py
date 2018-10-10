import binascii
import sys
import socket


H_1 = "8888"
H_2 = "0100"
H_3 = "0001"
H_4 = "0000"
H_5 = "0000"
H_6 = "0000"
Q_TYPE = "0001"
Q_CLASS = "0001"
Z_BYTE = "00"


def send_query():
    args = sys.argv

    if len(args) != 3:
        usage()
        return

    server = str(args[1])
    port = int(53)
    name = args[2]

    if ":" in server:
        server_port = server.split(":")
        server = str(server_port[0])
        port = int(server_port[1])

    name_list = name.split(".")
    name_bin = ""

    for n in name_list:
        name_bin = name_bin + int_to_hex(len(n)) + str_to_hex(n)

    name_bin = name_bin + Z_BYTE

    header = (H_1 + H_2 + H_3 + H_4 + H_5 + H_6)
    question = name_bin + Q_TYPE + Q_CLASS
    msg = binascii.unhexlify((header + question).replace("\n", ""))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.sendto(msg, (server, port))
        resp = sock.recvfrom(4096)
    finally:
        sock.close()

    print("Header and question hex: " + str(msg))
    print("Server response hex: " + str(resp[0]))


def int_to_hex(i):
    hex_i = hex(i).replace("0x", "")

    if len(hex_i) < 2:
        hex_i = "0" + hex_i

    return hex_i


def str_to_hex(s):
    hex_s = ""

    for c in s:
        h = hex(ord(c)).replace("0x", "")

        if len(h) < 2:
            hex_s = hex_s + "0" + h
        else:
            hex_s = hex_s + h

    return hex_s


def usage():
    """
    Displays usage information
    :return: None
    """
    print("Usage: ./351dns @<server:port> <name>")
    print("\tport (Optional) The UDP port number of the DNS server. Default value: 53.")
    print("\tserver (Required) The IP address of the DNS server, in a.b.c.d format.")
    print("\tname (Required) The name to query for.")


if __name__ == "__main__":
    send_query()
