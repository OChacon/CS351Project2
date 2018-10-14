import binascii
import sys
import socket
import select
import math


H_1 = "736F"
H_2 = "0100"
H_3 = "0001"
H_4 = "0000"
H_5 = "0000"
H_6 = "0000"
Q_TYPE = "0001"
Q_CLASS = "0001"
Z_BYTE = "00"

TIME_OUT_SEC = 5


def send_query():
    args = sys.argv

    if len(args) != 3:
        usage()
        exit(0)

    server = args[1]
    port = 53
    name = args[2]

    if ":" in server:
        server_port = server.split(":")
        server = str(server_port[0])
        port = int(server_port[1])

    if "." not in name or len(server.split(".")) != 4:
        usage()
        exit(0)

    name_list = name.split(".")
    name_bin = ""

    for n in name_list:
        name_bin = name_bin + int_to_hex(len(n)) + str_to_hex(n)

    name_bin = name_bin + Z_BYTE

    header = (H_1 + H_2 + H_3 + H_4 + H_5 + H_6)
    question = name_bin + Q_TYPE + Q_CLASS
    msg = binascii.unhexlify((header + question).replace("\n", ""))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(0)
    timed_out = False
    erred_out = False
    is_query_response = False
    resp = []

    try:
        dump_packet(msg)
        sock.sendto(msg, (server, port))

        while not timed_out and not is_query_response:
            ready = select.select([sock], [], [], TIME_OUT_SEC)

            if ready[0]:
                resp = sock.recvfrom(4096)
                is_query_response = is_dns_response(resp[0])

            if not resp:
                timed_out = True
    except socket.gaierror as e:
        print_err(e.strerror)
        timed_out = False
        erred_out = True
    finally:
        sock.close()

    if timed_out:
        print("NORESPONSE")
        exit(0)
    elif erred_out:
        exit(0)

    print_response(resp[0])


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


def hex_to_bin_list(h_str):
    bin_list = []
    bin_list_full = []

    for h in h_str:
        b = str(bin(int(h, 16)))[2:]

        while len(b) < 4:
            b = "0" + b

        bin_list.append(b)

    bin_list_len = len(bin_list)

    for i in range(0, bin_list_len, 2):
        b = bin_list[i]

        if (i + 1) < bin_list_len:
            b = b + bin_list[i + 1]
        else:
            b = "0000" + b

        bin_list_full.append(b)

    return bin_list_full


def is_dns_response(s):
    hex_list = str(s).split("\\x")

    if str_to_hex(hex_list[0][2:4]).lower() != H_1.lower():
        return False
    elif str(hex_to_bin_list(hex_list[1])[0])[0] != "1":
        return False
    else:
        return True


def dump_packet(p):
    s_list = []
    h_list = []
    p_list = str(p).split("\\x")
    s_id = p_list[0][2:4]
    p_list[0] = str_to_hex(s_id[0])
    p_list.insert(1, str_to_hex(s_id[1]))
    p_len = len(p_list)
    p_list[p_len - 1] = p_list[p_len - 1][0:2]

    for i in range(p_len):
        wrd = p_list[i]
        wrd_len = len(wrd)

        if wrd_len > 2:
            h_list.append(wrd[0:2])
            s_list.append(".")
            wrd_str = wrd[2:wrd_len]
            wrd_hex = str_to_hex(wrd_str)
            wrd_hex_len = len(wrd_hex)
            s_index = 0

            while wrd_hex_len > 0:
                wrd_hex_wrd = wrd_hex[0:2]
                wrd_hex = wrd_hex[2:wrd_hex_len]
                wrd_hex_len -= 2
                h_list.append(wrd_hex_wrd)
                s_list.append(wrd_str[s_index])
                s_index += 1
        else:
            h_list.append(wrd)

            if int(wrd, 16) == 0 or int(wrd, 16) == 1:
                s_list.append(".")
            else:
                s_list.append(chr(int(wrd, 16)))

    wrd_cnt = len(h_list)
    lines_cnt = int(math.floor(wrd_cnt / 16) + 1)

    for i in range(16 - (wrd_cnt % 16)):
        h_list.append("  ")
        s_list.append("  ")

    print("Packet dump:")

    for i in range(0, lines_cnt):
        print("[00" + str(i) + "0] ", end="")
        list_i_start = i * 16
        list_i_end = (i + 1) * 16

        for j in range(list_i_start, list_i_end):
            if j % 8 == 0:
                print("  ", end="")

            print(str(h_list[j]) + " ", end="")

        for j in range(list_i_start, list_i_end):
            if j % 8 == 0:
                print("  ", end="")

            print(str(s_list[j]) + " ", end="")

        print()
    print()


def print_response(r):
    hex_str = str(binascii.hexlify(r))[1:]
    hex_str_len = len(hex_str)

    head_bin_list = []

    for i in range(5, 25, 4):
        head_bin_list.append(hex_to_bin_list(hex_str[i:i + 4]))

    r_code = head_bin_list[0][1][4:]

    if r_code != "0000":
        print_err(int(r_code, 2))
        return

    ans_index = 25

    while ans_index < hex_str_len:
        url_part_len = int(hex_str[ans_index:ans_index + 2], 16)
        if url_part_len == 0:
            ans_index += 2
            break
        else:
            ans_index += 2 * (url_part_len + 1)

    if ans_index == 25:
        print_err("Could not find answer section")
        return

    class_index = ans_index + 4
    rd_index = ans_index + 28

    ans_type = int(hex_str[ans_index:ans_index + 4], 16)
    ans_class = int(hex_str[class_index:class_index + 4], 16)
    rd_length = int(hex_str[rd_index:rd_index + 4], 16)

    ip_1 = str(int(hex_str[rd_index + 4: rd_index + 6], 16))
    ip_2 = str(int(hex_str[rd_index + 6: rd_index + 8], 16))
    ip_3 = str(int(hex_str[rd_index + 8: rd_index + 10], 16))
    ip_4 = str(int(hex_str[rd_index + 10: rd_index + 12], 16))
    ip_full = ip_1 + "." + ip_2 + "." + ip_3 + "." + ip_4

    print("IP\t" + ip_full)


def print_err(e):
    print("ERROR\t" + e)


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
