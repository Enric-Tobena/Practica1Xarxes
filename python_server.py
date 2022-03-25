#!/usr/bin/env python3

import socket, select
import sys
from datetime import datetime

debug = False


class server_config:
    def __init__(self, id_serv, udp_port, tcp_port):
        self.id_serv = id_serv
        self.udp_port = udp_port
        self.tcp_port = tcp_port


def parse_args():
    global debug

    if len(sys.argv) == 1 or len(sys.argv) == 2 and sys.argv[1] == "-d":
        if len(sys.argv) == 2:
            debug = True
        print("Executar servidor normal")
        server = setup_server("server.cfg")
        print_server(server)
        debug_message("INF. -> Debugger activat per paràmetre '-d'")
    elif len(sys.argv) == 3 and sys.argv[1] == "-c":
        datafile_name = sys.argv[2]
        server = setup_server(datafile_name)
        print_server(server)
    elif len(sys.argv) == 2 and sys.argv[1] == "-d":
        debug_message("INF. -> Debugger activat per paràmetre '-d'")
        debug = True
    else:
        print("Ús incorrecte dels paràmetres d'entrada")
        exit(-1)


def debug_message(message):
    if debug:
        actual_time = datetime.now()
        str_time = actual_time.strftime("%b %d, %Y at %H:%M:%S ||")

        print(str_time, message)


def setup_server(server_cfg):
    try:
        with open(server_cfg) as server_file:
            id_serv = server_file.readline().split("= ")[1].replace('\n', '')
            udp_port = server_file.readline().split("= ")[1].replace('\n', '')
            tcp_port = server_file.readline().split("= ")[1].replace('\n', '')

            return server_config(id_serv, udp_port, tcp_port)

    except FileNotFoundError:
        print("ERR. -> El fitxer no existeix o no s'ha pogut obrir correctament")
        exit(-1)


def print_server(server):
    print("/* SERVER PARAMS */")
    print("Id:", server.id_serv)
    print("UDP_port:", server.udp_port)
    print("TCP_port:", server.tcp_port)


if __name__ == '__main__':
    parse_args()
