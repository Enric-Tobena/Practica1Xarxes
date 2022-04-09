#!/usr/bin/env python3

import socket, select
import sys
from datetime import datetime

debug = False
check_client = []


class server_config:
    def __init__(self, id_serv, udp_port, tcp_port):
        self.id_serv = id_serv
        self.udp_port = udp_port
        self.tcp_port = tcp_port


def parse_args():
    global debug
    global check_client

    if len(sys.argv) <= 2:
        if len(sys.argv) == 2:
            if sys.argv[1] is not "-d":
                print("Ús incorrecte dels paràmetres d'entrada")
                exit(-1)
            else:
                debug = True
        server_data = setup_server("server.cfg")
        authorized_clients("bbdd_dev.dat")
    elif len(sys.argv) == 3:
            if sys.argv[1] is not "-c" or "-u":
                print("Ús incorrecte dels paràmetres d'entrada")
                exit(-1)
            if sys.argv[1] == "-c":
                server_data = setup_server(sys.argv[2])
                authorized_clients("bbdd_dev.dat")
            if sys.argv[1] == "-u":
                server_data = setup_server("server.cfg")
                authorized_clients(sys.argv[2])
    elif len(sys.argv) == 4:
        debug = True
        if sys.argv[1] == "-d":
            if sys.argv[2] is not "-c" or "-u":
                print("Ús incorrecte dels paràmetres d'entrada")
                exit(-1)
            if sys.argv[2] == "-c":
                server_data = setup_server(sys.argv[3])
                authorized_clients("bbdd_dev.dat")
            if sys.argv[2] == "-u":
                server_data = setup_server("server.cfg")
                authorized_clients(sys.argv[3])
        elif sys.argv[3] == "-d":
            if sys.argv[1] is not "-c" or "-u":
                print("Ús incorrecte dels paràmetres d'entrada")
                exit(-1)
            if sys.argv[1] == "-c":
                server_data = setup_server(sys.argv[2])
                authorized_clients("bbdd_dev.dat")
            if sys.argv[1] == "-u":
                server_data = setup_server("server.cfg")
                authorized_clients(sys.argv[2])
        else:
            print("Ús incorrecte dels paràmetres d'entrada")
            exit(-1)
    elif len(sys.argv) == 5:

    elif len(sys.argv) == 6:

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

def authorized_clients(bbdd_dev):
    try:
        with open(bbdd_dev) as clientid_file:
            client_id = clientid_file.readline().split("\n ").replace('\n', '')
            while client_id is not "":
                check_client.append(client_id)
                client_id = clientid_file.readline().split("\n ").replace('\n', '')

    except FileNotFoundError:
        print("ERR. -> El fitxer no existeix o no s'ha pogut obrir correctament")
        exit(-1)


def print_server(server_data):
    print("/* SERVER PARAMS */")
    print("Id:", server_data.id_serv)
    print("UDP_port:", server_data.udp_port)
    print("TCP_port:", server_data.tcp_port)


if __name__ == '__main__':
    parse_args()
