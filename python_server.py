#!/usr/bin/env python3

import socket, select
import sys
from datetime import datetime

debug = False
clients_id_list = []
connected_clients_list = []


class server_config:
    def __init__(self, id_serv, udp_port, tcp_port):
        self.id_serv = id_serv
        self.udp_port = udp_port
        self.tcp_port = tcp_port

class connected_client:
    def __init__(self, id_client, id_communication, ip_address):
        self.id_client = id_client
        self.id_communication = id_communication
        self.ip_address = ip_address

def parse_args():
    global debug, server_data
    global clients_id_list
    print(len(sys.argv))
    if len(sys.argv) <= 2:
        if len(sys.argv) == 2:
            if sys.argv[1] != "-d":
                print("Ús incorrecte dels paràmetres d'entrada")
                exit(-1)
            else:
                debug = True
        server_data = setup_server("server.cfg")
        authorized_clients("bbdd_dev.dat")
    elif len(sys.argv) == 3:
            if sys.argv[1] != "-c" and sys.argv[1] != "-u":
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
            if sys.argv[2] != "-c" and sys.argv[2] != "-u":
                print("Ús incorrecte dels paràmetres d'entrada")
                exit(-1)
            if sys.argv[2] == "-c":
                server_data = setup_server(sys.argv[3])
                authorized_clients("bbdd_dev.dat")
            if sys.argv[2] == "-u":
                server_data = setup_server("server.cfg")
                authorized_clients(sys.argv[3])
        elif sys.argv[3] == "-d":
            if sys.argv[1] != "-c" and sys.argv[1] != "-u":
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
            if sys.argv[1] != "-c" and sys.argv[1] != "-u":
                print("Ús incorrecte dels paràmetres d'entrada")
                exit(-1)
            if sys.argv[3] != "-c" and sys.argv[3] != "-u":
                print("Ús incorrecte dels paràmetres d'entrada")
                exit(-1)

            if sys.argv[1] == "-c":
                if sys.argv[3] != "-u":
                    print("Ús incorrecte dels paràmetres d'entrada")
                    exit(-1)
                else:
                    server_data = setup_server(sys.argv[2])
                    authorized_clients(sys.argv[4])
            if sys.argv[1] == "-u":
                if sys.argv[3] != "-c":
                    print("Ús incorrecte dels paràmetres d'entrada")
                    exit(-1)
                else:
                    server_data = setup_server(sys.argv[4])
                    authorized_clients(sys.argv[2])
    elif len(sys.argv) == 6:
        correct_debug = False
        i = 1
        while i < len(sys.argv):
            if sys.argv[i] == "-d":
                correct_debug = True
                debug = True
                break
            i += 2
        if not correct_debug:
            print("Ús incorrecte dels paràmetres d'entrada")
            exit(-1)

        if i == 1:
            if sys.argv[2] == "-c" and sys.argv[4] == "-u":
                server_data = setup_server(sys.argv[3])
                authorized_clients(sys.argv[5])
            elif sys.argv[2] == "-u" and sys.argv[4] == "-c":
                server_data = setup_server(sys.argv[5])
                authorized_clients(sys.argv[3])
            else:
                print("Ús incorrecte dels paràmetres d'entrada")
                exit(-1)
        elif i == 3:
            if sys.argv[1] == "-c" and sys.argv[4] == "-u":
                server_data = setup_server(sys.argv[2])
                authorized_clients(sys.argv[5])
            elif sys.argv[1] == "-u" and sys.argv[4] == "-c":
                server_data = setup_server(sys.argv[5])
                authorized_clients(sys.argv[2])
            else:
                print("Ús incorrecte dels paràmetres d'entrada")
                exit(-1)
        elif i == 5:
            if sys.argv[1] == "-c" and sys.argv[3] == "-u":
                server_data = setup_server(sys.argv[2])
                authorized_clients(sys.argv[4])
            elif sys.argv[1] == "-u" and sys.argv[3] == "-c":
                server_data = setup_server(sys.argv[4])
                authorized_clients(sys.argv[2])
            else:
                print("Ús incorrecte dels paràmetres d'entrada")
                exit(-1)
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
            client_id = clientid_file.readline().replace("\n", "")
            while len(client_id) > 0:
                clients_id_list.append(client_id)
                client_id = clientid_file.readline().replace("\n", "")

    except FileNotFoundError:
        print("ERR. -> El fitxer no existeix o no s'ha pogut obrir correctament")
        exit(-1)

def setup_sockets():
    global tcp_socket_fd, udp_socket_fd
    tcp_socket_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    udp_socket_fd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    debug_message("Sockets TCP i UDP inicialitzats correctament")

def print_server():
    print("/* SERVER PARAMS */")
    print("Id:", server_data.id_serv)
    print("UDP_port:", server_data.udp_port)
    print("TCP_port:", server_data.tcp_port)

def print_authorized_clients():
    print("/* AUTHORIZED CLIENTS */")
    for client in clients_id_list:
        print(client)

if __name__ == '__main__':
    global server_data
    global tcp_socket_fd, udp_socket_fd
    parse_args()

    print_server()
    print_authorized_clients()
    debug_message("Debugger activat")
    setup_sockets()

