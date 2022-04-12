#!/usr/bin/env python3

import sys, os, traceback, optparse, struct, random, re
import time
import socket, select
import threading
from datetime import datetime

udp_pack_format = "B11s11s61s"
tcp_pack_format = "B11s11s8s16s80s"

debug = False
clients_list = []


class server_config:
    def __init__(self, id_serv, udp_port, tcp_port):
        self.id_serv = id_serv
        self.udp_port = udp_port
        self.tcp_port = tcp_port

class client:
    def __init__(self, id_client):
        self.id_client = id_client
        self.id_communication = ""
        self.ip_address = "NONE"
        self.status = 'DISCONNECTED'
        self.tcp_and_elems = ""

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
            udp_port = int(server_file.readline().split("= ")[1].replace('\n', ''))
            tcp_port = int(server_file.readline().split("= ")[1].replace('\n', ''))

            return server_config(id_serv, udp_port, tcp_port)

    except FileNotFoundError:
        print("ERR. -> El fitxer no existeix o no s'ha pogut obrir correctament")
        exit(-1)

def authorized_clients(bbdd_dev):
    try:
        with open(bbdd_dev) as clientid_file:
            client_id = clientid_file.readline().replace("\n", "")
            while len(client_id) > 0:
                new_client = client(client_id)
                clients_list.append(new_client)
                client_id = clientid_file.readline().replace("\n", "")

    except FileNotFoundError:
        print("ERR. -> El fitxer no existeix o no s'ha pogut obrir correctament")
        exit(-1)

def setup_sockets():
    global tcp_socket_fd, udp_socket_fd
    tcp_socket_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    udp_socket_fd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    debug_message("Sockets TCP i UDP inicialitzats correctament")

def listen_to_connections():
    global tcp_thread, udp_thread
    #tcp_thread = threading.Thread(target=tcp_connection)
    udp_thread = threading.Thread(target=udp_connection)
    #tcp_thread.daemon = True
    #udp_thread.setDaemon(True)

    debug_message("INF. -> Connexions TCP i UDP inicialitzades correctament")
    #tcp_thread.start()
    udp_thread.start()

def udp_connection():
    global udp_socket_fd
    try:
        udp_socket_fd.bind(('localhost', server_data.udp_port))
    except socket.error as err_msg:
        print("Error al mètode bind del socket UDP:", err_msg)
        exit(-1)

    debug_message("INF. -> Port UDP obert a rebre paquets")
    while True:
        received, address = udp_socket_fd.recvfrom(struct.calcsize(udp_pack_format))
        pack_to_string = struct.unpack(udp_pack_format, received)

        received_pack = get_udp_params(pack_to_string)
        treat_received_udp(received_pack, address)

def send_udp_package(package_type, address, id_client):
    global tcp_thread, udp_thread
    if package_type == '0xa1':      #REG_REQ
        debug_message("INF. -> Dades del paquet REG_REQ correctes. Enviament de REG_ACK")

        id_com = generate_rand_int(10)
        change_idcom(id_client, id_com)
        new_udp_port = generate_rand_int(5)
                                                                                                                        #Canviar port
        pack_to_send = struct.pack(udp_pack_format, 0xa1, bytes(server_data.id_serv, 'utf-8'), bytes(id_com, 'utf-8'), bytes("2022", 'utf-8'))
        udp_socket_fd.sendto(pack_to_send, address)

        print("INF. -> El client", id_client, "passa a l'estat WAIT-INFO")

        print_authorized_clients()

    elif package_type == '0xa2':
        print("REG_NACK")
        pack_to_send = struct.pack(udp_pack_format)
    elif package_type == '0xa3':        #REG_REJ
        debug_message("INF. -> Dades del paquet REG_REQ incorrectes. Enviament de REG_REJ")
        pack_to_send = struct.pack(udp_pack_format, 0xa3, bytes(server_data.id_serv, 'utf-8'), bytes("0000000000", 'utf-8'), bytes("Dades incorrectes o client no autoritzat", 'utf-8'))
        udp_socket_fd.sendto(pack_to_send, address)
    elif package_type == '0xa5':        #INFO_ACK
        if get_status(id_client) == "WAIT_INFO":
            debug_message("INF. -> Dades del paquet REG_INFO correctes. Enviament de INFO_ACK")
        else:
            print("Estat del client", id_client, "incorrecte per rebre INFO_ACK")
            disconnect_client(id_client)
    elif package_type == '0xa6':        #INFO_NACK
        debug_message("INF. -> Dades del paquet REG_INFO incorrectes. Enviament de INFO_NACK")
        print("INF. -> El client", id_client, "passa a l'estat DISCONNECTED")
        pack_to_send = struct.pack(udp_pack_format, 0xa6, bytes(server_data.id_serv, 'utf-8'), bytes(get_idcom(id_client), 'utf-8'), bytes("Dades incorrectes", 'utf-8'))
        udp_socket_fd.sendto(pack_to_send, address)

        disconnect_client(id_client)
    elif package_type == '0xa7':
        print("INFO_REJ")
        pack_to_send = struct.pack(udp_pack_format)

def treat_received_udp(package, address):
    if package['package_type'] == '0xa0':       #REG_REQ
        msg = "INF. -> Rebut paquet REG_REQ del client amb id: " + package['id_transmitter'] + ". Es comprovaran les dades del dispositiu"
        debug_message(msg)
        if is_valid_udp(package, "0000000000", ""):
            change_status(package['id_transmitter'], "WAIT_INFO")
            change_address(package['id_transmitter'], address)
            send_udp_package('0xa1', address, package['id_transmitter'])
        else:
            send_udp_package('0xa3', address, package['id_transmitter'])
    elif package['package_type'] == '0xa4':     #REG_INFO
        msg = "INF. -> Rebut paquet REG_INFO del client amb id: " + package['id_transmitter'] + ". Es comprovaran les dades del dispositiu"
        debug_message(msg)
        if is_valid_udp(package, get_idcom(package['id_transmitter']), "Non_relevant_data_to_compare"):
            change_tcp_elems(package['id_transmitter'], package['data'])
            print_authorized_clients()
            send_udp_package('0xa5', get_address(package['id_transmitter']), package['id_transmitter'])
        else:
            send_udp_package('0xa6', get_address(package['id_transmitter']), package['id_transmitter'])
    elif package['package_type'] == '0xb0':     #ALIVE
            print("ALIVE")
    else:
        printf("Rebut paquet UNKNOWN, el client amb id:", package['id_transmitter'], "passa a l'estat DISCONNECTED")
        disconnect_client(package['id_transmitter'])

def is_valid_udp(package, id_communication, data):
    if package['package_type'] == 0xa0:
        return is_authorized(package['id_transmitter']) and package['id_communication'] == id_communication and package['data'] == data
    else:
        return is_authorized(package['id_transmitter']) and package['id_communication'] == id_communication

def is_authorized(new_clientid):
    for client in clients_list:
        if client.id_client == new_clientid:
            return True
    return False

def change_status(client_id, new_status):
    for client in clients_list:
        if client.id_client == client_id:
            client.status = new_status

def change_address(client_id, new_address):
    for client in clients_list:
        if client.id_client == client_id:
            client.ip_address = new_address

def change_idcom(client_id, new_idcom):
    for client in clients_list:
        if client.id_client == client_id:
            client.id_communication = new_idcom

def change_tcp_elems(client_id, tcp_elems):
    for client in clients_list:
        if client.id_client == client_id:
            client.tcp_and_elems = tcp_elems

def get_status(client_id):
    for client in clients_list:
        if client.id_client == client_id:
            return client.status

def get_address(client_id):
    for client in clients_list:
        if client.id_client == client_id:
            return client.ip_address

def get_idcom(client_id):
    for client in clients_list:
        if client.id_client == client_id:
            return client.id_communication

def get_udp_params(udp_params):         #se li passa un string que ve del struct.unpack
    prov_list = []
    ordered_data = {'package_type' : 0x00, 'id_transmitter' : "", 'id_communication' : "", 'data' : ""}

    for param in udp_params:
        prov_list.append(str(param))

    ordered_data['package_type'] = str(hex(int(prov_list[0])))
    ordered_data['id_transmitter'] = prov_list[1][2:12]
    ordered_data['id_communication'] = prov_list[2][2:12]

    if ordered_data['package_type'] != '0xa0':
        if ordered_data['package_type'] == '0xa4':
            ordered_data['data'] = prov_list[3].split("'")[1].split("\x00")[0]          #Faltara quadrar aixo dels elems

    return ordered_data

def generate_rand_int(n):
    if n != 5:
        result = str(random.randint(0, 9))
    else:
        result = str(random.randint(0, 5))

    for i in range(0, n - 1):
        result += str(random.randint(0, 9))
    return result

def disconnect_client(id_client):
    change_status(id_client, "DISCONNECTED")
    change_idcom(id_client, "")
    change_address(id_client, "NONE")
    change_tcp_elems(id_client, "")

def print_server():
    print("/* SERVER PARAMS */")
    print("Id:", server_data.id_serv)
    print("UDP_port:", server_data.udp_port)
    print("TCP_port:", server_data.tcp_port)

def print_authorized_clients():
    print("/* AUTHORIZED CLIENTS */")
    for client in clients_list:
        print("Id:", client.id_client, '\t', "Status:", client.status, '\t',"Id_com:", client.id_communication, '\t',"IP:", client.ip_address, '\t', "TCP&Elems:", client.tcp_and_elems)

def print_udp_package(package):
    print("/* UDP PACKAGE */")
    print(package['package_type'])
    print(package['id_transmitter'])
    print(package['id_communication'])
    print(package['data'])

if __name__ == '__main__':
    global server_data
    global tcp_socket_fd, udp_socket_fd
    parse_args()

    print_server()
    print_authorized_clients()
    setup_sockets()
    listen_to_connections()

