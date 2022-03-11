#!/usr/bin/env python3

import socket, select
import sys
from datetime import datetime


class server_config:
    def __init__(self, id_serv, udp_port, tcp_port):
        self.id_serv = id_serv
        self.udp_port = udp_port
        self.tcp_port = tcp_port


"""
def set_up_socket():
    global TCP_socket
    TCP_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    TCP_socket.bind(("SRV001P122", 2202))
    TCP_socket.listen(5)


def server_loop():
    try:
        while True:
            connection_socket, client_address = TCP_socket.accept()
            received_data = connection_socket.recv(0000)  # Port del client
            while True:
                if not received_data:
                    break
                else:
                    connection_socket.send(received_data)
            connection_socket.close()
    finally:
        TCP_socket.close()

def run_server():
    set_up_socket()
    server_loop()
"""


def debug_message(message):
    actual_time = datetime.now()
    str_time = actual_time.strftime("%b %d, %Y at %H:%M:%S ||")

    print(str_time, message)


def setup_server(server_cfg):
    try:
        with open(server_cfg) as server_file:
            id_serv = server_file.readline().split("= ")[1]
            udp_port = server_file.readline().split("= ")[1]
            tcp_port = server_file.readline().split("= ")[1]

            return server_config(id_serv, udp_port, tcp_port)

    except FileNotFoundError:
        print("ERR. -> El fitxer no existeix o no s'ha pogut obrir correctament")
        exit(-1)


if __name__ == '__main__':
    if len(sys.argv) == 1:
        print("Executar servidor normal")
    elif len(sys.argv) == 3 and sys.argv[1] == "-c":
        datafile_name = sys.argv[2]
        server = setup_server(datafile_name)
        print("Id: ", server.id_serv, "UDP_port: ", server.udp_port, "TCP_port: ", server.tcp_port)
    elif len(sys.argv) == 2 and sys.argv[1] == "-d":
        debug_message("INF. -> Debugger activat per paràmetre '-d'")
    else:
        print("Ús incorrecte dels paràmetres d'entrada")
        exit(-1)
