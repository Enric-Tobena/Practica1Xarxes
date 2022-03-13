#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <stdbool.h>

/* Sockets */
#include <sys/types.h>
#include <sys/socket.h>

/* Strings i errors */
#include <string.h>
#include <errno.h>

/* Xarxes */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

/* AUXILIARS */
#define LONG_MESSAGE 128
#define LONG_DEBUGGER 256

/* FASE DE REGISTRE: Tipus de paquets */
#define REG_REQ 0xA0 
#define REG_ACK 0xA1 
#define REG_NACK 0xA2 
#define REG_REJ 0xA3 
#define REG_INFO 0xA4 
#define INFO_ACK 0xA5
#define INFO_NACK 0xA6
#define INFO_REJ 0xA7

/* ESTATS d'un client */
#define DISCONNECTED 0xF0
#define NOT_REGISTERED 0xF1
#define WAIT_ACK_REG 0xF2
#define WAIT_INFO 0xF3
#define WAIT_ACK_INFO 0xF4
#define REGISTERED 0xF5
#define SEND_ALIVE 0xF6

/* COMUNICACIÓ PERIÒDICA AMB EL SERVIDOR: Tipus de paquets */
#define ALIVE 0xB0
#define ALIVE_NACK 0xB1
#define ALIVE_REJ 0xB2

/* TRANSFERÈNCIA DE DADES AMB EL SERVIDOR: Tipus de paquets */
#define SEND_DATA 0xC0
#define DATA_ACK 0xC1
#define DATA_NACK 0xC2
#define DATA_REJ 0xC3
#define SET_DATA 0xC4
#define GET_DATA 0xC5

/* VARIABLES DE REGISTRE */
#define T 1
#define U 2
#define N 8
#define O 3
#define P 2
#define Q 4

struct TCPPackage {
    unsigned char package_type;
    char transmitter_id[11];
    char communication_id[11];
    char elem[8];
    char value[16];
    char info[80];
};

struct UDPPackage {
    unsigned char package_type;
    char transmitter_id[11];
    char communication_id[11];
    char data[61];
};

struct Client {
    char client_id[11];

    char elem_one[15];
    char elem_two[15];
    char elem_three[15];
    char elem_four[15];
    char elem_five[15];

    char server[15];
    int state;
};

struct TCPSocket {
    int tcp_socket_fd;
    int local_tcp;
    struct sockaddr_in tcp_socket_address;
};

struct UDPSocket {
    int udp_socket_fd;
    int server_udp;
    struct sockaddr_in udp_socket_address;
};

FILE *client_file;
bool active_debug = false;
struct Client client;
struct TCPSocket tcp_socket;
struct UDPSocket udp_socket;
struct UDPPackage server_data;

struct UDPPackage received_from_server;

/* FUNCIONS PRINCIPALS */
void parse_args(int argc, char *argv[]);
void setup_tcp_socket();
void setup_udp_socket();
void setup_client(char client_cfg[]);
void read_file();
void debug_message(char message[]);
void register_process();
void register_loop(struct UDPPackage reg_request);
int first_P_register_req(struct UDPPackage reg_request);
int second_register_req(struct UDPPackage reg_request);
void received_udp_package(struct UDPPackage received_pack);
void send_info_ack();

void build_client_struct();
struct UDPPackage build_udp_package(unsigned char, char[], char[], char[]);
struct TCPPackage build_tcp_package(unsigned char, char[], char[], char[], char[], char[]);

/* FUNCIONS AUXILIARS */
void print_client();
void print_tcp_package(struct TCPPackage package);
void print_udp_package(struct UDPPackage package);
size_t getline();
int package_timer(int send_time);


int main(int argc, char *argv[]) {
    if(argc == 3 || argc == 4) {
        parse_args(argc, argv);
    } else if (argc <= 2){
        if(argc == 2) {
            if(strcmp(argv[1], "-d") == 0) {
                active_debug = true;
            } else {
                printf("ERR. -> Ús incorrecte dels paràmetres d'entrada \n");
                exit(-1);
            }
        }
        setup_client("client.cfg");
    } else {
        printf("ERR. -> Ús incorrecte dels paràmetres d'entrada \n");
        exit(-1);
    }

    setup_tcp_socket();
    setup_udp_socket();
    register_process();
}

void parse_args(int argc, char *argv[]) {
    char *file_name;
    if(argc == 3) {
        if(strcmp(argv[1], "-c") == 0) {
            file_name = argv[2];
            setup_client(file_name);
        } else {
            printf("ERR. -> Ús incorrecte dels paràmetres d'entrada \n");
            exit(-1);
        }
    } else {
        if(strcmp(argv[1], "-c") == 0) {
            file_name = argv[2];
            if(strcmp(argv[3], "-d") == 0) {
                active_debug = true;
                setup_client(file_name);
            } else {
                printf("ERR. -> Ús incorrecte dels paràmetres d'entrada \n");
                exit(-1);
            }
        } else if (strcmp(argv[1], "-d") == 0) {
            active_debug = true;
            if(strcmp(argv[2], "-c") == 0) {
                file_name = argv[3];
                setup_client(file_name);
            } else {
                printf("ERR. -> Ús incorrecte dels paràmetres d'entrada \n");
                exit(-1);
            }
        } else {
            printf("ERR. -> Ús incorrecte dels paràmetres d'entrada \n");
            exit(-1);
        }
    }
}

void setup_client(char client_cfg[]) {
    client_file = fopen(client_cfg, "r");
    if(client_file == NULL) {
        perror("Error al inicialitzar el fitxer del client");
        close(tcp_socket.tcp_socket_fd);
        close(udp_socket.udp_socket_fd);
        exit(-1);
    }

    read_file();
}

void read_file() {
    int i = 0;
    char *read_data;
    char *token;
    size_t length = 0;

    client.state = NOT_REGISTERED;
    while(getline(&read_data, &length, client_file) != -1) {
        token = strtok(read_data, "= \n");
        while(token != NULL) {
            if(i % 2 == 1) {
                build_client_struct(i, token);
            }

            token = strtok(NULL, "= \n");
            i++;
        }

    }

    print_client();
}

void build_client_struct(int i, char *token) {
    if(i == 1) {
        strcpy(client.client_id, token);
    } else if (i == 3) {
        int num = 1;
        char *elems = strtok(token, ";= \n");
        while(elems != NULL) {
            if(num == 1) {
                strcpy(client.elem_one, elems);
            } else if(num == 2) {
                strcpy(client.elem_two, elems);
            } else if (num == 3) {
                strcpy(client.elem_three, elems);
            } else if (num == 4) {
                strcpy(client.elem_four, elems);
            } else if(num == 5) {
                strcpy(client.elem_five, elems);
            }

            elems = strtok(NULL, ";= \n");
            num++;
        }
    } else if (i == 5) {
        tcp_socket.local_tcp = atoi(token);
    } else if (i == 7) {
        strcpy(client.server, token);
    } else if (i == 9) {
        udp_socket.server_udp = atoi(token);
    }

}

void setup_tcp_socket() {
    tcp_socket.tcp_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(tcp_socket.tcp_socket_fd < 0) {
       perror("Error al inicialitzar el socket TCP: ERR. -> mètode socket()");
        close(tcp_socket.tcp_socket_fd);
        exit(-1);
    }

    if(bind(tcp_socket.tcp_socket_fd, (struct sockaddr *) &tcp_socket.tcp_socket_address, sizeof(tcp_socket.tcp_socket_address)) < 0) {
        perror("Error al inicialitzar el socket TCP: ERR. -> mètode bind()");
        close(tcp_socket.tcp_socket_fd);
        exit(-1);
    }

    if(connect(tcp_socket.tcp_socket_fd, (struct sockaddr *) &tcp_socket.tcp_socket_address, sizeof(tcp_socket.tcp_socket_address)) < 0) {
        perror("Error al inicialitzar el socket TCP: ERR. -> mètode connect()");
        close(tcp_socket.tcp_socket_fd);
        exit(-1);
    }

    tcp_socket.tcp_socket_address.sin_family = AF_INET;

    debug_message("INF. -> Socket TCP inicialitzat correctament");

    // http://www.chuidiang.org/clinux/sockets/udp/udp.php
}

void setup_udp_socket() {
    udp_socket.udp_socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(udp_socket.udp_socket_fd < 0) {
        perror("Error al inicialitzar el socket UDP: ERR. -> mètode socket()");
        close(udp_socket.udp_socket_fd);
        exit(-1);
    }

    if(bind(udp_socket.udp_socket_fd, (struct sockaddr *) &udp_socket.udp_socket_address, sizeof(udp_socket.udp_socket_address)) < 0) {
        perror("Error al inicialitzar el socket UDP: ERR. -> mètode bind()");
        close(udp_socket.udp_socket_fd);
        exit(-1);
    }

    if(connect(udp_socket.udp_socket_fd, (struct sockaddr *) &udp_socket.udp_socket_address, sizeof(udp_socket.udp_socket_address)) < 0) {
        perror("Error al inicialitzar el socket UDP: ERR. -> mètode connect()");
        close(udp_socket.udp_socket_fd);
        exit(-1);
    }

    memset(&udp_socket.udp_socket_address, 0, sizeof(struct sockaddr_in));
    udp_socket.udp_socket_address.sin_family = AF_INET;
    udp_socket.udp_socket_address.sin_port = htons(udp_socket.server_udp);
    udp_socket.udp_socket_address.sin_addr.s_addr = INADDR_ANY;

    debug_message("INF. -> Socket UDP inicialitzat correctament");
}

void debug_message(char message[]) {
    if(active_debug) {
        char time_string[LONG_MESSAGE];
        time_t t = time(NULL);

        struct tm *actual_time = localtime(&t);
        strftime(time_string, LONG_MESSAGE, "%b %d, %Y at %H:%M:%S", actual_time);
        printf("%s || %s\n", time_string, message);
    }
    // https://ccia.ugr.es/~jfv/ed1/c++/cdrom3/TIC-CD/web/tema9/teoria_14_2.htm
}

void register_process() {
    struct UDPPackage reg_request = build_udp_package(REG_REQ, client.client_id, "0000000000", "");
    print_udp_package(reg_request);

    register_loop(reg_request);
}

struct UDPPackage build_udp_package(unsigned char package_type, char transmitter_id[], char communication_id[], char data[]) {
    struct UDPPackage udp_package;

    udp_package.package_type = package_type;
    strcpy(udp_package.transmitter_id, transmitter_id);
    strcpy(udp_package.communication_id, communication_id);
    strcpy(udp_package.data, data);

    return udp_package;
}

struct TCPPackage build_tcp_package(unsigned char package_type, char transmitter_id[], char communication_id[], char elem[], char value[], char info[]) {
    struct TCPPackage tcp_package;

    tcp_package.package_type = package_type;
    strcpy(tcp_package.transmitter_id, transmitter_id);
    strcpy(tcp_package.communication_id, communication_id);
    strcpy(tcp_package.elem, elem);
    strcpy(tcp_package.value, value);
    strcpy(tcp_package.info, info);

    return tcp_package;
}

void register_loop(struct UDPPackage reg_request) {
    int attempts;
    int packages = 0;

    for(attempts = 0; attempts < O; attempts++) {
        packages = first_P_register_req(reg_request);
        if(packages == P) {
            packages = second_register_req(reg_request);
            if(packages < N) {
                break;
            }
        } else {
            break;
        }

        if(packages >= N && attempts - 1 < O) {
            sleep(U);
            debug_message("INF -> Es procedirà a reintentar el procés de registre");
        }
    }

    if(attempts >= O) {  //S'han superat el màxim d'intents
        perror("Error al establir connexió amb el servidor");
        exit(EXIT_FAILURE);
    } else { //Si el paquet és correcte (recv > 0) arriba aquí bé
        //print_udp_package(received_from_server);
        received_udp_package(received_from_server);
    }

}

int first_P_register_req(struct UDPPackage reg_request) {
    int p1;
    ssize_t send, recv;
    int packages = 0;

    for(p1 = 0; p1 < P; p1++) {  //Primers P (2) paquets
        send = sendto(udp_socket.udp_socket_fd, &reg_request, sizeof(reg_request), 0,
                      (struct sockaddr *) &udp_socket.udp_socket_address, sizeof(udp_socket.udp_socket_address));
        if (send < 0) {
            perror("Error al enviar la sol·licitud de registre al servidor. ERR. -> mètode sendto()");
        }
        packages++;

        if (client.state == NOT_REGISTERED) {
            client.state = WAIT_ACK_REG;
            debug_message("INF. -> Sol·licitud de registre enviada. Estat del client: NOT_REGISTERED -> WAIT_ACK_REG");
        } else {
            debug_message("INF. -> Sol·licitud de registre enviada. Estat del client: WAIT_ACK_REG");
        }

        recv = recvfrom(udp_socket.udp_socket_fd, &received_from_server, sizeof(received_from_server), 0,
                        (struct sockaddr *) 0, (socklen_t *) 0);
        print_udp_package(received_from_server);

        if (recv < 0) {
            sleep(T);
        } else {
            return packages;
        }
    }

    return P;
}

int second_register_req(struct UDPPackage reg_request) {
    int p2;
    ssize_t send, recv;
    int packages = P;
    int send_time = T;

    for(p2 = P; p2 < N && client.state != REGISTERED; p2++) {  //Des del 3r fins al 8è paquet
        send = sendto(udp_socket.udp_socket_fd, &reg_request, sizeof(reg_request), 0,
                      (struct sockaddr *) &udp_socket.udp_socket_address, sizeof(udp_socket.udp_socket_address));
        if(send < 0) {
            perror("Error al enviar la sol·licitud de registre al servidor. ERR. -> mètode sendto()");
        }
        packages++;

        if (client.state == NOT_REGISTERED) {
            client.state = WAIT_ACK_REG;
            debug_message("INF. -> Sol·licitud de registre enviada. Estat del client: NOT_REGISTERED -> WAIT_ACK_REG");
        } else {
            debug_message("INF. -> Sol·licitud de registre enviada. Estat del client: WAIT_ACK_REG");
        }

        recv = recvfrom(udp_socket.udp_socket_fd, &received_from_server, sizeof(received_from_server), 0,
                        (struct sockaddr *) 0, (socklen_t *) 0);
        print_udp_package(received_from_server);

        if (recv < 0) {
            if(packages == N) {
                return N;
            }
            send_time = package_timer(send_time);
            sleep(send_time);
        } else {
            return packages;
        }
    }

    return P;
}

int package_timer(int send_time) {
    if(send_time < Q * T) {
        return send_time + T;
    } else {
        return send_time;
    }
}

void received_udp_package(struct UDPPackage received_pack) {
    if(received_pack.package_type == REG_ACK) {
        printf("Rebut paquet REG_ACK -> S'enviarà un paquet REG_INFO al servidor\n");
        //server_data = build_udp_package();

        send_info_ack();
    } else if(received_pack.package_type == REG_NACK) {
        printf("Rebut paquet REG_NACK -> \n");
    } else if(received_pack.package_type == REG_REJ) {
        printf("Rebut paquet REG_REJ -> S'iniciarà un nou procés de registre\n");
        client.state = NOT_REGISTERED;
        register_process();
    } else if(received_pack.package_type == INFO_ACK) {
        printf("Rebut paquet INFO_ACK -> Estat del client: WAIT_ACK_INFO -> REGISTERED\n");
        debug_message("INF. -> Fase de registre completada amb èxit");
        client.state = REGISTERED;
    } else if(received_pack.package_type == INFO_NACK) {
        printf("Rebut paquet INFO_NACK -> \n");
    } else {
        printf("Tipus de paquet no identificat: ERR. -> mètode received_udp_package()\n");
        exit(EXIT_FAILURE);
    }
}

void send_info_ack() {

}

void print_client() {
    printf("/* CLIENT */\n");
    printf("Id: %s\n", client.client_id);
    printf("State: 0x%0X\n", client.state);
    printf("Local-TCP: %i\n", tcp_socket.local_tcp);
    printf("Elem1: %s\n", client.elem_one);
    printf("Elem2: %s\n", client.elem_two);
    printf("Elem3: %s\n", client.elem_three);
    printf("Elem4: %s\n", client.elem_four);
    printf("Elem5: %s\n", client.elem_five);
    printf("Server: %s\n", client.server);
    printf("Server-UDP: %i\n", udp_socket.server_udp);
    putchar('\n');
}

void print_tcp_package(struct TCPPackage package) {
    printf("/* TCP PACKAGE */\n");
    printf("Package_type: 0x%0X\n", package.package_type);
    printf("Transmitter_id: %s\n", package.transmitter_id);
    printf("Communication_id: %s\n", package.communication_id);
    printf("Element: %s\n", package.elem);
    printf("Value: %s\n", package.value);
    printf("Info: %s\n", package.info);
    putchar('\n');
}

void print_udp_package(struct UDPPackage package) {
    printf("/* UDP PACKAGE */\n");
    printf("Package_type: 0x%0X\n", package.package_type);
    printf("Transmitter_id: %s\n", package.transmitter_id);
    printf("Communication_id: %s\n", package.communication_id);
    printf("Data: %s\n", package.data);
    putchar('\n');
}

