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
#include <bits/types/struct_timeval.h>
#include <bits/pthreadtypes.h>
#include <pthread.h>

/* AUXILIARS */
#define LONG_MESSAGE 128

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

/* VARIABLES DE COMUNICACIÓ PERIÒDICA */
#define V 2
#define R 2
#define S 3

/* ENVIAMENT DE PAQUETS TCP */
#define M 3

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
    char all_elems[75];

    char elem_one[8];
    char elem_two[8];
    char elem_three[8];
    char elem_four[8];
    char elem_five[8];

    char value_one[16];
    char value_two[16];
    char value_three[16];
    char value_four[16];
    char value_five[16];

    int state;
    struct sockaddr_in client_address;
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

struct Server {
    char transmitter_id[11];
    char communication_id[11];
    char server_ip[15];
    int tcp_port;
};

FILE *client_file;
bool active_debug = false;
int num_reg_pr = 0;
pthread_t to_read = (pthread_t) NULL;

struct Client client;
struct TCPSocket tcp_socket;
struct UDPSocket udp_socket;
struct Server server_data;

struct UDPPackage received_udp_from_server;
struct TCPPackage received_tcp_from_server;

/* FUNCIONS PRINCIPALS */
void parse_args(int argc, char *argv[]);
void setup_tcp_socket();
void setup_udp_socket();
void setup_client(char client_cfg[]);
void read_file();
void debug_message(char message[]);
void start_client(int num_process);
int register_loop(struct UDPPackage reg_request);
int first_P_register_req(struct UDPPackage reg_request);
int second_register_req(struct UDPPackage reg_request);
void send_reg_info();
void send_alive_packs();
void treat_register_udp_package(struct UDPPackage received_pack);
void treat_alive_udp_package(struct UDPPackage received_pack);
void *read_commands();
void print_elems();
void treat_command(char command[]);
void disconnect_client();
void set_elem_value(char id_elem[], char new_value[]);
void send_tcp_data_package(unsigned char package_type, char id_elem[]);
char *associated_value(char id_elem[]);
void treat_data_tcp_package(struct TCPPackage received_pack);

void build_client_struct();
struct UDPPackage build_udp_package(unsigned char, char[], char[], char[]);
struct TCPPackage build_tcp_package(unsigned char, char[], char[], char[], char[], char[]);

/* FUNCIONS AUXILIARS */
void print_client();
void print_tcp_package(struct TCPPackage package);
void print_udp_package(struct UDPPackage package);
void print_server_data();
size_t getline();
int package_timer(int send_time);
bool valid_udp_package(struct UDPPackage checked_package);
bool valid_elem_id(char id_elem[]);
bool valid_tcp_package(struct TCPPackage checked_package);

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

    start_client(num_reg_pr);
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
        strcpy(client.all_elems, token);
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
        strcpy(server_data.server_ip, token);
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

    struct hostent *host = gethostbyname(server_data.server_ip);
    if(!host) {
        printf("Error: Servidor no trobat");
        exit(-1);
    }

    memset(&tcp_socket.tcp_socket_address, 0, sizeof(struct sockaddr_in));
    tcp_socket.tcp_socket_address.sin_family = AF_INET;
    tcp_socket.tcp_socket_address.sin_port = htons(server_data.tcp_port);
    tcp_socket.tcp_socket_address.sin_addr.s_addr = ((struct in_addr *) host->h_addr_list[0])->s_addr;

    if(connect(tcp_socket.tcp_socket_fd, (struct sockaddr *) &tcp_socket.tcp_socket_address, sizeof(tcp_socket.tcp_socket_address)) < 0) {
        perror("Error al inicialitzar el socket TCP: ERR. -> mètode connect()");
        close(tcp_socket.tcp_socket_fd);
        exit(-1);
    }

    debug_message("INF. -> Socket TCP inicialitzat correctament");
}

void setup_udp_socket() {
    udp_socket.udp_socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(udp_socket.udp_socket_fd < 0) {
        perror("Error al inicialitzar el socket UDP: ERR. -> mètode socket()");
        close(udp_socket.udp_socket_fd);
        exit(-1);
    }

    struct hostent *host = gethostbyname(server_data.server_ip);
    if(!host) {
        printf("Error: Servidor no trobat");
        exit(-1);
    }

    memset(&client.client_address, 0, sizeof(struct sockaddr_in));
    client.client_address.sin_family = AF_INET;
    client.client_address.sin_port = htons(0);
    client.client_address.sin_addr.s_addr = htonl(INADDR_ANY);

    if(bind(udp_socket.udp_socket_fd, (struct sockaddr *) &client.client_address, sizeof(client.client_address)) < 0) {
        perror("Error al inicialitzar el socket UDP: ERR. -> mètode bind()");
        close(udp_socket.udp_socket_fd);
        exit(-1);
    }

    memset(&udp_socket.udp_socket_address, 0, sizeof(struct sockaddr_in));
    udp_socket.udp_socket_address.sin_family = AF_INET;
    udp_socket.udp_socket_address.sin_port = htons(udp_socket.server_udp);
    udp_socket.udp_socket_address.sin_addr.s_addr = ((struct in_addr *) host->h_addr_list[0])->s_addr;

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
}

void start_client(int num_process) {
    setup_udp_socket();
    struct UDPPackage reg_request = build_udp_package(REG_REQ, client.client_id, "0000000000", "");
    //print_udp_package(reg_request);

    int attempts, packages;
    for(attempts = num_process; attempts < O; attempts++) {
        packages = register_loop(reg_request);
        if(packages <= N) {
            break;
        }

        if(packages >= N && attempts - 1 < O) {
            sleep(U);
            debug_message("INF -> Es procedirà a iniciar un nou procés de registre");
        }
    }

    if(attempts >= O) {  //S'han superat el màxim d'intents
        printf("ERR. -> No s'ha pogut establir connexió amb el servidor.\n");
        exit(EXIT_FAILURE);
    } else {
        treat_register_udp_package(received_udp_from_server);
    }
}

int register_loop(struct UDPPackage reg_request) {
    int packages = first_P_register_req(reg_request);
    if(packages == P) {
        packages = second_register_req(reg_request);
    }
    return packages;
}

int first_P_register_req(struct UDPPackage reg_request) {
    struct timeval tmv;
    tmv.tv_sec = T;
    tmv.tv_usec = 0;

    int p1;
    ssize_t send, recv;
    int packages = 0;

    for(p1 = 0; p1 < P; p1++) {  //Primers P (2) paquets
        send = sendto(udp_socket.udp_socket_fd, &reg_request, sizeof(reg_request), 0,
                      (struct sockaddr *) &udp_socket.udp_socket_address, sizeof(udp_socket.udp_socket_address));
        if(send < 0) {
            perror("Error al enviar la sol·licitud de registre al servidor. ERR. -> mètode sendto()");
        }
        packages++;

        if (client.state == NOT_REGISTERED) {
            client.state = WAIT_ACK_REG;
            printf("INF. -> Sol·licitud de registre (REG_REQ) enviada. Estat del client: NOT_REGISTERED -> WAIT_ACK_REG\n");
        } else {
            debug_message("INF. -> Sol·licitud de registre (REG_REQ) enviada. Estat del client: WAIT_ACK_REG");
        }

        setsockopt(udp_socket.udp_socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *) &tmv, sizeof(tmv));
        recv = recvfrom(udp_socket.udp_socket_fd, &received_udp_from_server, sizeof(received_udp_from_server), 0,
                        (struct sockaddr *) 0, (socklen_t *) 0);
        print_udp_package(received_udp_from_server);

        if(recv > 0) {
            return packages;
        }
    }

    return P;
}

int second_register_req(struct UDPPackage reg_request) {
    struct timeval tmv;
    tmv.tv_sec = T;
    tmv.tv_usec = 0;

    int p2;
    ssize_t send, recv;
    int packages = P;
    for(p2 = P; p2 < N && client.state != REGISTERED; p2++) {  //Des del 3r fins al 8è paquet
        send = sendto(udp_socket.udp_socket_fd, &reg_request, sizeof(reg_request), 0,
                      (struct sockaddr *) &udp_socket.udp_socket_address, sizeof(udp_socket.udp_socket_address));
        if(send < 0) {
            perror("Error al enviar la sol·licitud de registre al servidor. ERR. -> mètode sendto()");
        }
        packages++;

        if (client.state == NOT_REGISTERED) {
            client.state = WAIT_ACK_REG;
            printf("INF. -> Sol·licitud de registre (REG_REQ) enviada. Estat del client: NOT_REGISTERED -> WAIT_ACK_REG\n");
        } else {
            debug_message("INF. -> Sol·licitud de registre (REG_REQ) enviada. Estat del client: WAIT_ACK_REG");
        }

        setsockopt(udp_socket.udp_socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *) &tmv, sizeof(tmv));
        recv = recvfrom(udp_socket.udp_socket_fd, &received_udp_from_server, sizeof(received_udp_from_server), 0,
                        (struct sockaddr *) 0, (socklen_t *) 0);
        //print_udp_package(received_udp_from_server);

        if (recv < 0) {
            if(packages == N) {
                return N;
            }
            tmv.tv_sec = package_timer(tmv.tv_sec);
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

void treat_register_udp_package(struct UDPPackage received_pack) {
    if(received_pack.package_type == REG_ACK) {
        printf("Rebut paquet REG_ACK -> S'enviarà un paquet REG_INFO al servidor\n");
        strcpy(server_data.transmitter_id, received_pack.transmitter_id);
        strcpy(server_data.communication_id, received_pack.communication_id);

        send_reg_info();
    } else if(received_pack.package_type == REG_NACK) {
        printf("Rebut paquet REG_NACK -> Es reiniciarà l'enviament de paquets de registre\n");
        client.state = NOT_REGISTERED;
        start_client(num_reg_pr);
    } else if(received_pack.package_type == REG_REJ) {
        printf("Rebut paquet REG_REJ -> S'iniciarà un nou procés de registre\n");
        client.state = NOT_REGISTERED;
        num_reg_pr++;
        start_client(num_reg_pr);
    } else if(received_pack.package_type == INFO_ACK) {
        if(valid_udp_package(received_pack)) {
            printf("Rebut paquet INFO_ACK -> Estat del client: WAIT_ACK_INFO -> REGISTERED\n");
            debug_message("INF. -> Inici de la fase d'enviament de paquets ALIVE");
            client.state = REGISTERED;
            server_data.tcp_port = atoi(received_pack.data);
            udp_socket.udp_socket_address.sin_port = htons(udp_socket.server_udp);
            send_alive_packs();
        } else {
            printf("ERR. -> Dades del paquet INFO_ACK errònies. S'iniciarà un nou procés de registre.\n");
            udp_socket.udp_socket_address.sin_port = htons(udp_socket.server_udp);
            client.state = NOT_REGISTERED;
            num_reg_pr++;
            start_client(num_reg_pr);
        }
    } else if(received_pack.package_type == INFO_NACK) {
        if(valid_udp_package(received_pack)) {
            printf("Rebut paquet INFO_NACK -> Es reiniciarà l'enviament de paquets de registre.\n");
            printf("ERR: %s\n", received_pack.data);
        } else {
            printf("ERR. -> Dades del paquet INFO_NACK errònies. S'iniciarà un nou procés de registre.\n");
            num_reg_pr++;
        }
        client.state = NOT_REGISTERED;
        udp_socket.udp_socket_address.sin_port = htons(udp_socket.server_udp);
        start_client(num_reg_pr);
    } else {
        printf("Rebut paquet UNKNOWN: S'iniciarà un nou procés de registre\n");
        client.state = NOT_REGISTERED;
        num_reg_pr++;
        start_client(num_reg_pr);
    }
}

void send_reg_info() {
    struct timeval tmv;
    tmv.tv_sec = 2 * T;
    tmv.tv_usec = 0;

    ssize_t send, recv;
    char data[61];
    sprintf(data, "%d,", tcp_socket.local_tcp);
    strcat(data, client.all_elems);

    struct UDPPackage reg_info = build_udp_package(REG_INFO, client.client_id, server_data.communication_id, data);
    //print_udp_package(reg_info);


    udp_socket.udp_socket_address.sin_port = htons(atoi(received_udp_from_server.data));
    send = sendto(udp_socket.udp_socket_fd, &reg_info, sizeof(reg_info), 0,
                      (struct sockaddr *) &udp_socket.udp_socket_address, sizeof(udp_socket.udp_socket_address));
    if(send < 0) {
        perror("Error al enviar el paquet REG_INFO al servidor. ERR. -> mètode sendto()");
    } else {
        if(client.state == WAIT_ACK_REG) {
            client.state = WAIT_ACK_INFO;
            printf("INF. -> Paquet REG_INFO enviat al servidor. Estat del client: WAIT_ACK_REG -> WAIT_ACK_INFO\n");
        }

        setsockopt(udp_socket.udp_socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *) &tmv, sizeof(tmv));
        recv = recvfrom(udp_socket.udp_socket_fd, &received_udp_from_server, sizeof(received_udp_from_server), 0,
                        (struct sockaddr *) 0, (socklen_t *) 0);
        //print_udp_package(received_udp_from_server);
        if(recv < 0) {
            client.state = NOT_REGISTERED;
            debug_message("INF. -> No s'ha rebut el paquet de confirmació de client");
            printf("INF. -> Estat del client. WAIT_ACK_INFO -> NOT_REGISTERED.\n");
            udp_socket.udp_socket_address.sin_port = htons(udp_socket.server_udp);
            num_reg_pr++;
            start_client(num_reg_pr);
        } else {
            treat_register_udp_package(received_udp_from_server);
        }
    }
}

void send_alive_packs() {
    print_server_data();
    int not_received_alives = 0;

    struct timeval tmv;
    tmv.tv_sec = R * V;
    tmv.tv_usec = 0;

    ssize_t send, recv;
    struct UDPPackage alive_pack = build_udp_package(ALIVE, client.client_id, server_data.communication_id, "");
    while((client.state == REGISTERED || client.state == SEND_ALIVE) != 0) {
        send = sendto(udp_socket.udp_socket_fd, &alive_pack, sizeof(alive_pack), 0,
                      (struct sockaddr *) &udp_socket.udp_socket_address, sizeof(udp_socket.udp_socket_address));
        if (send < 0) {
            perror("Error al enviar el paquet ALIVE al servidor. ERR. -> mètode sendto()");
        } else {
            setsockopt(udp_socket.udp_socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *) &tmv, sizeof(tmv));
            recv = recvfrom(udp_socket.udp_socket_fd, &received_udp_from_server, sizeof(received_udp_from_server), 0,
                            (struct sockaddr *) 0, (socklen_t *) 0);
            if (recv < 0) {
                not_received_alives++;
                debug_message("INF. -> No s'ha rebut el paquet ALIVE de resposta del servidor");
                printf("Paquets ALIVE del servidor no rebuts: %i\n", not_received_alives);
                if(not_received_alives == S) {
                    client.state = NOT_REGISTERED;
                    printf("INF. -> S'iniciarà un nou procés de registre: Número de paquets ALIVE no rebuts excedit.\n");
                    num_reg_pr++;
                    start_client(num_reg_pr);
                }
                debug_message("INF. -> Enviament d'ALIVE");
            } else {
                //print_udp_package(received_udp_from_server);
                not_received_alives = 0;
                treat_alive_udp_package(received_udp_from_server);
            }
        }
    }
}

void treat_alive_udp_package(struct UDPPackage received_pack) {
    if(received_pack.package_type == ALIVE) {
        if(valid_udp_package(received_pack) && strcmp(client.client_id, received_pack.data) == 0) {
            debug_message("INF -> Rebut paquet ALIVE -> Dades correctes");
            if(client.state == REGISTERED) {
                client.state = SEND_ALIVE;
                pthread_create(&to_read, NULL, read_commands, NULL);
                printf("INF. -> Estat del client: REGISTERED -> SEND_ALIVE\n");
                debug_message("INF. -> Port TCP obert");
            }
            debug_message("INF. -> Enviament d'ALIVE");
            sleep(V);
            //exit(0);        //Substituir el break i treure posteriorment
        } else {
            printf("ERR. -> Dades del paquet ALIVE errònies. S'iniciarà un nou procés de registre.\n");
            client.state = NOT_REGISTERED;
            num_reg_pr++;
            start_client(num_reg_pr);
        }
    } else if(received_pack.package_type == ALIVE_NACK) {
        printf("Rebut paquet ALIVE_NACK -> Es reiniciarà l'enviament de paquets de registre.\n");
        client.state = NOT_REGISTERED;
        pthread_cancel(to_read);
        start_client(num_reg_pr);
    } else if(received_pack.package_type == ALIVE_REJ) {
        printf("Rebut paquet ALIVE_REJ -> S'iniciarà un nou procés de registre\n");
        client.state = NOT_REGISTERED;
        pthread_cancel(to_read);
        num_reg_pr++;
        start_client(num_reg_pr);
    } else {
        printf("Rebut paquet UNKNOWN -> S'iniciarà un nou procés de registre\n");
        client.state = NOT_REGISTERED;
        pthread_cancel(to_read);
        num_reg_pr++;
        start_client(num_reg_pr);
    }
}

bool valid_udp_package(struct UDPPackage checked_package) {
    if(strcmp(server_data.transmitter_id, checked_package.transmitter_id) == 0 && strcmp(server_data.communication_id, checked_package.communication_id) == 0) {
        return true;
    } else {
        return false;
    }
}

void *read_commands() {
    while(1) {
        char command[LONG_MESSAGE];
        fgets(command, LONG_MESSAGE, stdin);

        char *quit_intro = strtok(command, "\n");
        if(quit_intro != NULL) {
            treat_command(quit_intro);
        }
    }
}

void treat_command(char command[]) {
    if(strcmp("stat", command) == 0) {
        print_elems();
    } else if(strcmp("quit", command) == 0){
        disconnect_client();
        return;
    } else {
        char *token = strtok(command, " \n");
        if(strcmp("set", token) == 0) {
            int i = 0;
            char id_elem[15];
            char new_value[15];
            token = strtok(NULL, " \n");
            while(token != NULL) {
                if(i == 0) {
                    strcpy(id_elem, token);
                } else if(i == 1) {
                    strcpy(new_value, token);
                }

                token = strtok(NULL, " \n");
                i++;
            }

            if(i == 2) {
                if(valid_elem_id(id_elem)) {
                    set_elem_value(id_elem, new_value);
                } else {
                    printf("%s -> Identificador no vàlid.\n", id_elem);
                }
            } else {
                printf("Ús: set <identificador_element> <nou_valor>.\n");
            }
            return;
        } else if(strcmp("send", token) == 0) {
            printf("Comanda *send* no implementada.\n");
        } else {
            printf("*%s* -> Comanda errònia.\n", token);
            return;
        }
    }
}

void disconnect_client() {
    if(client.state == SEND_ALIVE) {
        close(tcp_socket.tcp_socket_fd);
        close(udp_socket.udp_socket_fd);
        close(tcp_socket.local_tcp);
        close(udp_socket.server_udp);

        close(server_data.tcp_port);

        printf("INF -> Dispositiu amb id: %s desconnectat amb èxit.\n", client.client_id);
        exit(EXIT_SUCCESS);
    } else {
        printf("ERR. -> Estat del client no és SEND_ALIVE i no es pot executar la comanda 'quit'.\n");
    }
}

void set_elem_value(char id_elem[], char new_value[]) {
    if(strcmp(client.elem_one, id_elem) == 0) {
        strcpy(client.value_one, new_value);
    } else if(strcmp(client.elem_two, id_elem) == 0) {
        strcpy(client.value_two, new_value);
    } else if(strcmp(client.elem_three, id_elem) == 0) {
        strcpy(client.value_three, new_value);
    } else if(strcmp(client.elem_four, id_elem) == 0) {
        strcpy(client.value_four, new_value);
    } else if(strcmp(client.elem_five, id_elem) == 0) {
        strcpy(client.value_five, new_value);
    }

    printf("INF -> Valor de l'element %s canviat amb èxit.\n", id_elem);
}

void send_tcp_data_package(unsigned char package_type, char id_elem[]) {
    struct timeval tmv;
    tmv.tv_sec = M;
    tmv.tv_usec = 0;

    ssize_t send_p, recv_p;

    char actual_value[16];
    strcpy(actual_value, associated_value(id_elem));

    char date[80];
    time_t t = time(NULL);
    struct tm *tmp = localtime(&t);
    strftime(date, 80, "%Y-%m-%d;%H:%M:%S", tmp);

    struct TCPPackage send_tcp_data = build_tcp_package(package_type, client.client_id, server_data.communication_id, id_elem, actual_value, date);
    print_tcp_package(send_tcp_data);

    setup_tcp_socket();
    send_p = send(tcp_socket.tcp_socket_fd, &send_tcp_data, sizeof(send_tcp_data), 0);

    if(send_p < 0) {
        perror("Error al enviar el paquet SEND_DATA al servidor. ERR. -> mètode send()");
    }

    setsockopt(tcp_socket.tcp_socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *) &tmv, sizeof(tmv));
    recv_p = recv(tcp_socket.tcp_socket_fd, &received_tcp_from_server, sizeof(received_tcp_from_server), 0);
    if(recv_p < 0) {
        printf("Timeout del socket TCP esgotat -> Dades no acceptades. S'iniciarà un nou procés de registre.\n");
        num_reg_pr++;
        start_client(num_reg_pr);
    } else {
        print_tcp_package(received_tcp_from_server);
        treat_data_tcp_package(received_tcp_from_server);
    }

}

void treat_data_tcp_package(struct TCPPackage received_pack) {
    if(received_pack.package_type == DATA_ACK) {
        if(valid_tcp_package(received_pack)) {
            printf("Rebut paquet DATA_ACK -> Enviament d'informació acceptat.\n");
            close(tcp_socket.tcp_socket_fd);
        } else {
            printf("Dades del paquet DATA_ACK errònies. -> S'iniciarà un nou procés de registre.\n");
            client.state = NOT_REGISTERED;
            close(udp_socket.udp_socket_fd);
            close(tcp_socket.tcp_socket_fd);
            num_reg_pr++;
            start_client(num_reg_pr);
        }
    } else if(received_pack.package_type == DATA_NACK) {
        printf("Rebut paquet DATA_NACK -> Error al emmagatzemar les dades o dades errònies.\n");
        close(tcp_socket.tcp_socket_fd);
    } else if(received_pack.package_type == DATA_REJ) {
        printf("Rebut paquet DATA_REJ -> Informació rebutjada. S'obrirà un nou procés de registre.\n");
        client.state = NOT_REGISTERED;
        pthread_cancel(to_read);
        close(udp_socket.udp_socket_fd);
        close(tcp_socket.tcp_socket_fd);
        num_reg_pr++;
        start_client(num_reg_pr);
    } else if(received_pack.package_type == SET_DATA) {
        if(valid_tcp_package(received_pack) && valid_elem_id(received_pack.elem) && received_pack.elem[6] == 'I') {
            printf("Rebut paquet SET_DATA -> Dades correctes\n");
            set_elem_value(received_pack.elem, received_pack.value);
            send_tcp_data_package(DATA_ACK, received_pack.elem);
        } else {
            printf("Rebut paquet SET_DATA -> Però les dades són incorrectes.\n");
        }
    } else if(received_pack.package_type == GET_DATA) {
        if(valid_tcp_package(received_pack) && valid_elem_id(received_pack.elem)) {
            printf("Rebut paquet GET_DATA -> L'element pertany al dispositiu.\n");
            send_tcp_data_package(DATA_ACK, received_pack.elem);
        } else {
            printf("Rebut paquet GET_DATA -> Però les dades són incorrectes.\n");
        }
    } else {
        printf("Rebut paquet UNKNOWN\n");
    }
}

char *associated_value(char id_elem[]) {
    if(strcmp(client.elem_one, id_elem) == 0) {
        return client.value_one;
    } else if(strcmp(client.elem_two, id_elem) == 0) {
        return client.value_two;
    } else if(strcmp(client.elem_three, id_elem) == 0) {
        return client.value_three;
    } else if(strcmp(client.elem_four, id_elem) == 0) {
        return client.value_four;
    } else if(strcmp(client.elem_five, id_elem) == 0) {
        return client.value_five;
    }

    return NULL;
}

bool valid_elem_id(char id_elem[]) {
   return strcmp(client.elem_one, id_elem) == 0 || strcmp(client.elem_two, id_elem) == 0 || strcmp(client.elem_three, id_elem) == 0 ||
           strcmp(client.elem_four, id_elem) == 0 || strcmp(client.elem_five, id_elem) == 0;
}

bool valid_tcp_package(struct TCPPackage checked_package) {
    return strcmp(checked_package.communication_id, server_data.communication_id) == 0 && valid_elem_id(checked_package.elem)
            && strcmp(client.client_id, checked_package.info) == 0;
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

struct UDPPackage build_udp_package(unsigned char package_type, char transmitter_id[], char communication_id[], char data[]) {
    struct UDPPackage udp_package;

    udp_package.package_type = package_type;
    strcpy(udp_package.transmitter_id, transmitter_id);
    strcpy(udp_package.communication_id, communication_id);
    strcpy(udp_package.data, data);

    return udp_package;
}

void print_elems() {
    printf("ELEMENT   VALUE\n");
    printf("-------   -------\n");
    printf("%s    %s\n", client.elem_one, client.value_one);
    printf("%s    %s\n", client.elem_two, client.value_two);
    printf("%s    %s\n", client.elem_three, client.value_three);
    printf("%s    %s\n", client.elem_four, client.value_four);
    printf("%s    %s\n", client.elem_five, client.value_five);
}

void print_client() {
    printf("/* CLIENT (cfg) */\n");
    printf("Id: %s\n", client.client_id);
    printf("State: 0x%0X\n", client.state);
    printf("Local-TCP: %i\n", tcp_socket.local_tcp);
    printf("AllElems: %s\n", client.all_elems);
    print_elems();
    printf("Server: %s\n", server_data.server_ip);
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

void print_server_data() {
    printf("/* SERVER PARAMS */\n");
    printf("Transmitter_id: %s\n", server_data.transmitter_id);
    printf("Communication_id: %s\n", server_data.communication_id);
    printf("Server: %s\n", server_data.server_ip);
    printf("TCP port: %i\n", server_data.tcp_port);
    putchar('\n');
}

