#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "cryptogr.hpp"
#include "data.hpp"
#include "pthread.h"

#define PORT 3000
#define MAX_NUM_CLIENT   (4)
#define DEGUG_EXTRA_INFO (2)
#define DEBUG_MODE       (1)

int debug = 0;

void server_flow(int new_socket);
void *client_conn_handler(void *socket_desc);  //thread
void getOpcParser(int argc, char const* argv[]);






//netstat -vanp tcp | grep 3000

//./server -d 1
//./server -d 2
//./server -h
int main(int argc, char const* argv[])
{

    getOpcParser(argc, argv);

    int server_fd, new_socket, *new_sock;
    ssize_t value_read;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);
    pthread_t clients;

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
 
    // Forcefully attaching socket to the port
    if (setsockopt(server_fd, SOL_SOCKET,
                   SO_REUSEADDR | SO_REUSEPORT, &opt,
                   sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Forcefully attaching socket to the port
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 10) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }




    while(1){
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address, &addrlen)) < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        new_sock = (int*)malloc(1);
        *new_sock = new_socket;

        if (pthread_create(&clients, NULL, client_conn_handler, (void*)new_sock) != 0) {
            // Error in creating thread
            perror("could not create thread");
        }
    }


    close(server_fd);
    return 0;
}






void *client_conn_handler(void *socket_desc) {  //thread
    int sock = *(int*)socket_desc;
    server_flow(sock);
    close(sock);
    free(socket_desc);
    return 0;
}


void server_flow(int new_socket) {

    char buffer[MAX_SIZE_BUFFER] = { 0 };
    struct data_t data;
    uint32_t initial_key = 0x00;
    cryptography cryptation;
    cases_t cases = WAITING;
    int go_on = 1;
    int value_read;

    while(go_on == 1){

        switch (cases) {
            case WAITING:

                memset(buffer, 0, sizeof(buffer));
                value_read = read(new_socket, buffer, MAX_SIZE_BUFFER - 1);
                cases = (cases_t)buffer[OFFSET_HEADER_TYPE]; //  should arrive <--- 0
                break;

            case LOGIN_REQUEST:

                memcpy(&data.login.request, buffer, buffer[OFFSET_HEADER_SIZE_MSB] << 8 | buffer[OFFSET_HEADER_SIZE_LSB]);
                if(debug >= DEGUG_EXTRA_INFO)
                    printf("---> size: %d, sequence: %d, type: %d, user: %s , passw: %s  .\n",data.login.request.header.size ,data.login.request.header.sequence, data.login.request.header.type,
                data.login.request.user_name, data.login.request.password);
                cases = LOGIN_RESPONSE;

                break;
            case LOGIN_RESPONSE:

                data.login.response.header.sequence = data.login.request.header.sequence;
                data.login.response.header.type = LOGIN_RESPONSE;
                data.login.response.header.size = sizeof(data.login.response);
                /*condition to user and password if false disconnect client */
                data.login.response.status_code = STATUS_CODE_OK; //0=failed 1=OK

                initial_key =  (
                    (data.login.response.header.sequence << 16) |
                    (cryptation.checkSum((const char*)data.login.request.user_name) << 8) |
                    cryptation.checkSum((const char*)data.login.request.password)
                    );


                send(new_socket, &data.login.response, sizeof(data.login.response), 0);
                cases = WAITING; //  should arrive <--- 2
                break;
        case ECHO_REQUEST:

            memcpy(&data.echo.request, buffer, buffer[OFFSET_HEADER_SIZE_MSB] << 8 | buffer[OFFSET_HEADER_SIZE_LSB]);
            if (debug >= DEGUG_EXTRA_INFO)
                printf("<--- size: %d, sequence: %d, type: %d .\n",data.echo.request.header.size ,data.echo.request.header.sequence, data.echo.request.header.type);

            cryptation.getCipherKeyArray(data.echo.request.cipher_size, initial_key);

            if (debug == DEGUG_EXTRA_INFO) {
                printf("\nCipher_text:\n");
                for (size_t i = 0; i < data.echo.request.cipher_size; i++) {
                    printf("%02X ",data.echo.request.cipher_message[i]);
                }
            }

            cases = ECHO_RESPONSE;
            break;
        case ECHO_RESPONSE:

            data.echo.response.header.sequence = data.login.request.header.sequence;
            data.echo.response.header.type = ECHO_RESPONSE;
            data.echo.response.decipher_size = data.echo.request.cipher_size;
            data.echo.response.header.size = sizeof(data.echo.response.header) +
                data.echo.response.decipher_size + sizeof(data.echo.response.decipher_size);

            memcpy(data.echo.response.plain_message, cryptation.getDeCipherTextArray(data.echo.request.cipher_size, data.echo.request.cipher_message), data.echo.request.cipher_size);
            if (debug >= DEBUG_MODE)
                printf("\n\nDeciper text: %s\n", data.echo.response.plain_message);
            send(new_socket, &data.echo.response, sizeof(data.echo.response), 0);
            go_on = 0;
            break;
        default:
            break;
        }

    }
    if (debug >= DEBUG_MODE)
        printf("\n\n =============================================================\n");
}



void getOpcParser(int argc, char const* argv[]){
  int i;
  int option;

  while ((option = getopt(argc, (char * const *)argv, "d:h")) != -1) {
    switch (option) {
    case 'd':
      debug = (atoi(optarg) == DEGUG_EXTRA_INFO? DEGUG_EXTRA_INFO : DEBUG_MODE);
      break;
    case 'h':
      printf("use ./server -d 2\n");
      break;
    }
  }
}