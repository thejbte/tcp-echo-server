#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "cryptogr.hpp"
#include "data.hpp"
#include <iostream>

#define PORT 3000

#define ARG_PASSW   (3)
#define ARG_USER    (2)
#define ARG_MSG     (1)

char username[MAX_SIZE_USER_AND_PASSW] = "testuser";
char password[MAX_SIZE_USER_AND_PASSW] = "testpass";

uint8_t message_sequence = 87;
uint32_t initial_key = 0x00;

//./client "hola mundo" "testuser" "testpass"

//g++ cryptogr.cpp client.cpp -o client && g++ cryptogr.cpp server.cpp -o  server

void client_flow(int client_fd, char *message);






int main(int argc, char const* argv[])
{
    int status, client_fd;
    struct sockaddr_in serv_addr;

    char message[MAX_SIZE_BUFFER] = "hola julian, mensaje cifrado algo mas";

    if(argc < 2 ){
        printf("bad argumnets: ./main \"message to send\" \"user\" \"password\"\n");
        return 0;
    }

    if (argv[ARG_MSG] != nullptr &&  argv[ARG_USER] != nullptr && argv[ARG_PASSW] != nullptr) {
        memset(message, 0, sizeof(message));
        memset(username, 0, sizeof(username));
        memset(password, 0, sizeof(password));
        strncpy(message, argv[ARG_MSG], strlen(argv[ARG_MSG]));
        strncpy(username, argv[ARG_USER], strlen(argv[ARG_USER]));
        strncpy(password, argv[ARG_PASSW], strlen(argv[ARG_PASSW]));
    } else {
        printf("bad argumnets: ./main \"message to send\" \"user\" \"password\"\n");
        return 0;
    }

    char buffer[MAX_SIZE_BUFFER] = { 0 };
    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    if ((status = connect(client_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr))) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }

    /*loop*/
    client_flow(client_fd, message);


    close(client_fd);
    return 0;
}







void client_flow(int client_fd, char *message) {

    char buffer[MAX_SIZE_BUFFER] = { 0 };
    struct data_t data;
    uint32_t initial_key = 0x00;
    cryptography cryptation;
    cases_t cases = LOGIN_REQUEST;
    int go_on = 1;
    int value_read;
    size_t lenmsg = strlen(message);

    initial_key =  ((message_sequence << 16) |
                    (cryptation.checkSum(username) << 8) |
                    cryptation.checkSum(password));


    while(go_on == 1){

        /*type*/
        switch (cases) {
            case WAITING:
                memset(buffer, 0, sizeof(buffer));
                value_read = read(client_fd, buffer, MAX_SIZE_BUFFER - 1);
                cases = (cases_t)buffer[OFFSET_HEADER_TYPE];
                break;

            case LOGIN_REQUEST:
                strncpy((char*)data.login.request.user_name, username, strlen(username) + 1);
                strncpy((char*)data.login.request.password, password, strlen(password) + 1);
                data.login.request.header.sequence = message_sequence;
                data.login.request.header.type = LOGIN_REQUEST;
                data.login.request.header.size = sizeof(data.login.request);

                send(client_fd, &data.login.request, sizeof(data.login.request), 0);
                cases = WAITING; //  should arrive <--- 1

                break;
            case LOGIN_RESPONSE:
                /* login response */
                memcpy(&data.login.response, buffer,
                     buffer[OFFSET_HEADER_SIZE_MSB] << 8 |
                     buffer[OFFSET_HEADER_SIZE_LSB]);

                if (data.login.response.status_code == STATUS_CODE_OK) {
                    cases = ECHO_REQUEST;
                } else {
                    go_on = 0; // close client
                }
                break;
            case ECHO_REQUEST:
                data.echo.request.header.sequence = data.login.request.header.sequence;
                data.echo.request.header.type = ECHO_REQUEST;

                data.echo.request.cipher_size = lenmsg;
                data.echo.request.header.size = sizeof(data.echo.request.header) +
                    data.echo.request.cipher_size + sizeof(data.echo.request.cipher_size);

                cryptation.getCipherKeyArray(lenmsg, initial_key);
                memcpy(data.echo.request.cipher_message,
                    cryptation.getCipherTextArray(lenmsg, message), lenmsg);
                send(client_fd, &data.echo.request, sizeof(data.echo.request) , 0);
                cases = WAITING; //  should arrive <--- 3
                break;
            case ECHO_RESPONSE:

                /* echo response */
                memcpy(&data.echo.response, buffer,
                buffer[OFFSET_HEADER_SIZE_MSB] << 8 |
                buffer[OFFSET_HEADER_SIZE_LSB]);

                printf("\nResponse: %s\n", data.echo.response.plain_message);
                go_on = 0;
                break;

            default:
                go_on = 0;
                break;
        }
    }
}
