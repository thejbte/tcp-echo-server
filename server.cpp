// Server side C program to demonstrate Socket
// programming
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "cryptogr.hpp"
#include "data.hpp"

#define PORT 8080

int main(int argc, char const* argv[])
{
    int server_fd, new_socket;
    ssize_t valread;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);
    char buffer[1024] = { 0 };
    //char* hello = "Hello from server";
    
    uint8_t checkSumPassword = 0, checkSumUserName = 0;
    char message[65535] = "hola julian, mensaje cifrado algo mas from server";
    size_t lenmsg = strlen(message);
    cryptography cryptation;
    struct data_t data;
    uint32_t initial_key = 0x00;
    //data.echo.login.cipher_message = new uint8_t[len_msg];



    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
 
    // Forcefully attaching socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET,
                   SO_REUSEADDR | SO_REUSEPORT, &opt,
                   sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
 
    // Forcefully attaching socket to the port 8080
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    if ((new_socket = accept(server_fd, (struct sockaddr*)&address, &addrlen)) < 0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }
    
    uint8_t *cipher_key_ptr;
    int go_on = 1;
    while(go_on == 1){
        memset(buffer, 0, sizeof(buffer));
        valread = read(new_socket, buffer, 1024 - 1); // subtract 1 for the null
                              // terminator at the end

        for(int i=0; i < strlen(message); i++){
            printf("buffer[%d]: %02X %c\n",i, buffer[i], buffer[i]);
        }

        switch (buffer[2]) /*type*/
        {
        case 0:
            /* login request */
            memcpy(&data.login.request, buffer, buffer[1] << 8 | buffer[0]);
            printf("size: %ld, sequence: %d, type: %d, user: %s , passw: %s  .\n",data.login.request.header.size ,data.login.request.header.sequence, data.login.request.header.type,
            data.login.request.user_name, data.login.request.password);

            data.login.response.header.sequence = data.login.request.header.sequence;
            data.login.response.header.type = 1;
            data.login.response.header.size = sizeof(data.login.response);
            /*condition to user and password if false disconnect client */
            data.login.response.status_code = 1; //0=failed 1=OK

            checkSumPassword = cryptation.checkSum((const char*)data.login.request.password);
            checkSumUserName = cryptation.checkSum((const char*)data.login.request.user_name);
            initial_key =  ((data.login.response.header.sequence << 16) | (checkSumUserName << 8) | (checkSumPassword));


            printf("\n");
            //send(new_socket, message, strlen(message), 0);
            send(new_socket, &data.login.response, sizeof(data.login.response), 0);
            printf("Hello message sent\n");
            break;
        case 2:
            /* echo request */

            //data.echo.request.cipher_message = new uint8_t[buffer[5] << 8 | buffer[4]];
            memcpy(&data.echo.request, buffer, buffer[1] << 8 | buffer[0]);
            printf("size: %ld, sequence: %d, type: %d .\n",data.echo.request.header.size ,data.echo.request.header.sequence, data.echo.request.header.type);
            //data.echo.request.ciph15er_message = new uint8_t[data.echo.request.cipher_size];

            cipher_key_ptr = cryptation.getCipherKeyArray(data.echo.request.cipher_size, initial_key);
    printf("\n\n cipher_key:\n");
    for (size_t i = 0; i < data.echo.request.cipher_size; i++)
    {
        printf("%02X ",cipher_key_ptr[i]);
    }

                printf("\n\n cipher_text:\n");
                
    for (size_t i = 0; i < data.echo.request.cipher_size; i++)
    {
        printf("%02X ",data.echo.request.cipher_message[i]);
    }

            data.echo.response.header.sequence = data.login.request.header.sequence;
            data.echo.response.header.type = 3;
            data.echo.response.decipher_size = data.echo.request.cipher_size;
            data.echo.response.header.size = sizeof(data.echo.response.header) +
                data.echo.response.decipher_size + sizeof(data.echo.response.decipher_size);

            memcpy(data.echo.response.plain_message, cryptation.getDeCipherTextArray(data.echo.request.cipher_size, data.echo.request.cipher_message), data.echo.request.cipher_size);
            printf("Deciper text: %s\n", data.echo.response.plain_message);

            // printf("\n");
            //send(new_socket, message, strlen(message), 0);
            send(new_socket, &data.echo.response, sizeof(data.echo.response), 0);
           // printf("Hello message sent\n");
            go_on = 0;
            close(new_socket);
            break;
        default:
            break;
        }




        //printf("\n");
        //send(new_socket, message, strlen(message), 0);
        //printf("Hello message sent\n");
    
        // closing the connected socket
        //close(new_socket);
        // closing the listening socket
    }
    close(server_fd);
    //delete data.echo.request.cipher_message;
    //delete cipher_key_ptr;
    //delete data.echo.response.plain_message;
    return 0;
}