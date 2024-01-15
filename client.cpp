// Client side C program to demonstrate Socket
// programming
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "cryptogr.hpp"
#include "data.hpp"
#include <iostream>

#define PORT 8080

char username[MAX_LEN_USER_AND_PASSW] ="testuser";
char password[MAX_LEN_USER_AND_PASSW] ="testpass";
uint8_t bytte = 0x00;
uint8_t message_sequence = 87;
uint32_t initial_key = 0x00;



int main(int argc, char const* argv[])
{
    int status, valread, client_fd;
    struct sockaddr_in serv_addr;

    uint8_t checkSumPassword = 0, checkSumUserName = 0;
    char message[65535] = "hola julian, mensaje cifrado algo mas";
    size_t lenmsg = 0;
    cryptography cryptation;
    struct data_t data;
    //data.echo.login.cipher_message = new uint8_t[len_msg];
    uint8_t *cipher_key_ptr;

    if(argc < 2 ){
        printf("bad argumnets: ./main \"message to send\"\n");
        return 0;
    }

    if (argv[1] != nullptr) {
        memset(message, 0, sizeof(message));
        strncpy(message, argv[1], strlen(argv[1]));

    }
    lenmsg = strlen(message);
    checkSumPassword = cryptation.checkSum(password);
    checkSumUserName = cryptation.checkSum(username);
    initial_key =  ((message_sequence << 16) | (checkSumUserName << 8) | (checkSumPassword));

    /*login request*/
    strncpy((char*)data.login.request.user_name, username, strlen(username) + 1);
    strncpy((char*)data.login.request.password, password, strlen(password) + 1);
    data.login.request.header.sequence = message_sequence;
    data.login.request.header.type = 0;
    data.login.request.header.size = sizeof(data.login.request);

    char buffer[1024] = { 0 };
    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }
 
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
 
    // Convert IPv4 and IPv6 addresses from text to binary
    // form
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }
 
    if ((status = connect(client_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr))) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }

    int go_on = 1;
    send(client_fd, &data.login.request, sizeof(data.login.request), 0);
    printf("Hello message sent\n");
    while(go_on == 1){
        memset(buffer, 0, sizeof(buffer));
        valread = read(client_fd, buffer, 1024 - 1); // subtract 1 for the null
                                  // terminator at the end
        switch (buffer[2]) /*type*/
        {
        case 1:
            /* login response */
            memcpy(&data.login.response, buffer, buffer[1] << 8 | buffer[0]);
            printf("size: %ld, sequence: %d, type: %d, statusCode: %d .\n",data.login.response.header.size ,
            data.login.response.header.sequence, data.login.response.header.type,
            data.login.response.status_code);

        if (data.login.response.status_code == 1) //0=failed 1=OK
        {
            data.echo.request.header.sequence = data.login.request.header.sequence;
            data.echo.request.header.type = 2;


            data.echo.request.cipher_size = lenmsg;
            data.echo.request.header.size = sizeof(data.echo.request.header) +
                data.echo.request.cipher_size + sizeof(data.echo.request.cipher_size);

            cipher_key_ptr = cryptation.getCipherKeyArray(lenmsg, initial_key);
            //uint8_t *cipher_text_ptr = cryptation.getCipherTextArray(lenmsg, message);
            memcpy(data.echo.request.cipher_message, cryptation.getCipherTextArray(lenmsg, message), lenmsg);
                printf("\n\n cipher_text:\n");
    for (size_t i = 0; i < lenmsg; i++)
    {
        //printf("%02X ",data.echo.request.cipher_message[i]);
    }
            send(client_fd, &data.echo.request, sizeof(data.echo.request) , 0);
            //send(client_fd, data.echo.request.cipher_message, data.echo.request.cipher_size, 0);
            printf("Hello message sent statusCode %d\n", data.echo.request.header.type);
            
        }

        for(int i=0; i < strlen(message); i++){
            //printf("buffer[%d]: %02X %c\n",i, buffer[i], buffer[i]);
        }

            break;
        case 3:

            /* echo response */
            memcpy(&data.echo.response, buffer, buffer[1] << 8 | buffer[0]);
            printf("size: %ld, sequence: %d, type: %d.\n",data.echo.response.header.size ,
                data.echo.response.header.sequence, data.echo.response.header.type);
            printf("text: %s\n", data.echo.response.plain_message);
        for(int i=0; i < strlen(message); i++){
            //printf("buffer[%d]: %02X %c\n",i, buffer[i], buffer[i]);
        }
            go_on = 0;
            break;
        default:
            break;
        }


    }
    // closing the connected socket
    close(client_fd);
    //delete data.echo.request.cipher_message;
    return 0;
}
