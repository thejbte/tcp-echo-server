/******************************************************************************

                              Online C++ Compiler.
               Code, Compile, Run and Debug C++ program online.
Write your code in this editor and press "Run" button to compile and execute it.
g++ main.cpp crypt.cpp -g -o main
*******************************************************************************/

#include <iostream>
#include <string>
#include <stdint.h>
#include <cstring>
#include "cryptogr.hpp"
#include "data.hpp"

using namespace std;

const char username[MAX_LEN_USER_AND_PASSW] ="testuser";
const char password[MAX_LEN_USER_AND_PASSW] ="testpass";
uint8_t bytte = 0x00;
uint8_t message_sequence = 87;

uint32_t initial_key = 0x00;

/*only to test */
void check_bytes(size_t len, void * ptr) {
    uint8_t _byte ;
    uint8_t * bytes = (uint8_t*)ptr;
    for(int i=0; i < len; i++) {
        printf("lala: %02X\n", *(bytes++));
    }
}


int main()
{   
    uint8_t checkSumPassword = 0, checkSumUserName = 0;
    char message[65535] = "hola julian, mensaje cifrado algo mas";
    size_t lenmsg = strlen(message);
    cryptography cryptation;
    struct data_t data;
    //data.echo.login.cipher_message = new uint8_t[len_msg];

    checkSumPassword = cryptation.checkSum(password);
    checkSumUserName = cryptation.checkSum(username);
    initial_key =  ((message_sequence << 16) | (checkSumUserName << 8) | (checkSumPassword));

    /*login request*/
    strncpy((char*)data.login.request.password, password, strlen(password) + 1);
    strncpy((char*)data.login.request.user_name, username, strlen(username) + 1);
    data.login.request.header.sequence = message_sequence;
    data.login.request.header.type = 0;
    //data.login.request.header.size = ??

    /*ECHO request*/
    data.echo.request.header.sequence = message_sequence;
    data.echo.request.header.type = 2;
    //data.echo.request.header.size = ?
    data.echo.request.cipher_size = lenmsg;

    uint8_t *cipher_key_ptr = cryptation.getCipherKeyArray(lenmsg, initial_key);
    //uint8_t *cipher_text_ptr = cryptation.getCipherTextArray(lenmsg, message);
    data.echo.request.cipher_message = cryptation.getCipherTextArray(lenmsg, message);


    printf("\n\n cipher_key:\n");
    for (size_t i = 0; i < lenmsg; i++)
    {
        printf("%02X ",cipher_key_ptr[i]);
    }

    printf("\n\n cipher_text:\n");
    for (size_t i = 0; i < lenmsg; i++)
    {
        printf("%02X ",data.echo.request.cipher_message[i]);
    }

    printf("\nstring msg cipher: %s\n", data.echo.request.cipher_message);

    /*ECHO response*/
    data.echo.response.header.sequence = message_sequence;
    data.echo.response.header.type = 3;
    //data.echo.request.header.size = ?
    data.echo.response.decipher_size = lenmsg;
    
    //uint8_t *decipher_text_ptr = cryptation.getDeCipherTextArray(lenmsg, data.echo.request.cipher_message);
    data.echo.response.plain_message = cryptation.getDeCipherTextArray(lenmsg, data.echo.request.cipher_message);
    printf("Deciper text: %s\n", data.echo.response.plain_message);





    //struct header_message_t  header;
//
    //header.size = 65535;
    //header.type = 7;
    //header.sequence = 32;
  
   // printf("%08X\n",header.block);
    //struct data_t data;
    //data.echo.request.header.size = 65535;
    //data.echo.request.header.type = 7;
    //data.echo.request.header.sequence = 32;
    //data.login.request.header = data.echo.request.header;
   // check_bytes(data.echo.request.cipher_size, data.echo.request.cipher_message);
    //check_bytes(sizeof(data.echo.request.header), &data.echo.request.header);
    //check_bytes(sizeof(data.login.request), &data.login.request);
   
   // printf("size: %ld", sizeof(data.echo.request)); //14 not 16
    //data.echo.request.header.size = sizeof(data.echo.request);//0 4 6(8bytes del ptr(dentro tiene los datos del mensaje encriptado 28))
    //o tambien podría ser , analizar cual.
    //data.echo.request.header.size = sizeof(data.echo.request.cipher_size) + sizeof(data.echo.request.header) + data.echo.request.cipher_size;

    //
    delete data.echo.request.cipher_message;
    return 0;
}

