#include <stdint.h>
/*
union header_message_t {

    struct {
        uint16_t size;
        uint8_t type;
        uint8_t sequence;
    };
    uint32_t block;
};
*/
#pragma pack(push)  /* push current alignment to stack */
#pragma pack(1)

const int MAX_LEN_USER_AND_PASSW = 32;
/*header message*/
struct header_t {
    uint16_t size;
    uint8_t type;
    uint8_t sequence;
};

/*type 0*/
struct login_request_t {
    struct header_t  header;
    uint8_t user_name[MAX_LEN_USER_AND_PASSW] = {0};
    uint8_t password[MAX_LEN_USER_AND_PASSW] = {0};
};

/*type 1*/
struct login_response_t {
    struct header_t  header;
    uint16_t status_code;
};

/*type 2*/
struct echo_request_t {
    struct header_t  header;
    uint16_t cipher_size;
    uint8_t cipher_message[65535];
};

/*type 3*/
struct echo_response_t {
    struct header_t  header;
    uint16_t decipher_size;
    uint8_t plain_message[65535];
};

struct echo_t {
    echo_response_t response;
    echo_request_t request;
};

struct login_t {
    login_response_t response;
    login_request_t request;
};

struct data_t {
    echo_t echo;
    login_t login;
};

#pragma pack(pop)   /* restore original alignment from stack */