#include <stdint.h>

#pragma pack(push)  /* push current alignment to stack */
#pragma pack(1)

const int MAX_SIZE_USER_AND_PASSW = 32;
const int MAX_SIZE_BUFFER = 65535;
const int OFFSET_HEADER_SIZE_LSB = 0;
const int OFFSET_HEADER_SIZE_MSB = 1;
const int OFFSET_HEADER_TYPE = 2;

const int STATUS_CODE_OK = 1;
const int STATUS_CODE_FAILED = 0;


typedef enum {
    LOGIN_REQUEST = 0,
    LOGIN_RESPONSE = 1,
    ECHO_REQUEST = 2,
    ECHO_RESPONSE = 3,
    WAITING = 4,
} cases_t;


/*header message*/
struct header_t {
    uint16_t size;
    uint8_t type;
    uint8_t sequence;
};

/*type 0*/
struct login_request_t {
    struct header_t  header;
    uint8_t user_name[MAX_SIZE_USER_AND_PASSW] = {0};
    uint8_t password[MAX_SIZE_USER_AND_PASSW] = {0};
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
    uint8_t cipher_message[MAX_SIZE_BUFFER];
};

/*type 3*/
struct echo_response_t {
    struct header_t  header;
    uint16_t decipher_size;
    uint8_t plain_message[MAX_SIZE_BUFFER];
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
