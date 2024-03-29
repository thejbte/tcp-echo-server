
#include "cryptogr.hpp"
#include <stdint.h>
#include <string.h>
#include <stdio.h>



/*sum complement 8bits*/
uint8_t cryptography::checkSum(const char * var) {
    uint8_t sum = 0;
    uint8_t *bytes = (uint8_t*)var;
    for (int i = 0; i < sizeof(bytes); i++) {
        sum += bytes[i];
    }

    return (sum%256);
}

uint32_t cryptography::next_key(uint32_t key)
{
    return (key*1103515245  + 12345) %  0x7FFFFFFF;
}

void cryptography::generateCipherKeys(
    const size_t num_keys, const uint32_t _initial_key) {

    initial_key = _initial_key;

    for (size_t i = 0; i < num_keys ; i++) {
        uint32_t keyN = next_key(initial_key);
        initial_key = keyN;
        cipher_key[i] = keyN%256;
    }

}

void cryptography::generateCipherText(
    const size_t len_msg, const char * message) {

    if (message != nullptr) {
        for (size_t i = 0; i < len_msg ; i++) {
            cipher_text[i] = cipher_key[i] ^ message[i];
        }
    }

}

void cryptography::generateDeCipherText(
    const size_t len_msg, const uint8_t * crypted_message) {

    if (crypted_message != nullptr) {
        for (size_t i = 0; i < len_msg ; i++) {
            decipher_text[i] = crypted_message[i] ^ cipher_key[i];
        }
    }
}

void cryptography::setInitialKey(uint32_t value) {
    initial_key = value;
}

uint8_t *cryptography::getCipherKeyArray(
    const size_t num_keys, const uint32_t _initial_key) {

    generateCipherKeys(num_keys, _initial_key);
    return cipher_key;
}

uint8_t *cryptography::getCipherTextArray(
    const size_t len_msg, const char * message) {

    generateCipherText(len_msg, message);
    return cipher_text;
}

uint8_t *cryptography::getDeCipherTextArray(
    const size_t len_msg, const uint8_t * crypted_message) {
    generateDeCipherText(len_msg, crypted_message);
    return decipher_text;
}


