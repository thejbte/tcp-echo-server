#include <cstdint>
#include <cstddef>

#ifndef __CRYPTOGR_HPP_
#define __CRYPTOGR_HPP_

class cryptography {
    private:
        uint32_t initial_key = 0;
        uint8_t cipher_key[65535];
        uint8_t cipher_text[65535];
        uint8_t decipher_text[65535];

        uint32_t next_key(uint32_t key);
        void generateCipherKeys(const size_t num_keys, const uint32_t _initial_key);
        void generateCipherText(const size_t len_msg, const char * message);
        void generateDeCipherText(const size_t len_msg, const uint8_t * crypted_message);

    public:
        cryptography() = default;
        ~cryptography(){
            //delete  cipher_key, cipher_text;
        }
        uint8_t checkSum(const char * var);
        void setInitialKey(uint32_t value);
        uint8_t *getCipherKeyArray(const size_t num_keys, const uint32_t _initial_key);
        uint8_t *getCipherTextArray(const size_t len_msg, const char * message);
        uint8_t *getDeCipherTextArray(const size_t len_msg, const uint8_t * crypted_message);

};

#endif /*__CRYPTOGR_HPP_*/