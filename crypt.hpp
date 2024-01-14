#include <cstdint>
#include <cstddef>

class crypt {
    private:
        uint32_t initial_key = 0;
        uint8_t *cipher_key = nullptr;
        uint8_t *cipher_text = nullptr;
        uint8_t *decipher_text = nullptr;

        uint32_t next_key(uint32_t key);
        void generateCipherKeys(const size_t num_keys, const uint32_t _initial_key);
        void generateCipherText(const size_t len_msg, const char * message);
        void generateDeCipherText(const size_t len_msg, const uint8_t * crypted_message);

    public:
        crypt() = default;
        ~crypt(){
            delete  cipher_key, cipher_text;
        }
        uint8_t checkSum(const char * var);
        void setInitialKey(uint32_t value);
        uint8_t *getCipherKeyArray(const size_t num_keys, const uint32_t _initial_key);
        uint8_t *getCipherTextArray(const size_t len_msg, const char * message);
        uint8_t *getDeCipherTextArray(const size_t len_msg, const uint8_t * crypted_message);
        /*desencryptar , genero las key de nuevo 
        con cada key hago xor  entre lo encryptado y la key
        Ej: B=66 dec
        66 xor key(25) = 91(encryted)
        91 xor 25 == 66
        */

};