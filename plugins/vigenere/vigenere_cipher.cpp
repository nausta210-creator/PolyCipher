#include "crypto_interface.h"

void secure_mem_clear(uint8_t* ptr, size_t size) {
    if (ptr) {
        volatile uint8_t* vptr = static_cast<volatile uint8_t*>(ptr);
        while (size--) {
            *vptr++ = 0;
        }
    }
}

extern "C" {

CryptoStatus get_output_size(size_t input_size, size_t* out_size, bool is_encrypt) {
    if (!out_size) return CryptoStatus::InvalidParam;
    
    *out_size = input_size;
    return CryptoStatus::Success;
}

CryptoStatus encrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
    if (!input.data || !key.data || !output.data || key.size == 0) {
        return CryptoStatus::InvalidParam;
    }
    if (output.size < input.size) {
        return CryptoStatus::BufferTooSmall;
    }

    for (size_t i = 0; i < input.size; ++i) {
        uint8_t text_byte = input.data[i];
        uint8_t key_byte = key.data[i % key.size];
        
        output.data[i] = static_cast<uint8_t>((text_byte + key_byte) % 256);
    }

    return CryptoStatus::Success;
}

CryptoStatus decrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
    if (!input.data || !key.data || !output.data || key.size == 0) {
        return CryptoStatus::InvalidParam;
    }
    if (output.size < input.size) {
        return CryptoStatus::BufferTooSmall;
    }

    for (size_t i = 0; i < input.size; ++i) {
        uint8_t cipher_byte = input.data[i];
        uint8_t key_byte = key.data[i % key.size];
        
        output.data[i] = static_cast<uint8_t>((cipher_byte - key_byte + 256) % 256);
    }

    return CryptoStatus::Success;
}
    const AlgorithmInfo* get_algorithm_info() {
        static const AlgorithmInfo info = { "Vigenere", 0 }; 
        return &info;
    }

}