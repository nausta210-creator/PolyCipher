#include "../../include/crypto_interface.h"
#include <cstring>
#include <cstdint>
#include <random>

static void rc4_init(const uint8_t* key, size_t key_len, uint8_t* sbox) {
    if (key_len == 0) return;
    
    for (int i = 0; i < 256; ++i) {
        sbox[i] = static_cast<uint8_t>(i);
    }
    
    size_t j = 0;
    for (size_t i = 0; i < 256; ++i) {
        j = (j + sbox[i] + key[i % key_len]) % 256;
        uint8_t temp = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = temp;
    }
}

static void rc4_process(const uint8_t* input, uint8_t* output, size_t len, uint8_t* sbox) {
    size_t i = 0, j = 0;
    for (size_t k = 0; k < len; ++k) {
        i = (i + 1) % 256;
        j = (j + sbox[i]) % 256;
        
        uint8_t temp = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = temp;
        
        uint8_t key_byte = sbox[(sbox[i] + sbox[j]) % 256];
        output[k] = input[k] ^ key_byte;
    }
}

extern "C" {
CryptoStatus generate_rc4_keys(uint64_t, uint64_t, char* buffer, size_t buffer_size, size_t* bytes_written) {
    if (!buffer || !bytes_written) return CryptoStatus::InvalidParam;
    if (buffer_size < 16) return CryptoStatus::BufferTooSmall; 

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distr(32, 126); 

    for (size_t j = 0; j < 16; ++j) {
        buffer[j] = static_cast<char>(distr(gen));
    }

    *bytes_written = 16;
    return CryptoStatus::Success;
}

CryptoStatus get_output_size(size_t input_size, size_t* out_size, bool /*is_encrypt*/) {
    if (!out_size) return CryptoStatus::InvalidParam;
    *out_size = input_size;
    return CryptoStatus::Success;
}

CryptoStatus encrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
    if (!input.data || !key.data || !output.data) return CryptoStatus::InvalidParam;
    if (key.size == 0) return CryptoStatus::InvalidParam;
    if (output.size < input.size) return CryptoStatus::BufferTooSmall;
    
    uint8_t sbox[256];
    rc4_init(key.data, key.size, sbox);
    rc4_process(input.data, output.data, input.size, sbox);
    std::memset(sbox, 0, sizeof(sbox));
    return CryptoStatus::Success;
}

CryptoStatus decrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
    return encrypt(input, key, output);
}

const AlgorithmInfo* get_algorithm_info() {
    static const AlgorithmInfo info = { "RC4", 0 };
    return &info;
}

}
