#include "crypto_interface.h"
#include <random>

const size_t VIGENERE_KEY_SIZE = 16;

extern "C" {

CryptoStatus generate_vigenere_keys(uint64_t, uint64_t, char* buffer, size_t buffer_size, size_t* bytes_written) {
    if (!buffer || !bytes_written) return CryptoStatus::InvalidParam;
    if (buffer_size < VIGENERE_KEY_SIZE) return CryptoStatus::BufferTooSmall;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distr('a', 'z');

    for (size_t j = 0; j < VIGENERE_KEY_SIZE; ++j) {
        buffer[j] = static_cast<char>(distr(gen));
    }

    *bytes_written = VIGENERE_KEY_SIZE;
    return CryptoStatus::Success;
}

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
    static const AlgorithmInfo info = { "Vigenere", VIGENERE_KEY_SIZE }; 
    return &info;
}

}