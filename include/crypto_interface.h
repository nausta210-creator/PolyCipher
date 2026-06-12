#ifndef CRYPTO_INTERFACE_H
#define CRYPTO_INTERFACE_H

#include <cstdint>
#include <cstddef>
#include <vector>

enum class CryptoStatus : int32_t {
    Success = 0,
    InvalidParam = 1,
    BufferTooSmall = 2,
    MemoryError = 3,
    AuthFailure = 4,
    UnknownError = 5
};

struct ConstBuffer {
    const uint8_t* data;
    size_t size;
};

struct MutBuffer {
    uint8_t* data;
    size_t size;
};

void secure_memory_clear(uint8_t* ptr, size_t size) {
    if (ptr) {
        volatile uint8_t* vptr = static_cast<volatile uint8_t*>(ptr);
        while (size--) {
            *vptr++ = 0;
        }
    }
}

void secure_memory_clear(std::vector<uint8_t>& vec) {
    if (!vec.empty()) {
        secure_memory_clear(vec.data(), vec.size());
        vec.clear(); 
    }
}

extern "C" {
    CryptoStatus get_output_size(size_t input_size, size_t* out_size, bool is_encrypt);

    CryptoStatus encrypt(ConstBuffer input, ConstBuffer key, MutBuffer output);

    CryptoStatus decrypt(ConstBuffer input, ConstBuffer key, MutBuffer output);

    struct AlgorithmInfo {
        const char* algorithm_name;
        size_t key_size;
    };

    const AlgorithmInfo* get_algorithm_info();

}

#endif