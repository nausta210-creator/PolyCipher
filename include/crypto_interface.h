#ifndef CRYPTO_INTERFACE_H
#define CRYPTO_INTERFACE_H

#include <cstdint>
#include <cstddef>

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

extern "C" {
    CryptoStatus get_output_size(size_t input_size, size_t* out_size, bool is_encrypt);

    CryptoStatus encrypt(ConstBuffer input, ConstBuffer key, MutBuffer output);

    CryptoStatus decrypt(ConstBuffer input, ConstBuffer key, MutBuffer output);

    struct AlgorithmInfo {
    const char* algorithm_name;
    size_t key_size;
    };

    extern "C" const AlgorithmInfo* get_algorithm_info();

}

#endif