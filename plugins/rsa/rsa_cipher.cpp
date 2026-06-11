#include "crypto_interface.h"
#include <algorithm>
#include <string>
#include <cstdio>
#include <iostream>

void secure_rsa_clear(uint8_t* ptr, size_t size) {
    if (ptr) {
        volatile uint8_t* vptr = static_cast<volatile uint8_t*>(ptr);
        while (size--) {
            *vptr++ = 0;
        }
    }
}

uint64_t modular_pow(uint64_t base, uint64_t exp, uint64_t mod) {
    if (mod == 1) return 0;
    uint64_t res = 1;
    base = base % mod;
    
    while (exp > 0) {
        if (exp % 2 == 1) {
            res = (static_cast<__uint128_t>(res) * base) % mod;
        }
        exp = exp >> 1;
        base = (static_cast<__uint128_t>(base) * base) % mod;
    }
    return res;
}

int64_t extended_gcd(int64_t e, int64_t phi) {
    int64_t r0 = phi;
    int64_t u0 = 0;
    int64_t v0 = 1;

    int64_t r1 = e;
    int64_t u1 = 1;
    int64_t v1 = 0;

    size_t i = 2; 
    int64_t q = 0;  
    int64_t r = 0;   
    int64_t u = 0;   
    int64_t v = 0;   

    while (r1 != 0) {
        q = r0 / r1;      
        r = r0 % r1;      
        u = u0 - q * u1;  
        v = v0 - q * v1; 

        r0 = r1; r1 = r;
        u0 = u1; u1 = u;
        v0 = v1; v1 = v;
        
        i++;
    }

    if (u0 < 0) {
        u0 += phi; 
    }
    
    return u0;
}

extern "C" {

CryptoStatus get_output_size(size_t input_size, size_t* out_size, bool is_encrypt) {
    if (!out_size) return CryptoStatus::InvalidParam;
    
    if (is_encrypt) {
        *out_size = input_size * sizeof(uint64_t);
    } else {
        *out_size = input_size / sizeof(uint64_t);
    }
    return CryptoStatus::Success;
}

CryptoStatus encrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
    if (!input.data || !key.data || !output.data || key.size == 0) {
        return CryptoStatus::InvalidParam;
    }
    if (output.size < input.size * sizeof(uint64_t)) {
        return CryptoStatus::BufferTooSmall;
    }

    std::string key_str(reinterpret_cast<const char*>(key.data), key.size);
    
    uint64_t e = 0, n = 0;
    if (std::sscanf(key_str.c_str(), "%lu,%lu", &e, &n) != 2) {
        return CryptoStatus::InvalidParam;
    }

    uint64_t* out_ptr = reinterpret_cast<uint64_t*>(output.data);

    for (size_t i = 0; i < input.size; ++i) {
        uint64_t m = input.data[i];
        if (m >= n) {
            return CryptoStatus::InvalidParam;
        }
        out_ptr[i] = modular_pow(m, e, n);
    }

    return CryptoStatus::Success;
}

CryptoStatus decrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
    if (!input.data || !key.data || !output.data || key.size == 0) {
        return CryptoStatus::InvalidParam;
    }
    if (input.size % sizeof(uint64_t) != 0 || output.size < input.size / sizeof(uint64_t)) {
        return CryptoStatus::BufferTooSmall;
    }

    std::string key_str(reinterpret_cast<const char*>(key.data), key.size);
    
    uint64_t d = 0, n = 0;
    if (std::sscanf(key_str.c_str(), "%lu,%lu", &d, &n) != 2) {
        return CryptoStatus::InvalidParam;
    }

    const uint64_t* in_ptr = reinterpret_cast<const uint64_t*>(input.data);
    size_t blocks_count = input.size / sizeof(uint64_t);

    for (size_t i = 0; i < blocks_count; ++i) {
        uint64_t c = in_ptr[i];
        output.data[i] = static_cast<uint8_t>(modular_pow(c, d, n) & 0xFF);
    }

    return CryptoStatus::Success;
}
    const AlgorithmInfo* get_algorithm_info() {
        static const AlgorithmInfo info = { "RSA", 8 };
        return &info;
    }

}