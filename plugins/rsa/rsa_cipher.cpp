#include "crypto_interface.h"
#include <algorithm>
#include <string>
#include <cstdio>
#include <iostream>

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

bool isPrime(uint64_t n) {
    if (n <= 1) return false;
    if (n <= 3) return true;
    if (n % 2 == 0 || n % 3 == 0) return false;
    for (uint64_t i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0) return false;
    }
    return true;
}


extern "C" {

CryptoStatus generate_rsa_keys(uint64_t p, uint64_t q, char* out_buffer, size_t max_size, size_t* written) {
    if (!isPrime(p) || !isPrime(q)) {
        return CryptoStatus::InvalidParam; 
    }

    if (!out_buffer || !written || p <= 1 || q <= 1) {
        return CryptoStatus::InvalidParam;
    }

    uint64_t n = p * q;
    uint64_t phi = (p - 1) * (q - 1);
    uint64_t e = 65537;
    if (e >= phi) {
        e = 7;
    }

    int64_t d = extended_gcd(e, phi); 
    
    std::string keys_str = "Public: " + std::to_string(e) + "," + std::to_string(n) + "\nPrivate: " + std::to_string(d) + "," + std::to_string(n) + "\n";

    if (keys_str.size() >= max_size) {
        return CryptoStatus::BufferTooSmall;
    }

    std::copy(keys_str.begin(), keys_str.end(), out_buffer);
    out_buffer[keys_str.size()] = '\0';
    *written = keys_str.size();

    return CryptoStatus::Success;
}

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
    
    size_t pos = key_str.find("Public: ");
    if (pos != std::string::npos) {
        pos += 8;
    } else {
        pos = 0; 
    }

    uint64_t e = 0, n = 0;
    if (std::sscanf(key_str.c_str() + pos, "%lu,%lu", &e, &n) != 2) {
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

    secure_memory_clear(reinterpret_cast<uint8_t*>(&key_str[0]), key_str.size());

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
    
    size_t pos = key_str.find("Private: ");
    if (pos != std::string::npos) {
        pos += 9;
    } else {
        pos = 0;
    }

    uint64_t d = 0, n = 0;
    if (std::sscanf(key_str.c_str() + pos, "%lu,%lu", &d, &n) != 2) {
        return CryptoStatus::InvalidParam;
    }

    const uint64_t* in_ptr = reinterpret_cast<const uint64_t*>(input.data);
    size_t blocks_count = input.size / sizeof(uint64_t);

    for (size_t i = 0; i < blocks_count; ++i) {
        uint64_t c = in_ptr[i];
        output.data[i] = static_cast<uint8_t>(modular_pow(c, d, n) & 0xFF);
    }

    secure_memory_clear(reinterpret_cast<uint8_t*>(&key_str[0]), key_str.size());

    return CryptoStatus::Success;
}

const AlgorithmInfo* get_algorithm_info() {
    static const AlgorithmInfo info = { "RSA", 0 };
    return &info;
}

}