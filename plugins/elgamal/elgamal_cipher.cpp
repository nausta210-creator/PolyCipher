#include "../../include/crypto_interface.h"
#include <random>
#include <cstring>
#include <cstdint>

// МАТЕМАТИЧЕСКИЕ ФУНКЦИИ 

// Возведение в степень по модулю (бинарный алгоритм)
static uint64_t mod_pow(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) result = (static_cast<__uint128_t>(result) * base) % mod;
        base = (static_cast<__uint128_t>(base) * base) % mod;
        exp >>= 1;
    }
    return result;
}

// Проверка числа на простоту
static bool is_prime(uint64_t n) {
    if (n < 2) return false;
    if (n % 2 == 0) return n == 2;
    if (n % 3 == 0) return n == 3;
    
    for (uint64_t i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0) return false;
    }
    return true;
}

// Парсинг строкового ключа формата "p,g,key"
static bool parse_key(const uint8_t* key_data, size_t key_size, 
                      uint64_t& p, uint64_t& g, uint64_t& key_val) {
    char key_str[256] = {0};
    size_t copy_len = (key_size < 255) ? key_size : 255;
    std::memcpy(key_str, key_data, copy_len);
    
    return (std::sscanf(key_str, "%lu,%lu,%lu", &p, &g, &key_val) == 3);
}

// ЭКСПОРТИРУЕМЫЕ ФУНКЦИИ ДЛЯ C ABI

extern "C" {

// Возвращает необходимый размер выходного буфера
CryptoStatus get_output_size(size_t input_size, size_t* out_size, bool is_encrypt) {
    if (!out_size) return CryptoStatus::InvalidParam;
    
    if (is_encrypt) {
        *out_size = input_size * 16;
    } else {
        if (input_size % 16 != 0) return CryptoStatus::InvalidParam;
        *out_size = input_size / 16;
    }
    return CryptoStatus::Success;
}

// Функция зашифрования Эль-Гамаль
CryptoStatus encrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
    if (!input.data || !key.data || !output.data) return CryptoStatus::InvalidParam;
    
    // Парсим ключ: p,g,public_key
    uint64_t p = 0, g = 0, public_key = 0;
    if (!parse_key(key.data, key.size, p, g, public_key)) {
        return CryptoStatus::InvalidParam;
    }
    // Валидация параметров
    if (!is_prime(p)) {
        return CryptoStatus::InvalidParam;
}
    if (g == 0 || g >= p) {
        return CryptoStatus::InvalidParam;
    }
    if (public_key < 2 || public_key >= p) {
        return CryptoStatus::InvalidParam;
    }
    
    // Проверка размера выходного буфера
    size_t required_size;
    get_output_size(input.size, &required_size, true);
    if (output.size < required_size) return CryptoStatus::BufferTooSmall;
    
    // Генератор случайных чисел для сессионного ключа k
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(2, p - 2);
    
    size_t out_pos = 0;
    for (size_t i = 0; i < input.size; ++i) {
        uint64_t k = dis(gen);
        uint64_t a = mod_pow(g, k, p);
        uint64_t b = (static_cast<__uint128_t>(input.data[i]) * mod_pow(public_key, k, p)) % p;
        
        for (int j = 0; j < 8; ++j) output.data[out_pos++] = (a >> (j * 8)) & 0xFF;
        for (int j = 0; j < 8; ++j) output.data[out_pos++] = (b >> (j * 8)) & 0xFF;
    }
    
    return CryptoStatus::Success;
}

// Функция расшифрования Эль-Гамаль (через малую теорему Ферма)
CryptoStatus decrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
    if (!input.data || !key.data || !output.data) return CryptoStatus::InvalidParam;
    
    // Парсим ключ: p,g,private_key
    uint64_t p = 0, g = 0, private_key = 0;
    if (!parse_key(key.data, key.size, p, g, private_key)) {
        return CryptoStatus::InvalidParam;
    }
    
    // Валидация параметров
    if (!is_prime(p)) {
        return CryptoStatus::InvalidParam;
    }
    if (private_key < 2 || private_key >= p) {
        return CryptoStatus::InvalidParam;
    }
    if (input.size % 16 != 0) {
        return CryptoStatus::InvalidParam;
    }
    
    // Проверка размера выходного буфера
    size_t required_size;
    get_output_size(input.size, &required_size, false);
    if (output.size < required_size) return CryptoStatus::BufferTooSmall;
    
    size_t out_pos = 0;
    for (size_t i = 0; i < input.size; i += 16) {
        uint64_t a = 0, b = 0;
        for (int j = 0; j < 8; ++j) a |= static_cast<uint64_t>(input.data[i + j]) << (j * 8);
        for (int j = 0; j < 8; ++j) b |= static_cast<uint64_t>(input.data[i + 8 + j]) << (j * 8);
        
        // Малая теорема Ферма: c^(-1) ≡ c^(p-2) mod p
        uint64_t ax = mod_pow(a, private_key, p);
        uint64_t m = (static_cast<__uint128_t>(b) * mod_pow(ax, p - 2, p)) % p;
        
        output.data[out_pos++] = static_cast<uint8_t>(m);
    }
    
    return CryptoStatus::Success;
}

} // extern "C"
