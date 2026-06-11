#include "../../include/crypto_interface.h"
#include <cstring>
#include <cstdint>

// ВНУТРЕННИЕ ФУНКЦИИ RC4 

// Инициализация S-блока (Key Scheduling Algorithm)
static void rc4_init(const uint8_t* key, size_t key_len, uint8_t* sbox) {
    if (key_len == 0) return;
    
    // Заполняем S-блок значениями 0..255
    for (int i = 0; i < 256; ++i) {
        sbox[i] = static_cast<uint8_t>(i);
    }
    
    // Перемешиваем S-блок ключом
    size_t j = 0;
    for (size_t i = 0; i < 256; ++i) {
        j = (j + sbox[i] + key[i % key_len]) % 256;
        uint8_t temp = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = temp;
    }
}

// Генерация псевдослучайного потока и XOR с данными (PRGA)
static void rc4_process(const uint8_t* input, uint8_t* output, size_t len, uint8_t* sbox) {
    size_t i = 0, j = 0;
    for (size_t k = 0; k < len; ++k) {
        i = (i + 1) % 256;
        j = (j + sbox[i]) % 256;
        
        // Swap
        uint8_t temp = sbox[i];
        sbox[i] = sbox[j];
        sbox[j] = temp;
        
        // Генерируем ключевой байт и XOR с данными
        uint8_t key_byte = sbox[(sbox[i] + sbox[j]) % 256];
        output[k] = input[k] ^ key_byte;
    }
}

// ЭКСПОРТИРУЕМЫЕ ФУНКЦИИ ДЛЯ C ABI

extern "C" {

// Возвращает необходимый размер выходного буфера
// Для RC4 размер не меняется (потоковый шифр)
CryptoStatus get_output_size(size_t input_size, size_t* out_size, bool /*is_encrypt*/) {
    if (!out_size) return CryptoStatus::InvalidParam;
    *out_size = input_size;
    return CryptoStatus::Success;
}

// Функция зашифрования
CryptoStatus encrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
    // Проверка параметров
    if (!input.data || !key.data || !output.data) return CryptoStatus::InvalidParam;
    if (key.size == 0) return CryptoStatus::InvalidParam;
    if (output.size < input.size) return CryptoStatus::BufferTooSmall;
    
    // Шифрование
    uint8_t sbox[256];
    rc4_init(key.data, key.size, sbox);
    rc4_process(input.data, output.data, input.size, sbox);
    
    // Безопасное зануление S-блока (чтобы ключ не остался в памяти)
    std::memset(sbox, 0, sizeof(sbox));
    return CryptoStatus::Success;
}

// Функция расшифрования (симметрична шифрованию)
CryptoStatus decrypt(ConstBuffer input, ConstBuffer key, MutBuffer output) {
    return encrypt(input, key, output);
}

} // extern "C"
