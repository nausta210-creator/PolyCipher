#ifndef CRYPTO_INTERFACE_H
#define CRYPTO_INTERFACE_H

#include <cstdint>
#include <cstddef>

// Строгая типизация состояний и ошибок для главного модуля и плагинов
enum class CryptoStatus : int32_t {
    Success = 0,
    InvalidParam = 1,
    BufferTooSmall = 2,
    MemoryError = 3,
    AuthFailure = 4,
    UnknownError = 5
};

// Структура для передачи входящих (неизменяемых) данных через C ABI
struct ConstBuffer {
    const uint8_t* data;
    size_t size;
};

// Структура для передачи выходного (изменяемого) буфера через C ABI
struct MutBuffer {
    uint8_t* data;
    size_t size;
};

// Экспортируемые функции, которые будет реализовывать каждая библиотека
extern "C" {
    // Вычисляет необходимый размер выходного буфера
    CryptoStatus get_output_size(size_t input_size, size_t* out_size, bool is_encrypt);

    // Функция зашифрования
    CryptoStatus encrypt(ConstBuffer input, ConstBuffer key, MutBuffer output);

    // Функция расшифрования
    CryptoStatus decrypt(ConstBuffer input, ConstBuffer key, MutBuffer output);
}

#endif // CRYPTO_INTERFACE_H